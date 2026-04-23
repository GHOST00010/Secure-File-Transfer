import os
import uuid
import sqlite3
import re
import datetime
from flask import Flask, request, redirect, session, send_file, render_template, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import pyotp
import qrcode
from io import BytesIO
import base64

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(minutes=15)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
DB_PATH = os.path.join(BASE_DIR, 'password.db')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ---------------- DATABASE SETUP ----------------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt BLOB NOT NULL,
            ecc_public_key BLOB NOT NULL,
            ecc_private_key_encrypted BLOB NOT NULL,
            totp_secret TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        conn.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_uuid TEXT UNIQUE NOT NULL,
            filename TEXT NOT NULL,
            owner_id INTEGER NOT NULL,
            encrypted_aes_key BLOB NOT NULL,
            ephemeral_public_key BLOB NOT NULL,
            upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(owner_id) REFERENCES users(id)
        )
        ''')
        conn.execute('''
        CREATE TABLE IF NOT EXISTS shared_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            encrypted_aes_key BLOB NOT NULL,
            ephemeral_public_key BLOB NOT NULL,
            FOREIGN KEY(file_id) REFERENCES files(id),
            FOREIGN KEY(receiver_id) REFERENCES users(id)
        )
        ''')
        conn.execute('''
        CREATE TABLE IF NOT EXISTS public_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER NOT NULL,
            link_uuid TEXT UNIQUE NOT NULL,
            encrypted_aes_key BLOB NOT NULL,
            salt BLOB NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(file_id) REFERENCES files(id)
        )
        ''')
    print("Database initialized.")

init_db()

# ---------------- CRYPTOGRAPHY HELPERS ----------------

def derive_key_from_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_data(data, key):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    return nonce + aesgcm.encrypt(nonce, data, None)

def decrypt_data(data, key):
    aesgcm = AESGCM(key)
    nonce = data[:12]
    ciphertext = data[12:]
    return aesgcm.decrypt(nonce, ciphertext, None)

def generate_ecc_pair():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return priv_bytes, pub_bytes

def hybrid_encrypt_key(key_to_encrypt, recipient_pub_bytes):
    # Load recipient public key
    recipient_pub_key = serialization.load_pem_public_key(recipient_pub_bytes, backend=default_backend())
    
    # Generate ephemeral key pair
    ephemeral_priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
    ephemeral_pub_bytes = ephemeral_priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # ECDH
    shared_key = ephemeral_priv.exchange(ec.ECDH(), recipient_pub_key)
    
    # HKDF to derive 32-byte key
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'hybrid-encryption',
        backend=default_backend()
    ).derive(shared_key)
    
    # Encrypt the actual key (AES-256 key)
    encrypted_key = encrypt_data(key_to_encrypt, derived_key)
    return encrypted_key, ephemeral_pub_bytes

def hybrid_decrypt_key(encrypted_key, recipient_priv_bytes, ephemeral_pub_bytes):
    # Load recipient private key
    recipient_priv_key = serialization.load_pem_private_key(recipient_priv_bytes, password=None, backend=default_backend())
    # Load ephemeral public key
    ephemeral_pub_key = serialization.load_pem_public_key(ephemeral_pub_bytes, backend=default_backend())
    
    # ECDH
    shared_key = recipient_priv_key.exchange(ec.ECDH(), ephemeral_pub_key)
    
    # HKDF
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'hybrid-encryption',
        backend=default_backend()
    ).derive(shared_key)
    
    # Decrypt
    return decrypt_data(encrypted_key, derived_key)

# ---------------- AUTHENTICATION ----------------

def is_strong_password(password):
    if len(password) < 8: return False
    if not re.search(r"[A-Z]", password): return False
    if not re.search(r"[a-z]", password): return False
    if not re.search(r"[0-9]", password): return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password): return False
    return True

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash("Passwords do not match!", "error")
            return redirect(url_for('register'))
        
        if not is_strong_password(password):
            flash("Password must be at least 8 characters long and contain uppercase, lowercase, numbers, and special characters.", "error")
            return redirect(url_for('register'))
            
        with get_db() as conn:
            user = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
            if user:
                flash("Username already exists!", "error")
                return redirect(url_for('register'))
            
            # Key generation
            salt = os.urandom(16)
            priv_bytes, pub_bytes = generate_ecc_pair()
            
            # Encrypt private key with password
            pw_key = derive_key_from_password(password, salt)
            encrypted_priv_key = encrypt_data(priv_bytes, pw_key)
            
            # OTP setup
            totp_secret = pyotp.random_base32()
            
            conn.execute('''
                INSERT INTO users (username, password_hash, salt, ecc_public_key, ecc_private_key_encrypted, totp_secret)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (username, generate_password_hash(password), salt, pub_bytes, encrypted_priv_key, totp_secret))
            conn.commit()
            
        flash("Registration successful! Please login.", "success")
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        with get_db() as conn:
            user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
            
        if user and check_password_hash(user['password_hash'], password):
            session['temp_user_id'] = user['id']
            session['temp_username'] = user['username']
            session['password_hint'] = password # For deriving keys in this session only
            return redirect(url_for('verify_2fa'))
        else:
            flash("Invalid credentials!", "error")
            
    return render_template('login.html')

@app.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'temp_user_id' not in session:
        return redirect(url_for('login'))
        
    with get_db() as conn:
        user = conn.execute('SELECT totp_secret FROM users WHERE id = ?', (session['temp_user_id'],)).fetchone()
        
    totp = pyotp.TOTP(user['totp_secret'])
    
    if request.method == 'POST':
        otp = request.form.get('otp')
        if totp.verify(otp):
            session['user_id'] = session['temp_user_id']
            session['username'] = session['temp_username']
            session.pop('temp_user_id')
            session.pop('temp_username')
            session.permanent = True
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid OTP!", "error")
            
    # For simulation, print the OTP (in real app, user uses Google Authenticator)
    print(f"DEBUG: Current OTP for {session['temp_username']} is: {totp.now()}")
    
    # Generate QR code for setup if needed (simplified here)
    uri = totp.provisioning_uri(name=session['temp_username'], issuer_name="SecureShare")
    img = qrcode.make(uri)
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    qr_base64 = base64.b64encode(buffered.getvalue()).decode()
    
    return render_template('verify_2fa.html', qr_code=qr_base64, otp_val=totp.now())

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ---------------- FILE OPERATIONS ----------------

@app.route('/')
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    with get_db() as conn:
        my_files = conn.execute('SELECT * FROM files WHERE owner_id = ?', (session['user_id'],)).fetchall()
        shared_with_me = conn.execute('''
            SELECT files.filename, files.file_uuid, users.username as owner, shared_files.id as share_id
            FROM shared_files
            JOIN files ON shared_files.file_id = files.id
            JOIN users ON files.owner_id = users.id
            WHERE shared_files.receiver_id = ?
        ''', (session['user_id'],)).fetchall()
        all_users = conn.execute('SELECT id, username FROM users WHERE id != ?', (session['user_id'],)).fetchall()
        
    return render_template('upload.html', my_files=my_files, shared_files=shared_with_me, users=all_users)

@app.route('/upload', methods=['POST'])
def upload():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    file = request.files.get('file')
    if not file:
        flash("No file selected!", "error")
        return redirect(url_for('dashboard'))
        
    filename = file.filename
    file_content = file.read()
    
    # Generate random AES-256 key
    aes_key = os.urandom(32)
    
    # Encrypt file content
    encrypted_content = encrypt_data(file_content, aes_key)
    
    # Save to disk with UUID
    file_uuid = str(uuid.uuid4())
    with open(os.path.join(UPLOAD_FOLDER, file_uuid), 'wb') as f:
        f.write(encrypted_content)
        
    # Hybrid encrypt the AES key for the owner
    with get_db() as conn:
        owner = conn.execute('SELECT ecc_public_key FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        enc_aes_key, eph_pub_bytes = hybrid_encrypt_key(aes_key, owner['ecc_public_key'])
        
        conn.execute('''
            INSERT INTO files (file_uuid, filename, owner_id, encrypted_aes_key, ephemeral_public_key)
            VALUES (?, ?, ?, ?, ?)
        ''', (file_uuid, filename, session['user_id'], enc_aes_key, eph_pub_bytes))
        conn.commit()
        
    flash("File uploaded successfully!", "success")
    return redirect(url_for('dashboard'))

@app.route('/share', methods=['POST'])
def share():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    file_id = request.form.get('file_id')
    receiver_id = request.form.get('receiver_id')
    
    if not receiver_id:
        flash("Please select a valid user to share with.", "error")
        return redirect(url_for('dashboard'))
    
    with get_db() as conn:
        # Verify ownership
        file_info = conn.execute('SELECT * FROM files WHERE id = ? AND owner_id = ?', (file_id, session['user_id'])).fetchone()
        if not file_info:
            flash("Unauthorized access attempt!", "error")
            return redirect(url_for('dashboard'))
            
        receiver = conn.execute('SELECT username, ecc_public_key FROM users WHERE id = ?', (receiver_id,)).fetchone()
        if not receiver:
            flash("Receiver not found.", "error")
            return redirect(url_for('dashboard'))

        # Get owner's private key to decrypt AES key first
        owner = conn.execute('SELECT salt, ecc_private_key_encrypted FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        pw_key = derive_key_from_password(session['password_hint'], owner['salt'])
        priv_bytes = decrypt_data(owner['ecc_private_key_encrypted'], pw_key)
        
        # Recover AES key
        aes_key = hybrid_decrypt_key(file_info['encrypted_aes_key'], priv_bytes, file_info['ephemeral_public_key'])
        
        # Re-encrypt for receiver
        receiver = conn.execute('SELECT ecc_public_key FROM users WHERE id = ?', (receiver_id,)).fetchone()
        enc_aes_key, eph_pub_bytes = hybrid_encrypt_key(aes_key, receiver['ecc_public_key'])
        
        conn.execute('''
            INSERT INTO shared_files (file_id, receiver_id, encrypted_aes_key, ephemeral_public_key)
            VALUES (?, ?, ?, ?)
        ''', (file_id, receiver_id, enc_aes_key, eph_pub_bytes))
        conn.commit()
        
    flash("File shared with registered user!", "success")
    return redirect(url_for('dashboard'))

@app.route('/generate_link/<int:file_id>', methods=['POST'])
def generate_link(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    passphrase = request.form.get('passphrase')
    if not passphrase:
        flash("Please set a passphrase for the link!", "error")
        return redirect(url_for('dashboard'))
        
    with get_db() as conn:
        # Verify ownership
        file_info = conn.execute('SELECT * FROM files WHERE id = ? AND owner_id = ?', (file_id, session['user_id'])).fetchone()
        if not file_info:
            flash("Unauthorized!", "error")
            return redirect(url_for('dashboard'))
            
        # Get owner's private key to decrypt AES key first
        owner = conn.execute('SELECT salt, ecc_private_key_encrypted FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        pw_key = derive_key_from_password(session['password_hint'], owner['salt'])
        priv_bytes = decrypt_data(owner['ecc_private_key_encrypted'], pw_key)
        
        # Recover original AES key
        aes_key = hybrid_decrypt_key(file_info['encrypted_aes_key'], priv_bytes, file_info['ephemeral_public_key'])
        
        # Encrypt AES key for the link using passphrase
        link_salt = os.urandom(16)
        link_pw_key = derive_key_from_password(passphrase, link_salt)
        enc_aes_key = encrypt_data(aes_key, link_pw_key)
        
        link_uuid = str(uuid.uuid4())
        
        conn.execute('''
            INSERT INTO public_links (file_id, link_uuid, encrypted_aes_key, salt)
            VALUES (?, ?, ?, ?)
        ''', (file_id, link_uuid, enc_aes_key, link_salt))
        conn.commit()
        
    public_url = request.host_url.rstrip('/') + url_for('public_view', link_uuid=link_uuid)
    flash(f"Public Link Generated! Share this URL: {public_url}", "success")
    return redirect(url_for('dashboard'))

@app.route('/p/<link_uuid>', methods=['GET', 'POST'])
def public_view(link_uuid):
    with get_db() as conn:
        link_info = conn.execute('''
            SELECT files.filename, public_links.* 
            FROM public_links 
            JOIN files ON public_links.file_id = files.id 
            WHERE public_links.link_uuid = ?
        ''', (link_uuid,)).fetchone()
        
    if not link_info:
        return "Link not found or expired.", 404
        
    if request.method == 'POST':
        passphrase = request.form.get('passphrase')
        try:
            # Derive key from passphrase
            link_pw_key = derive_key_from_password(passphrase, link_info['salt'])
            # Decrypt AES key
            aes_key = decrypt_data(link_info['encrypted_aes_key'], link_pw_key)
            
            # Now download the file
            return download_file_with_key(link_info['file_id'], aes_key, link_info['filename'])
        except Exception as e:
            flash("Incorrect passphrase!", "error")
            
    return render_template('public_download.html', filename=link_info['filename'])

def download_file_with_key(file_id, aes_key, filename):
    with get_db() as conn:
        file_info = conn.execute('SELECT file_uuid FROM files WHERE id = ?', (file_id,)).fetchone()
        
    with open(os.path.join(UPLOAD_FOLDER, file_info['file_uuid']), 'rb') as f:
        encrypted_content = f.read()
            
    decrypted_content = decrypt_data(encrypted_content, aes_key)
    return send_file(
        BytesIO(decrypted_content),
        download_name=filename,
        as_attachment=True
    )

@app.route('/delete/<int:file_id>', methods=['POST'])
def delete_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    with get_db() as conn:
        # Verify ownership
        file_info = conn.execute('SELECT * FROM files WHERE id = ? AND owner_id = ?', (file_id, session['user_id'])).fetchone()
        if not file_info:
            flash("Unauthorized deletion attempt!", "error")
            return redirect(url_for('dashboard'))
            
        # Delete from disk
        file_path = os.path.join(UPLOAD_FOLDER, file_info['file_uuid'])
        if os.path.exists(file_path):
            os.remove(file_path)
            
        # Delete from database (cascading delete should handle shared_files and public_links if foreign keys are set, but let's be explicit if not)
        conn.execute('DELETE FROM shared_files WHERE file_id = ?', (file_id,))
        conn.execute('DELETE FROM public_links WHERE file_id = ?', (file_id,))
        conn.execute('DELETE FROM files WHERE id = ?', (file_id,))
        conn.commit()
        
    flash(f"File '{file_info['filename']}' deleted successfully.", "success")
    return redirect(url_for('dashboard'))

@app.route('/download/<file_uuid>')
def download(file_uuid):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    with get_db() as conn:
        # Check if owner
        file_info = conn.execute('SELECT * FROM files WHERE file_uuid = ? AND owner_id = ?', (file_uuid, session['user_id'])).fetchone()
        is_shared = False
        
        if not file_info:
            # Check if shared
            file_info = conn.execute('''
                SELECT files.*, shared_files.encrypted_aes_key as shared_enc_key, shared_files.ephemeral_public_key as shared_eph_pub
                FROM shared_files
                JOIN files ON shared_files.file_id = files.id
                WHERE files.file_uuid = ? AND shared_files.receiver_id = ?
            ''', (file_uuid, session['user_id'])).fetchone()
            is_shared = True
            
        if not file_info:
            flash("Access denied!", "error")
            return redirect(url_for('dashboard'))
            
        # Decrypt ECC Private Key
        user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        pw_key = derive_key_from_password(session['password_hint'], user['salt'])
        priv_bytes = decrypt_data(user['ecc_private_key_encrypted'], pw_key)
        
        # Decrypt AES Key
        if is_shared:
            aes_key = hybrid_decrypt_key(file_info['shared_enc_key'], priv_bytes, file_info['shared_eph_pub'])
        else:
            aes_key = hybrid_decrypt_key(file_info['encrypted_aes_key'], priv_bytes, file_info['ephemeral_public_key'])
            
        # Decrypt File Content
        with open(os.path.join(UPLOAD_FOLDER, file_uuid), 'rb') as f:
            encrypted_content = f.read()
            
        decrypted_content = decrypt_data(encrypted_content, aes_key)
        
        return send_file(
            BytesIO(decrypted_content),
            download_name=file_info['filename'],
            as_attachment=True
        )

# ---------------- ERROR HANDLER ----------------
@app.errorhandler(404)
def not_found(e):
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(debug=debug_mode, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))