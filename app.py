from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(__file__), '..', '..', 'templates')
)

app.secret_key = "secret_key_provisoria"
# ...existing code...

# Configuración de MongoDB: usa tu URI real o local
app.config["MONGO_URI"] = os.environ.get(
    "MONGO_URI",
    "mongodb://localhost:27017/photo_db"
)
mongo_client = MongoClient(app.config["MONGO_URI"])
mongo_db = mongo_client["photo_db"]

UPLOAD_FOLDER = os.path.join(app.root_path, 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/')
def index():
    if 'user' not in session:
        return redirect(url_for('login'))
    files = list(mongo_db.files.find({"owner": session['user']}))
    return render_template('dashboard.html', files=files)

# ...existing code...

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        hashed_pw = generate_password_hash(request.form['password'])
        mongo_db.users.insert_one({
            "email": request.form['email'],
            "password": hashed_pw
        })
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = mongo_db.users.find_one({"email": request.form['email']})
        if user and check_password_hash(user['password'], request.form['password']):
            session['user'] = user['email']
            return redirect(url_for('index'))
    return render_template('login.html')

# --- RECUPERACIÓN DE CUENTA ---

from datetime import datetime, timedelta
import secrets

RESET_TOKEN_TTL_MINUTES = 30

def _create_reset_token(email: str) -> str:
    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(minutes=RESET_TOKEN_TTL_MINUTES)
    mongo_db.reset_tokens.insert_one({
        "email": email,
        "token": token,
        "expires_at": expires_at
    })
    return token

@app.route('/recover', methods=['GET', 'POST'])
def recover():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        if not email:
            return render_template('recover.html', error="Ingresa un correo válido.")

        user = mongo_db.users.find_one({"email": email})
        # No revelamos si existe el usuario
        if user:
            token = _create_reset_token(email)
            reset_url = url_for('reset_password', token=token, _external=True)
            # En vez de enviar email real (SMTP), lo mostramos para que puedas probar
            return render_template('recover.html', message=f'Usa este link para reestablecer: {reset_url}', email=email)
        return render_template('recover.html', message="Si el correo existe, te enviaremos un enlace de recuperación.", email=email)

    return render_template('recover.html')

@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_password(token: str):
    if request.method == 'POST':
        new_password = request.form.get('password', '')
        if len(new_password) < 6:
            return render_template('reset.html', token=token, error="La contraseña debe tener al menos 6 caracteres.")

        token_doc = mongo_db.reset_tokens.find_one({"token": token})
        if not token_doc:
            return render_template('reset.html', token=token, error="Token inválido.")

        expires_at = token_doc.get("expires_at")
        if not expires_at or expires_at < datetime.utcnow():
            return render_template('reset.html', token=token, error="El token expiró. Solicita uno nuevo.")

        mongo_db.users.update_one(
            {"email": token_doc["email"]},
            {"$set": {"password": generate_password_hash(new_password)}}
        )
        mongo_db.reset_tokens.delete_many({"token": token})

        return redirect(url_for('login'))

    return render_template('reset.html', token=token)

# --- GESTIÓN DE ARCHIVOS ---

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files: return "No hay archivo"
    file = request.files['file']
    if file.filename == '': return "Sin nombre"
    
    filename = secure_filename(file.filename)
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    
    # Guardar referencia en MongoDB
    mongo_db.files.insert_one({
        "filename": filename,
        "owner": session['user'],
        "type": file.content_type
    })
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
