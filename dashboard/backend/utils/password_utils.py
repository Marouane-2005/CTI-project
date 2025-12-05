import bcrypt
import secrets
import string

def hash_password(password):
    """Hasher un mot de passe"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password(password, password_hash):
    """Vérifier un mot de passe"""
    return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))

def generate_random_password(length=12):
    """Générer un mot de passe aléatoire"""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def generate_jwt_secret():
    """Générer une clé secrète JWT"""
    return secrets.token_urlsafe(64)