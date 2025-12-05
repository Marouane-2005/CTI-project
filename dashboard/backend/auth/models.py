import bcrypt
from datetime import datetime
import json

class User:
    """Modèle utilisateur simple (remplacez par votre DB si nécessaire)"""
    
    # Base de données utilisateurs en mémoire (remplacez par une vraie DB)
    users_db = {
        "admin": {
            "id": "admin",
            "username": "admin",
            "password_hash": bcrypt.hashpw("admin123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),
            "name": "Administrateur CTI",
            "email": "admin@cti-dashboard.local",
            "role": "admin",
            "created_at": "2025-01-01T00:00:00Z",
            "last_login": None
        },
        "analyst": {
            "id": "analyst",
            "username": "analyst",
            "password_hash": bcrypt.hashpw("analyst123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),
            "name": "Analyste CTI",
            "email": "analyst@cti-dashboard.local",
            "role": "analyst",
            "created_at": "2025-01-01T00:00:00Z",
            "last_login": None
        }
    }
    
    def __init__(self, user_data):
        self.id = user_data['id']
        self.username = user_data['username']
        self.password_hash = user_data['password_hash']
        self.name = user_data['name']
        self.email = user_data['email']
        self.role = user_data['role']
        self.created_at = user_data['created_at']
        self.last_login = user_data.get('last_login')

    @classmethod
    def find_by_username(cls, username):
        """Trouver un utilisateur par nom d'utilisateur"""
        user_data = cls.users_db.get(username)
        if user_data:
            return cls(user_data)
        return None

    @classmethod
    def find_by_id(cls, user_id):
        """Trouver un utilisateur par ID"""
        for username, user_data in cls.users_db.items():
            if user_data['id'] == user_id:
                return cls(user_data)
        return None

    def check_password(self, password):
        """Vérifier le mot de passe"""
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))
    
    def update_last_login(self):
        """Mettre à jour la dernière connexion"""
        self.last_login = datetime.utcnow().isoformat() + 'Z'
        self.users_db[self.username]['last_login'] = self.last_login
    
    def to_dict(self):
        """Convertir en dictionnaire (sans le hash du mot de passe)"""
        return {
            'id': self.id,
            'username': self.username,
            'name': self.name,
            'email': self.email,
            'role': self.role,
            'created_at': self.created_at,
            'last_login': self.last_login
        }