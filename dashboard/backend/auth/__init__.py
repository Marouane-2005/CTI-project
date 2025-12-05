from .routes import auth_bp
from .models import User

__all__ = ['auth_bp', 'User']

# ===== FICHIER 6: auth/decorators.py - Nouveau fichier =====
from functools import wraps
from flask import jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from .models import User

def auth_required(f):
    """Décorateur personnalisé pour vérifier l'authentification"""
    @wraps(f)
    @jwt_required()
    def decorated(*args, **kwargs):
        try:
            user_id = get_jwt_identity()
            user = User.find_by_id(user_id)
            
            if not user:
                return jsonify({'error': 'Utilisateur non valide'}), 401
            
            # Ajouter l'utilisateur au contexte de la requête
            return f(current_user=user, *args, **kwargs)
            
        except Exception as e:
            return jsonify({'error': 'Erreur d\'authentification'}), 401
    
    return decorated

def admin_required(f):
    """Décorateur pour les routes réservées aux admins"""
    @wraps(f)
    @auth_required
    def decorated(current_user, *args, **kwargs):
        if current_user.role != 'admin':
            return jsonify({'error': 'Accès refusé - droits administrateur requis'}), 403
        
        return f(current_user=current_user, *args, **kwargs)
    
    return decorated