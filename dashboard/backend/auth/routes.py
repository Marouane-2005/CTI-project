from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import (
    create_access_token, 
    create_refresh_token,
    jwt_required, 
    get_jwt_identity,
    get_jwt
)
from datetime import datetime
import logging

from .models import User

# Créer le blueprint pour l'authentification
auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')

# Set pour stocker les tokens révoqués (en production, utilisez Redis)
blacklisted_tokens = set()

@auth_bp.route('/login', methods=['POST'])
def login():
    """Endpoint de connexion"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Données JSON requises'}), 400
        
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        if not username or not password:
            return jsonify({'error': 'Nom d\'utilisateur et mot de passe requis'}), 400
        
        # Trouver l'utilisateur
        user = User.find_by_username(username)
        if not user or not user.check_password(password):
            return jsonify({'error': 'Identifiants incorrects'}), 401
        
        # Mettre à jour la dernière connexion
        user.update_last_login()
        
        # Créer les tokens
        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)
        
        # Log de la connexion
        current_app.logger.info(f"Connexion réussie pour l'utilisateur: {username}")
        
        return jsonify({
            'success': True,
            'message': 'Connexion réussie',
            'token': access_token,
            'refresh_token': refresh_token,
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Erreur lors de la connexion: {str(e)}")
        return jsonify({'error': 'Erreur interne du serveur'}), 500

@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """Endpoint de déconnexion"""
    try:
        # Ajouter le token à la blacklist
        jti = get_jwt()['jti']
        blacklisted_tokens.add(jti)
        
        user_id = get_jwt_identity()
        current_app.logger.info(f"Déconnexion de l'utilisateur: {user_id}")
        
        return jsonify({
            'success': True,
            'message': 'Déconnexion réussie'
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Erreur lors de la déconnexion: {str(e)}")
        return jsonify({'error': 'Erreur lors de la déconnexion'}), 500

@auth_bp.route('/verify', methods=['GET'])
@jwt_required()
def verify_token():
    """Vérifier la validité du token"""
    try:
        user_id = get_jwt_identity()
        user = User.find_by_id(user_id)
        
        if not user:
            return jsonify({'error': 'Utilisateur non trouvé'}), 404
        
        return jsonify({
            'valid': True,
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Erreur lors de la vérification du token: {str(e)}")
        return jsonify({'error': 'Token invalide'}), 401

@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """Rafraîchir le token d'accès"""
    try:
        user_id = get_jwt_identity()
        user = User.find_by_id(user_id)
        
        if not user:
            return jsonify({'error': 'Utilisateur non trouvé'}), 404
        
        new_token = create_access_token(identity=user_id)
        
        return jsonify({
            'success': True,
            'token': new_token,
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Erreur lors du rafraîchissement du token: {str(e)}")
        return jsonify({'error': 'Erreur lors du rafraîchissement'}), 500

@auth_bp.route('/me', methods=['GET'])
@jwt_required()
def get_current_user():
    """Obtenir les informations de l'utilisateur connecté"""
    try:
        user_id = get_jwt_identity()
        user = User.find_by_id(user_id)
        
        if not user:
            return jsonify({'error': 'Utilisateur non trouvé'}), 404
        
        return jsonify({
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Erreur lors de la récupération de l'utilisateur: {str(e)}")
        return jsonify({'error': 'Erreur interne'}), 500

# Fonction pour vérifier si un token est dans la blacklist
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload['jti']
    return jti in blacklisted_tokens