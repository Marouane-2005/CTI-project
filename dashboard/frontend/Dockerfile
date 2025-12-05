# dashboard/frontend/Dockerfile
FROM node:18-alpine as build-stage

# Étape cruciale : Travailler en tant que root pour éviter les problèmes de permissions
USER root

WORKDIR /app

# 1. Copier uniquement les fichiers de dépendances
COPY package*.json ./

# 2. Installer Vue CLI globalement et localement
RUN echo "Installing Vue CLI..." && \
    npm install -g @vue/cli-service --unsafe-perm && \
    # Installer les dépendances du projet
    npm ci --unsafe-perm && \
    # S'assurer que vue-cli-service est accessible
    ln -sf /usr/local/bin/vue-cli-service ./node_modules/.bin/vue-cli-service || true && \
    # Donner les permissions d'exécution à TOUS les binaires
    chmod -R +x ./node_modules/.bin/ 2>/dev/null || true && \
    chmod +x /usr/local/bin/vue-cli-service && \
    # Vérifier l'installation
    echo "Vue CLI version:" && \
    vue-cli-service --version

# 3. Vérification détaillée
RUN echo "=== VÉRIFICATION DES PERMISSIONS ===" && \
    echo "Recherche de vue-cli-service:" && \
    find / -name "*vue-cli-service*" 2>/dev/null | head -5 && \
    echo "" && \
    echo "Permissions de node_modules/.bin:" && \
    ls -la ./node_modules/.bin/ 2>/dev/null || echo "Aucun dossier .bin trouvé" && \
    echo "" && \
    echo "Chemin PATH:" && \
    echo $PATH

# 4. Copier le code source AVANT le build
COPY . .

# 5. Vérifier la structure du projet
RUN echo "=== STRUCTURE DU PROJET ===" && \
    ls -la && \
    echo "" && \
    echo "Contenu de src/:" && \
    ls -la src/ 2>/dev/null || echo "⚠️ Dossier src/ non trouvé!" && \
    echo "" && \
    echo "Scripts disponibles:" && \
    npm run

# 6. EXÉCUTION DU BUILD avec npx pour éviter les problèmes de chemin
RUN echo "=== DÉMARRAGE DU BUILD ===" && \
    # Essayer avec npx d'abord (plus fiable)
    npx vue-cli-service build || { \
        echo "⚠️ npx a échoué, tentative avec le chemin direct..." && \
        # Essayer le chemin local
        ./node_modules/.bin/vue-cli-service build || { \
            echo "⚠️ Chemin local a échoué, tentative avec global..." && \
            # Essayer le chemin global
            /usr/local/bin/vue-cli-service build || { \
                echo "❌ TOUTES LES TENTATIVES ONT ÉCHOUÉ" && \
                echo "Debug info:" && \
                echo "1. which vue-cli-service:" && \
                which vue-cli-service || echo "Non trouvé dans PATH" && \
                echo "2. Recherche étendue:" && \
                find /app -type f -name "*vue*" 2>/dev/null | head -10 && \
                echo "3. Test de vue-cli-service:" && \
                vue-cli-service --version || echo "Commande non disponible" && \
                exit 1; \
            }; \
        }; \
    }

# 7. Vérifier le résultat du build
RUN echo "=== VÉRIFICATION DU BUILD ===" && \
    echo "Contenu du dossier dist/:" && \
    ls -la dist/ && \
    echo "" && \
    echo "Taille du build:" && \
    du -sh dist/

# 8. Stage de production avec Nginx
FROM nginx:alpine as production-stage

# Copie des fichiers buildés
COPY --from=build-stage /app/dist /usr/share/nginx/html

# Configuration Nginx optimisée pour Vue.js
RUN echo 'server {
    listen 80;
    server_name _;
    root /usr/share/nginx/html;
    index index.html;
    
    # Compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css text/xml text/javascript application/javascript application/xml+rss application/json;
    
    # Cache des assets statiques
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
    
    # Vue Router history mode
    location / {
        try_files $uri $uri/ /index.html;
    }
    
    # Health check
    location /health {
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }
}' > /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]