# dashboard/frontend/Dockerfile - Version simplifiée et robuste
FROM node:18-alpine as builder

# Travail en root pour éviter tous les problèmes de permissions
USER root

WORKDIR /app

# 1. Installation des dépendances
COPY package*.json ./

# FORCER l'installation avec toutes les permissions
RUN npm config set unsafe-perm true && \
    npm install --legacy-peer-deps && \
    # Installer Vue CLI globalement
    npm install -g @vue/cli-service

# 2. Vérification CRITIQUE
RUN echo "=== VÉRIFICATION CRITIQUE ===" && \
    # Vérifier que vue-cli-service est exécutable
    ls -la /usr/local/bin/vue-cli-service && \
    chmod +x /usr/local/bin/vue-cli-service && \
    # Tester la commande
    vue-cli-service --version && \
    echo "✅ Vue CLI est prêt"

# 3. Copie du code source
COPY . .

# 4. Vérification du projet
RUN echo "=== PROJET VUE.JS ===" && \
    # Vérifier la structure Vue
    if [ -d "src" ]; then \
        echo "✅ Structure Vue.js détectée"; \
        echo "Fichiers dans src/:"; \
        ls -la src/ | head -10; \
    else \
        echo "❌ Structure Vue.js NON détectée!"; \
        echo "Structure actuelle:"; \
        ls -la; \
        exit 1; \
    fi

# 5. BUILD avec commande directe (plus fiable que npm run)
RUN echo "=== LANCEMENT DU BUILD ===" && \
    # Utiliser directement vue-cli-service
    vue-cli-service build --mode production

# 6. Vérification du résultat
RUN echo "=== BUILD TERMINÉ ===" && \
    echo "Contenu de dist/:" && \
    ls -la dist/ && \
    [ -f "dist/index.html" ] && echo "✅ index.html généré" || echo "❌ index.html MANQUANT!"

# 7. Production avec Nginx
FROM nginx:alpine

COPY --from=builder /app/dist /usr/share/nginx/html

# Configuration Nginx minimaliste et fonctionnelle
RUN rm /etc/nginx/conf.d/default.conf && \
    echo 'server {
        listen 80;
        root /usr/share/nginx/html;
        index index.html;
        location / {
            try_files $uri $uri/ /index.html;
        }
    }' > /etc/nginx/conf.d/app.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]