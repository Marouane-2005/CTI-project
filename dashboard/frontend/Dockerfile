# dashboard/frontend/Dockerfile - Version optimisée
FROM node:18-alpine as builder

WORKDIR /app

# Étape 1: Installer Vue CLI globalement pour éviter les problèmes de permissions
RUN npm install -g @vue/cli-service --unsafe-perm && \
    echo "Vue CLI version: $(vue-cli-service --version)"

# Étape 2: Copier et installer les dépendances du projet
COPY package*.json ./

# Installer toutes les dépendances (production + développement)
RUN npm ci --unsafe-perm && \
    # Créer un lien symbolique pour s'assurer que vue-cli-service est accessible
    ln -sf /usr/local/bin/vue-cli-service ./node_modules/.bin/vue-cli-service || true && \
    # Donner les permissions d'exécution
    chmod +x ./node_modules/.bin/* 2>/dev/null || true

# Étape 3: Copier le code source
COPY . .

# Étape 4: Vérifier la configuration
RUN echo "=== Configuration Vérifiée ===" && \
    echo "Structure du projet:" && \
    find . -maxdepth 2 -type f -name "*.js" -o -name "*.vue" -o -name "*.json" | head -20 && \
    echo "" && \
    echo "Scripts disponibles:" && \
    npm run

# Étape 5: Build l'application
RUN npm run build || { \
    echo "=== DEBUG INFORMATION ==="; \
    echo "1. Checking vue-cli-service:"; \
    which vue-cli-service || echo "Not in PATH"; \
    find /app -name "*vue-cli-service*" 2>/dev/null; \
    echo ""; \
    echo "2. Node modules bin directory:"; \
    ls -la /app/node_modules/.bin/ 2>/dev/null || echo "No .bin directory"; \
    echo ""; \
    echo "3. Trying direct vue-cli-service call:"; \
    npx vue-cli-service build 2>&1 | head -50 || echo "npx failed"; \
    exit 1; \
}

# Étape 6: Production avec Nginx
FROM nginx:alpine

# Copier les fichiers construits
COPY --from=builder /app/dist /usr/share/nginx/html

# Configuration Nginx optimisée pour Vue.js
RUN echo 'server { \
    listen 80; \
    server_name localhost; \
    root /usr/share/nginx/html; \
    index index.html; \
    \
    # Compression Gzip \
    gzip on; \
    gzip_vary on; \
    gzip_min_length 1024; \
    gzip_types text/plain text/css text/xml text/javascript application/javascript application/xml+rss application/json; \
    \
    # Headers de sécurité \
    add_header X-Frame-Options "SAMEORIGIN" always; \
    add_header X-Content-Type-Options "nosniff" always; \
    add_header X-XSS-Protection "1; mode=block" always; \
    \
    # Cache pour les assets statiques \
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ { \
        expires 1y; \
        add_header Cache-Control "public, immutable"; \
    } \
    \
    # Gestion du mode history de Vue Router \
    location / { \
        try_files $uri $uri/ /index.html; \
    } \
}' > /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]