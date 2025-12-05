# dashboard/frontend/Dockerfile
FROM node:18-alpine as build-stage

WORKDIR /app

# 1. Copier les fichiers de dépendances
COPY package*.json ./

# 2. Installer TOUTES les dépendances (y compris devDependencies)
RUN npm ci --include=dev --unsafe-perm && \
    # Vérifier que vue-cli-service est installé
    ls -la node_modules/.bin/vue-cli-service && \
    chmod +x node_modules/.bin/vue-cli-service

# 3. Vérification de l'installation
RUN echo "=== Vérification des dépendances ===" && \
    echo "Node version: $(node --version)" && \
    echo "NPM version: $(npm --version)" && \
    echo "Vue CLI Service:" && \
    ./node_modules/.bin/vue-cli-service --version || npm list @vue/cli-service

# 4. Copier le code source
COPY . .

# 5. Vérification de la structure avant build
RUN echo "=== Vérification de la structure ===" && \
    ls -la && \
    echo "=== Contenu src/ ===" && \
    ls -la src/ 2>/dev/null || echo "⚠️ Dossier src/ manquant!" && \
    echo "=== Fichiers critiques ===" && \
    test -f src/main.js && echo "✅ main.js présent" || echo "❌ main.js manquant" && \
    test -f src/App.vue && echo "✅ App.vue présent" || echo "❌ App.vue manquant" && \
    echo "=== package.json scripts ===" && \
    cat package.json | grep -A5 '"scripts"'

# 6. Construction de l'application
RUN npm run build || { \
    echo "❌ Build échoué. Debug info:"; \
    echo "Contenu de node_modules/.bin:"; \
    ls -la node_modules/.bin/; \
    echo "Recherche de vue-cli-service:"; \
    find . -name "*vue-cli-service*" 2>/dev/null; \
    exit 1; \
}

# 7. Stage de production avec Nginx
FROM nginx:alpine as production-stage

# Copie des fichiers buildés
COPY --from=build-stage /app/dist /usr/share/nginx/html

# Configuration Nginx pour SPA
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]