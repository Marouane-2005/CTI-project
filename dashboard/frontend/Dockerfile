# dashboard/frontend/Dockerfile
FROM node:18-alpine as build-stage

WORKDIR /app

# Copie uniquement package.json d'abord
COPY package.json ./

# Génère le package-lock.json et installe les dépendances
RUN npm install --package-lock-only && \
    npm ci --only=production

# Alternative: si vous avez déjà un package-lock.json valide
# COPY package*.json ./
# RUN npm ci --only=production

# Copie le reste du code source
COPY . .

# Vérification de la structure avant build
RUN echo "=== Vérification de la structure ===" && \
    ls -la && \
    echo "=== Contenu src/ ===" && \
    ls -la src/ 2>/dev/null || echo "Dossier src/ manquant!" && \
    echo "=== Vérification des fichiers critiques ===" && \
    test -f src/main.js && echo "✅ main.js présent" || echo "❌ main.js manquant" && \
    test -f src/App.vue && echo "✅ App.vue présent" || echo "❌ App.vue manquant"

# Construction de l'application
RUN npm run build

# Stage de production avec Nginx
FROM nginx:alpine as production-stage

# Copie des fichiers buildés
COPY --from=build-stage /app/dist /usr/share/nginx/html

# Configuration Nginx pour SPA
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]