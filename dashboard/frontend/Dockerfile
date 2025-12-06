# dashboard/frontend/Dockerfile
FROM node:18-alpine as build-stage

WORKDIR /app

# Copier les fichiers de config d'abord
COPY package*.json ./

# Installer TOUTES les dépendances (y compris dev)
RUN npm install


# Copier le code source
COPY . .

# Donner les permissions d'exécution aux binaires npm
RUN chmod -R +x node_modules/.bin

# Vérifier que vue-cli-service existe
RUN ls -la node_modules/.bin

# Construire l'application
RUN npm run build

# ------ STAGE DE PRODUCTION ------
FROM nginx:alpine as production-stage

COPY --from=build-stage /app/dist /usr/share/nginx/html

COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
