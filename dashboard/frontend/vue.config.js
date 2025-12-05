// vue.config.js - Version corrigée pour Docker
module.exports = {
  devServer: {
    port: 8081,
    host: '0.0.0.0', // AJOUT: Écouter sur toutes les interfaces
    proxy: {
      '/api': {
        // CORRECTION: Utiliser le nom du conteneur Docker au lieu de localhost
        target: process.env.NODE_ENV === 'production' 
          ? 'http://cti-dashboard-backend:5001'  // En production (Docker)
          : 'http://localhost:5001',             // En développement
        changeOrigin: true,
        logLevel: 'debug',
        timeout: 10000, // AJOUT: Timeout plus long
        onError: function(err, req, res) {
          console.log('Proxy Error:', err);
        }
      },
      '/socket.io': {
        target: process.env.NODE_ENV === 'production'
          ? 'http://cti-dashboard-backend:5001'  // En production (Docker) 
          : 'http://localhost:5001',             // En développement
        changeOrigin: true,
        ws: true,
        timeout: 10000
      }
    }
  },
  configureWebpack: {
    resolve: {
      alias: {
        '@': require('path').resolve(__dirname, 'src')
      }
    }
  }
}