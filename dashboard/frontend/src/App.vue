<!-- dashboard/frontend/src/App.vue -->
<template>
  <div id="app">
    <!-- Navigation principale avec logo et certifications -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary shadow-sm">
      <div class="container-fluid d-flex align-items-center">
        <!-- Logo Symolia et certifications à gauche -->
        <div class="navbar-left d-flex align-items-center me-auto">
          <div class="navbar-logo me-3">
            <img :src="images.symoliaLogo" alt="Symolia Groupe" class="symolia-logo">
          </div>
          <div class="navbar-certifications">
            <div class="cert-group">
              <img :src="images.iso27001" alt="ISO 27001" class="navbar-cert" title="ISO 27001 - Sécurité de l'information">
              <img :src="images.iso9001" alt="ISO 9001" class="navbar-cert" title="ISO 9001 - Management de la qualité">
              <img :src="images.ecovadisGold" alt="EcoVadis Gold" class="navbar-cert" title="EcoVadis Gold - Top 5% RSE">
              <img :src="images.unGlobalCompact" alt="UN Global Compact" class="navbar-cert" title="UN Global Compact">
            </div>
          </div>
        </div>
        
        <!-- Nom du dashboard exactement au milieu -->
        <div class="navbar-brand-center position-absolute start-50 translate-middle-x">
          <router-link to="/" class="navbar-brand text-decoration-none">
            <div class="brand-title">CTI Dashboard</div>
          </router-link>
        </div>
        
        <!-- Espace pour équilibrer la navbar -->
        <div class="navbar-right ms-auto" style="width: 1px;">
          <!-- Espace vide pour équilibrer le centrage -->
        </div>
        
        <!-- Toggle button pour mobile -->
        <button 
          class="navbar-toggler" 
          type="button" 
          data-bs-toggle="collapse" 
          data-bs-target="#navbarNav"
        >
          <span class="navbar-toggler-icon"></span>
        </button>
        
        <!-- Menu de navigation -->
        <div class="collapse navbar-collapse" id="navbarNav">
          <ul class="navbar-nav mx-auto mt-3">
            <li class="nav-item">
              <router-link 
                to="/" 
                class="nav-link"
                :class="{ active: $route.path === '/' }"
              >
                <i class="fas fa-home me-1"></i>Accueil
              </router-link>
            </li>
            <li class="nav-item">
              <router-link 
                to="/intelligence" 
                class="nav-link"
                :class="{ active: $route.path === '/intelligence' }"
              >
                <i class="fas fa-brain me-1"></i>Intelligence
              </router-link>
            </li>
            <li class="nav-item">
              <router-link 
                to="/threats" 
                class="nav-link"
                :class="{ active: $route.path === '/threats' }"
              >
                <i class="fas fa-shield-alt me-1"></i>Menaces
              </router-link>
            </li>
            <li class="nav-item">
              <router-link 
                to="/reports" 
                class="nav-link"
                :class="{ active: $route.path === '/reports' }"
              >
                <i class="fas fa-chart-line me-1"></i>Rapports
              </router-link>
            </li>
          </ul>
        </div>
      </div>
    </nav>
    
    <!-- Indicateur de chargement -->
    <div v-if="loading" class="loading-overlay">
      <div class="spinner-border text-primary" role="status">
        <span class="visually-hidden">Chargement...</span>
      </div>
    </div>
    
    <!-- Zone principale de contenu -->
    <main class="container-fluid mt-3">
      <router-view v-slot="{ Component }">
        <transition name="fade" mode="out-in">
          <component :is="Component" />
        </transition>
      </router-view>
    </main>
    
    <!-- Footer optionnel -->
    <footer class="bg-light mt-5 py-3">
      <div class="container text-center">
        <small class="text-muted">
          CTI Dashboard v1.0 - Dernière mise à jour: {{ lastUpdate }}
        </small>
      </div>
    </footer>
  </div>
</template>

<script>
// Import des images
import symoliaLogo from '@/assets/images/symolia-logo.png'
import iso27001 from '@/assets/images/iso-27001.png'
import iso9001 from '@/assets/images/iso-9001.png'
import ecovadisGold from '@/assets/images/ecovadis-gold.png'
import unGlobalCompact from '@/assets/images/un-global-compact.png'

export default {
  name: 'App',
  data() {
    return {
      loading: false,
      lastUpdate: new Date().toLocaleString('fr-FR'),
      apiBaseUrl: process.env.VUE_APP_API_URL || 'http://localhost:5001',
      // Images importées
      images: {
        symoliaLogo,
        iso27001,
        iso9001,
        ecovadisGold,
        unGlobalCompact
      }
    }
  },
  
  mounted() {
    // Test de connexion à l'API
    this.testApiConnection()
    
    // Mise à jour périodique du timestamp
    setInterval(() => {
      this.lastUpdate = new Date().toLocaleString('fr-FR')
    }, 60000)
  },
  
  methods: {
    async testApiConnection() {
      try {
        this.loading = true
        const response = await fetch(`${this.apiBaseUrl}/api/test`)
        if (!response.ok) {
          throw new Error(`API Error: ${response.status}`)
        }
        
        const data = await response.json()
        console.log('✅ Connexion API réussie:', data)
    }   catch (error) {
        console.error('❌ Erreur connexion API:', error)
      // Afficher un message utilisateur
        this.$toast?.error?.('Impossible de se connecter au backend')
    }   finally {
        this.loading = false
    }
  }
}
}
</script>

<style scoped>
#app {
  font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
  min-height: 100vh;
  display: flex;
  flex-direction: column;
}

main {
  flex: 1;
}

/* Navigation réorganisée */
.navbar {
  padding: 15px 0;
  min-height: 80px;
}

.container-fluid {
  max-width: 100%;
  padding: 0 20px;
}

/* Logo Symolia à gauche */
.navbar-logo {
  width: 200px;
  display: flex;
  align-items: center;
}

.symolia-logo {
  height: 60px;
  width: auto;
  object-fit: contain;
  /* Logo bien intégré sans bordures visibles */
  opacity: 0.6;
  transition: all 0.3s ease;
  /* Masquer les bords avec un masque dégradé */
  mask: radial-gradient(ellipse at center, rgba(0,0,0,1) 60%, rgba(0,0,0,0.8) 80%, rgba(0,0,0,0) 100%);
  -webkit-mask: radial-gradient(ellipse at center, rgba(0,0,0,1) 60%, rgba(0,0,0,0.8) 80%, rgba(0,0,0,0) 100%);
  /* Filtre pour adoucir les contours */
  filter: blur(0.3px);
}

.symolia-logo:hover {
  opacity: 0.8;
  transform: scale(1.02);
  filter: blur(0px);
}

/* Nom du dashboard au milieu */
.navbar-brand-center {
  max-width: 400px;
}

.navbar-brand {
  color: white !important;
  text-decoration: none !important;
}

.brand-title {
  font-size: 1.8rem;
  font-weight: 700;
  line-height: 1.2;
  margin-bottom: 2px;
}

.brand-subtitle {
  font-size: 0.75rem;
  opacity: 0.85;
  font-weight: 400;
  letter-spacing: 0.5px;
}

/* Certifications à droite */
.navbar-certifications {
  width: 200px;
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 8px;
}

.cert-text {
  font-size: 0.7rem;
  font-weight: 600;
  color: rgba(255, 255, 255, 0.8);
  text-transform: uppercase;
  letter-spacing: 0.8px;
  white-space: nowrap;
}

.cert-group {
  display: flex;
  gap: 6px;
  align-items: center;
}

/* Images de certifications */
.navbar-cert {
  height: 60px;
  width: auto;
  object-fit: contain;
  transition: all 0.2s ease;
  opacity: 1;
  /* Supprimer le filtre pour voir les vraies couleurs */
  cursor: pointer;
  /* Ajouter un fond léger pour la visibilité */
  background: rgba(255, 255, 255, 0.15);
  padding: 3px 6px;
  border-radius: 4px;
}

.navbar-cert:hover {
  opacity: 0.8;
  transform: scale(1.1);
  background: rgba(255, 255, 255, 0.25);
}

/* Toggle button */
.navbar-toggler {
  order: 4;
  margin-left: 10px;
}

/* Menu de navigation mobile */
.navbar-collapse {
  width: 100%;
  margin-top: 15px;
}

.navbar-nav {
  text-align: center;
}

/* Styles pour la navigation active */
.nav-link.active {
  background-color: rgba(255, 255, 255, 0.2);
  border-radius: 4px;
}

/* Loading overlay */
.loading-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background-color: rgba(0, 0, 0, 0.5);
  display: flex;
  justify-content: center;
  align-items: center;
  z-index: 9999;
}

/* Transitions */
.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}

/* Responsive Design */
@media (max-width: 992px) {
  .container-fluid {
    flex-direction: column;
    gap: 15px;
    text-align: center;
  }
  
  .navbar-logo,
  .navbar-brand-center,
  .navbar-certifications {
    width: 100%;
    justify-content: center;
  }
  
  .navbar-certifications {
    order: 3;
  }
}

@media (max-width: 768px) {
  .navbar {
    padding: 12px 0;
  }
  
  .container-fluid {
    padding: 0 15px;
  }
  
  .symolia-logo {
    height: 50px;
  }
  
  .brand-title {
    font-size: 1.4rem;
  }
  
  .brand-subtitle {
    font-size: 0.65rem;
  }
  
  .cert-text {
    font-size: 0.6rem;
  }
  
  .cert-placeholder {
    font-size: 0.55rem;
    padding: 3px 5px;
    min-width: 22px;
  }
}

@media (max-width: 576px) {
  .navbar {
    padding: 10px 0;
  }
  
  .symolia-logo {
    height: 42px;
  }
  
  .brand-title {
    font-size: 1.2rem;
  }
  
  .brand-subtitle {
    font-size: 0.6rem;
  }
  
  .cert-group {
    gap: 4px;
  }
  
  .navbar-cert {
    height: 22px;
  }
}
</style>

<style>
/* Styles globaux */
body {
  margin: 0;
  background-color: #f8f9fa;
}

/* Personnalisation Bootstrap */
.navbar-brand {
  font-weight: bold;
}

.card {
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
  border: none;
}

.btn-primary {
  background-color: #007bff;
  border-color: #007bff;
}

.btn-primary:hover {
  background-color: #0056b3;
  border-color: #0056b3;
}
</style>