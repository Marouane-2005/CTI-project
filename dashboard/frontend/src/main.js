import { createApp } from 'vue'
import { createRouter, createWebHistory } from 'vue-router'
import { createStore } from 'vuex'
import App from './App.vue'

// Import des composants de route avec les chemins relatifs corrects
import Overview from './views/Overview.vue'
import Intelligence from './views/intelligence.vue'  // Note: 'i' minuscule selon votre arborescence
import Threats from './views/Threat.vue'  // Note: le fichier s'appelle Threat.vue selon votre arborescence
import Reports from './views/Report.vue'  // Note: le fichier s'appelle Report.vue selon votre arborescence
import Login from './views/Login.vue'
// Import des services avec les chemins relatifs corrects
import { dashboardAPI } from './services/api.js'
import { useWebSocket } from './services/websocket.js'

// Configuration des routes
const routes = [
  {
    path: '/login',
    name: 'Login',
    component: Login,
    meta: { 
      title: 'Connexion',
      requiresAuth: false 
    }
  },
  { 
    path: '/', 
    name: 'Overview',
    component: Overview,
    meta: { title: 'Tableau de bord', 
           requiresAuth: true
    }
  },
  { 
    path: '/intelligence', 
    name: 'Intelligence',
    component: Intelligence,
    meta: { title: 'Intelligence',
            requiresAuth: true
    }
  },
  { 
    path: '/threats', 
    name: 'Threats',
    component: Threats,
    meta: { title: 'Menaces',
            requiresAuth: true
    }
  },
  { 
    path: '/reports', 
    name: 'Reports',
    component: Reports,
    meta: { title: 'Rapports',
            requiresAuth: true
     }
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

// Store Vuex pour la gestion d'état
const store = createStore({
  state: {
    isConnected: false,
    notifications: [],
    user: {
      id: null,           
      name: null,         
      isAuthenticated: false,  
      token: null
    },
    apiStatus: 'disconnected'
  },
  mutations: {
    SET_CONNECTION_STATUS(state, status) {
      state.isConnected = status
    },
    ADD_NOTIFICATION(state, notification) {
      state.notifications.unshift({
        id: Date.now(),
        timestamp: new Date(),
        ...notification
      })
      // Limiter à 50 notifications
      if (state.notifications.length > 50) {
        state.notifications = state.notifications.slice(0, 50)
      }
    },
    REMOVE_NOTIFICATION(state, notificationId) {
      state.notifications = state.notifications.filter(n => n.id !== notificationId)
    },
    SET_API_STATUS(state, status) {
      state.apiStatus = status
    },
    SET_USER_AUTH(state, { user, token }) {
      state.user = {
    ...user,
    isAuthenticated: true,
    token
  }
},
    LOGOUT_USER(state) {
  state.user = {
    id: null,
    name: null,
    isAuthenticated: false,
    token: null
  }
}
  },
  actions: {
    async testApiConnection({ commit }) {
      try {
        commit('SET_API_STATUS', 'connecting')
        await dashboardAPI.testConnection()
        commit('SET_API_STATUS', 'connected')
        commit('ADD_NOTIFICATION', {
          type: 'success',
          title: 'Connexion API',
          message: 'Connexion établie avec succès'
        })
        return true
      } catch (error) {
        commit('SET_API_STATUS', 'error')
        commit('ADD_NOTIFICATION', {
          type: 'error',
          title: 'Erreur API',
          message: `Impossible de se connecter: ${error.message}`
        })
        return false
      }
    },

    async login({ commit }, { credentials, rememberMe = false }) {
      try {
        const result = await dashboardAPI.login(credentials)
    
        commit('SET_USER_AUTH', {
           user: result.user,
           token: result.token
        })

    // Sauvegarder les données (vous ajouterez AuthManager plus tard)
        if (typeof window !== 'undefined') {
           const storage = rememberMe ? localStorage : sessionStorage
           storage.setItem('cti_auth_token', result.token)
           storage.setItem('cti_user_data', JSON.stringify(result.user))
        }
    
        commit('ADD_NOTIFICATION', {
          type: 'success',
          title: 'Connexion réussie',
          message: `Bienvenue ${result.user.name}`
       })
    
        return { success: true }
      } catch (error) {
        commit('ADD_NOTIFICATION', {
          type: 'error',
          title: 'Erreur de connexion',
          message: error.message || 'Identifiants incorrects'
      })
      return { success: false, error: error.message }
  }
},
    async logout({ commit }) {
        await dashboardAPI.logout()
  
  // Effacer les données stockées
        if (typeof window !== 'undefined') {
          sessionStorage.removeItem('cti_auth_token')
          sessionStorage.removeItem('cti_user_data')
          localStorage.removeItem('cti_auth_token')
          localStorage.removeItem('cti_user_data')
        }
  
        commit('LOGOUT_USER')
        commit('ADD_NOTIFICATION', {
          type: 'info',
          title: 'Déconnexion',
          message: 'Vous avez été déconnecté avec succès'
        })
},
    async restoreSession({ commit }) {
      if (typeof window === 'undefined') return false
  
      const token = sessionStorage.getItem('cti_auth_token') || localStorage.getItem('cti_auth_token')
      const userData = sessionStorage.getItem('cti_user_data') || localStorage.getItem('cti_user_data')
  
      if (token && userData) {
        try {
          const isValid = await dashboardAPI.verifyToken(token)
          if (isValid) {
            const user = JSON.parse(userData)
            dashboardAPI.setToken(token)
            commit('SET_USER_AUTH', { user, token })
            return true
      }
    }   catch (error) {
        console.error('Erreur restauration session:', error)
    }
  }
  return false
}
  },
  getters: {
    recentNotifications: state => state.notifications.slice(0, 10),
    isApiConnected: state => state.apiStatus === 'connected',
    isAuthenticated: state => state.user.isAuthenticated, 
    currentUser: state => state.user
  }
})

// Navigation guard pour les titres de page
router.beforeEach(async (to, from, next) => {
  document.title = to.meta.title ? `${to.meta.title} - CTI Dashboard` : 'CTI Dashboard'
  
  const isAuthenticated = store.getters.isAuthenticated
  const requiresAuth = to.meta.requiresAuth !== false
  
  // Si pas encore authentifié, essayer de restaurer la session
  if (!isAuthenticated && requiresAuth) {
    const sessionRestored = await store.dispatch('restoreSession')
    
    if (!sessionRestored) {
      next('/login')
      return
    }
  }
  
  if (requiresAuth && !store.getters.isAuthenticated) {
    next('/login')
  } else if (to.path === '/login' && store.getters.isAuthenticated) {
    next('/')
  } else {
    next()
  }
})

const app = createApp(App)

// Configuration globale
app.config.globalProperties.$apiUrl = process.env.VUE_APP_API_URL || 'http://localhost:5001'
app.config.globalProperties.$dashboardAPI = dashboardAPI

// Provide/inject pour les services globaux
app.provide('dashboardAPI', dashboardAPI)
app.provide('websocketService', useWebSocket)

app.use(router)
app.use(store)

// Gestion des erreurs globales
app.config.errorHandler = (error, vm, info) => {
  console.error('Erreur Vue.js:', error)
  console.error('Info:', info)
  
  // Ajouter l'erreur aux notifications
  if (store) {
    store.commit('ADD_NOTIFICATION', {
      type: 'error',
      title: 'Erreur Application',
      message: error.message || 'Une erreur inattendue s\'est produite'
    })
  }
}

store.dispatch('restoreSession').then(() => {
  app.mount('#app')
}).catch((error) => {
  console.error('❌ Erreur lors de l\'initialisation:', error)
  app.mount('#app')
})