// utils/auth.js
import { dashboardAPI } from '../services/api.js'

const TOKEN_KEY = 'cti_auth_token'
const USER_KEY = 'cti_user_data'

export class AuthManager {
  // Sauvegarder les données d'authentification
  static saveAuthData(user, token, rememberMe = false) {
    const storage = rememberMe ? localStorage : sessionStorage
    
    storage.setItem(TOKEN_KEY, token)
    storage.setItem(USER_KEY, JSON.stringify(user))
    
    // Configurer le token dans l'API
    dashboardAPI.setToken(token)
  }

  // Restaurer les données d'authentification
  static restoreAuthData() {
    // Vérifier d'abord sessionStorage, puis localStorage
    let token = sessionStorage.getItem(TOKEN_KEY) || localStorage.getItem(TOKEN_KEY)
    let userData = sessionStorage.getItem(USER_KEY) || localStorage.getItem(USER_KEY)

    if (token && userData) {
      try {
        const user = JSON.parse(userData)
        dashboardAPI.setToken(token)
        return { user, token }
      } catch (error) {
        console.error('Erreur lors de la restauration des données utilisateur:', error)
        this.clearAuthData()
      }
    }
    
    return null
  }

  // Vérifier si le token est valide
  static async verifyStoredToken() {
    const authData = this.restoreAuthData()
    
    if (!authData) {
      return false
    }

    try {
      const isValid = await dashboardAPI.verifyToken(authData.token)
      if (!isValid) {
        this.clearAuthData()
      }
      return isValid
    } catch (error) {
      console.error('Erreur de vérification du token:', error)
      this.clearAuthData()
      return false
    }
  }

  // Effacer les données d'authentification
  static clearAuthData() {
    sessionStorage.removeItem(TOKEN_KEY)
    sessionStorage.removeItem(USER_KEY)
    localStorage.removeItem(TOKEN_KEY)
    localStorage.removeItem(USER_KEY)
    
    dashboardAPI.setToken(null)
  }

  // Vérifier si l'utilisateur est connecté
  static isAuthenticated() {
    return dashboardAPI.getToken() !== null
  }

  // Obtenir les données utilisateur stockées
  static getStoredUser() {
    const userData = sessionStorage.getItem(USER_KEY) || localStorage.getItem(USER_KEY)
    if (userData) {
      try {
        return JSON.parse(userData)
      } catch (error) {
        console.error('Erreur lors de la lecture des données utilisateur:', error)
        return null
      }
    }
    return null
  }
}

// Utilitaires d'authentification pour les composants
export const authMixin = {
  computed: {
    isAuthenticated() {
      return this.$store.getters.isAuthenticated
    },
    currentUser() {
      return this.$store.getters.currentUser
    }
  },
  methods: {
    async logout() {
      await this.$store.dispatch('logout')
      this.$router.push('/login')
    }
  }
}

// Guard de route pour l'authentification
export const requireAuth = (to, from, next) => {
  const isAuthenticated = AuthManager.isAuthenticated()
  
  if (!isAuthenticated) {
    next('/login')
  } else {
    next()
  }
}

// Initialisation automatique au démarrage de l'app
export const initializeAuth = async (store) => {
  const authData = AuthManager.restoreAuthData()
  
  if (authData) {
    // Vérifier que le token est encore valide
    const isValid = await AuthManager.verifyStoredToken()
    
    if (isValid) {
      store.commit('SET_USER_AUTH', authData)
      console.log('✅ Session restaurée pour:', authData.user.name)
      return true
    }
  }
  
  return false
}