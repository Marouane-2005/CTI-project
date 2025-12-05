const API_BASE_URL = process.env.VUE_APP_API_URL || 'http://localhost:5001'

class DashboardAPI {
  constructor() {
    this.baseURL = API_BASE_URL
    this.token = null
    this.defaultHeaders = {
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    }
  }

  // Méthode utilitaire pour les requêtes
  async makeRequest(endpoint, options = {}) {
    const url = `${this.baseURL}${endpoint}`
    const headers = { ...this.defaultHeaders, ...options.headers }
    
    // NOUVEAU: Ajouter le token d'authentification si disponible
    if (this.token && !endpoint.includes('/auth/')) {
      headers['Authorization'] = `Bearer ${this.token}`
    }

    const config = {
      headers,
      ...options
    }

    try {
      console.log(`🌐 API Request: ${config.method || 'GET'} ${url}`)
      const response = await fetch(url, config)
      
      // NOUVEAU: Gérer l'expiration du token
      if (response.status === 401 && this.token) {
        this.token = null
        if (typeof window !== 'undefined') {
          window.location.href = '/login'
        }
        throw new Error('Session expirée')
      }
      
      if (!response.ok) {
        const errorData = await response.text()
        throw new Error(`HTTP ${response.status}: ${errorData}`)
      }

      const data = await response.json()
      console.log(`✅ API Response: ${endpoint}`, data)
      return data
    } catch (error) {
      console.error(`❌ API Error: ${endpoint}`, error)
      throw error
    }
  }

  // Test de connexion
  async testConnection() {
    return this.makeRequest('/api/test')
  }
  
   // === AUTHENTIFICATION ===
  async login(credentials) {
    try {
      const response = await this.makeRequest('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify(credentials)
      })

      this.token = response.token
      return {
        success: true,
        user: response.user,
        token: response.token
      }
    } catch (error) {
      console.error('Erreur de connexion:', error)
      throw new Error(error.message || 'Identifiants incorrects')
    }
  }

  async logout() {
    try {
      if (this.token) {
        await this.makeRequest('/api/auth/logout', {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${this.token}` }
        })
      }
    } catch (error) {
      console.error('Erreur de déconnexion:', error)
    } finally {
      this.token = null
    }
  }

  async verifyToken(token) {
    try {
      const response = await fetch(`${this.baseURL}/api/auth/verify`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        }
      })
      return response.ok
    } catch (error) {
      console.error('Erreur de vérification du token:', error)
      return false
    }
  }

  setToken(token) {
    this.token = token
  }

  getToken() {
    return this.token
  }
  // === DASHBOARD OVERVIEW ===
  async getOverview() {
    return this.makeRequest('/api/dashboard/overview')
  }

  async getDashboardStats() {
    return this.makeRequest('/api/dashboard/stats')
  }

  // === MENACES ET IOCs ===
  async getLiveThreats(params = {}) {
    const query = new URLSearchParams(params).toString()
    const endpoint = query ? `/api/dashboard/threats/live?${query}` : '/api/dashboard/threats/live'
    return this.makeRequest(endpoint)
  }

  async searchIOCs(searchParams = {}) {
    return this.makeRequest('/api/dashboard/iocs/search', {
      method: 'POST',
      body: JSON.stringify(searchParams)
    })
  }

  async getThreatLandscape() {
    return this.makeRequest('/api/dashboard/threat-landscape')
  }
  

  async getRecentIOCs(params = {}) {
  const query = new URLSearchParams(params).toString()
  const endpoint = query ? `/api/dashboard/iocs/recent?${query}` : '/api/dashboard/iocs/recent'
  return this.makeRequest(endpoint)
}
  // === ALERTES ===
  async getAlerts(acknowledged = null) {
    const query = acknowledged !== null ? `?acknowledged=${acknowledged}` : ''
    return this.makeRequest(`/api/dashboard/alerts${query}`)
  }

  async acknowledgeAlert(alertId, userId = 'dashboard-user') {
    return this.makeRequest(`/api/dashboard/alerts/${alertId}/acknowledge`, {
      method: 'POST',
      body: JSON.stringify({ user_id: userId })
    })
  }

  // === MITRE ATT&CK ===
  async getMitreOverview() {
    return this.makeRequest('/api/dashboard/mitre/overview')
  }

  async getMitreHeatmap(days = 30) {
    return this.makeRequest(`/api/dashboard/mitre/heatmap?days=${days}`)
  }

  async getEnhancedMitreHeatmap(days = 30) {
    return this.makeRequest(`/api/dashboard/mitre/heatmap/enhanced?days=${days}`)
  }

  async getMitreThreatActors() {
    return this.makeRequest('/api/dashboard/mitre/threat-actors')
  }

  async getMitreSoftware() {
    return this.makeRequest('/api/dashboard/mitre/software')
  }

  async getMitreCoverage() {
    return this.makeRequest('/api/dashboard/mitre/coverage')
  }

  async searchMitreTechniques(searchParams = {}) {
    return this.makeRequest('/api/dashboard/mitre/search', {
      method: 'POST',
      body: JSON.stringify(searchParams)
    })
  }

  async getMitreTimeline(days = 30) {
    return this.makeRequest(`/api/dashboard/mitre/timeline?days=${days}`)
  }

  async getMitreWidgets() {
    return this.makeRequest('/api/dashboard/mitre/widgets')
  }

  // === MÉTRIQUES ===
  async getMetricsTimeline(days = 7) {
    return this.makeRequest(`/api/dashboard/metrics/timeline?days=${days}`)
  }

  // === COLLECTOR ===
  async getCollectorStatus() {
    return this.makeRequest('/api/dashboard/collector/status')
  }

  async triggerCollection() {
    return this.makeRequest('/api/dashboard/collector/trigger', {
      method: 'POST'
    })
  }

  // === MÉTHODES BATCH POUR OPTIMISER LES CHARGEMENTS ===
  async getDashboardData() {
    try {
      const [overview, alerts, mitreHeatmap, stats] = await Promise.all([
        this.getOverview(),
        this.getAlerts(),
        this.getMitreHeatmap(),
        this.getDashboardStats()
      ])

      return {
        overview,
        alerts: alerts.alerts || [],
        mitreHeatmap: mitreHeatmap.heatmap || [],
        stats,
        timestamp: new Date().toISOString()
      }
    } catch (error) {
      console.error('Erreur lors du chargement des données dashboard:', error)
      throw error
    }
  }

  async getMitreCompleteData() {
    try {
      const [overview, threatActors, software, coverage, timeline] = await Promise.all([
        this.getMitreOverview(),
        this.getMitreThreatActors(),
        this.getMitreSoftware(), 
        this.getMitreCoverage(),
        this.getMitreTimeline()
      ])

      return {
        overview,
        threatActors: threatActors.threat_actors || [],
        software: software.software_list || [],
        coverage,
        timeline: timeline.timeline || [],
        timestamp: new Date().toISOString()
      }
    } catch (error) {
      console.error('Erreur lors du chargement des données MITRE:', error)
      throw error
    }
  }

  // === UTILITAIRES ===
  formatError(error) {
    if (error.name === 'TypeError' && error.message.includes('fetch')) {
      return 'Impossible de se connecter au serveur. Vérifiez que le backend est démarré.'
    }
    return error.message || 'Une erreur inattendue s\'est produite'
  }

  
  async makeRequest(endpoint, options = {}) {
  const url = `${this.baseURL}${endpoint}`
  const config = {
    headers: { ...this.defaultHeaders, ...options.headers },
    ...options
  }

  try {
    console.log(`🌐 API Request: ${config.method || 'GET'} ${url}`)
    const response = await fetch(url, config)
    
    if (!response.ok) {
      const errorData = await response.text()
      throw new Error(`HTTP ${response.status}: ${errorData}`)
    }

    const data = await response.json()
    console.log(`✅ API Response: ${endpoint}`, data)
    return data
  } catch (error) {
    console.error(`❌ API Error: ${endpoint}`, error)
    throw error
  }
}
  // À ajouter dans dashboard/frontend/src/services/api.js

// === GÉNÉRATION DE RAPPORTS ===
  
  async generateReport(reportType, options = {}) {
    return this.makeRequest('/api/reports/generate', {
      method: 'POST',
      body: JSON.stringify({
        type: reportType,
        options: options,
        timestamp: new Date().toISOString()
      })
    })
  }

  async getRecentReports(limit = 10) {
    return this.makeRequest(`/api/reports/recent?limit=${limit}`)
  }

  async getReportStatus(reportId) {
    return this.makeRequest(`/api/reports/${reportId}/status`)
  }

  async downloadReport(reportId) {
  try {
    console.log(`🔽 Téléchargement rapport: ${reportId}`)
    
    const url = `${this.baseURL}/api/reports/${reportId}/download`
    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'Accept': 'application/pdf'
      }
    })
    
    if (!response.ok) {
      let errorMessage = `Erreur HTTP ${response.status}`
      
      try {
        const errorData = await response.json()
        errorMessage = errorData.error || errorMessage
      } catch {
        errorMessage = `Erreur ${response.status}: ${response.statusText}`
      }
      
      throw new Error(errorMessage)
    }
    
    // Vérifier le type de contenu
    const contentType = response.headers.get('content-type')
    if (!contentType || !contentType.includes('application/pdf')) {
      console.warn('⚠️ Type de contenu inattendu:', contentType)
      // Ne pas lever d'erreur, continuer quand même
    }
    
    const blob = await response.blob()
    
    // Vérifier la taille du blob
    if (blob.size < 100) {
      throw new Error('Fichier PDF corrompu ou vide')
    }
    
    console.log(`✅ PDF téléchargé: ${blob.size} bytes`)
    return blob
    
  } catch (error) {
    console.error('❌ Erreur téléchargement PDF:', error)
    throw error
  }
}

// ✅ CORRECTION 7: Méthode d'aide pour déclencher le téléchargement
async downloadAndSaveReport(reportId, filename = null) {
  try {
    const blob = await this.downloadReport(reportId)
    
    // Créer un lien de téléchargement
    const url = window.URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = filename || `rapport_${reportId}.pdf`
    
    // Déclencher le téléchargement
    document.body.appendChild(link)
    link.click()
    
    // Nettoyer
    document.body.removeChild(link)
    window.URL.revokeObjectURL(url)
    
    console.log(`✅ Téléchargement déclenché: ${link.download}`)
    return true
    
  } catch (error) {
    console.error('❌ Erreur téléchargement et sauvegarde:', error)
    throw error
  }
}

  async getReportPreview(reportId) {
    return this.makeRequest(`/api/reports/${reportId}/preview`)
  }

  // Méthodes spécifiques aux rapports d'attaques
  async generateAttackReport(attackId, options = {}) {
    return this.makeRequest('/api/reports/attack', {
      method: 'POST',
      body: JSON.stringify({
        attack_id: attackId,
        include_timeline: options.include_timeline || true,
        include_mitre: options.include_mitre || true,
        include_iocs: options.include_iocs || true,
        format: options.format || 'pdf'
      })
    })
  }

  async getAttackAnalysis(attackId) {
    return this.makeRequest(`/api/dashboard/attacks/${attackId}/analysis`)
  }
  // Vérification de l'état de l'API
  // REMPLACER votre healthCheck() existant par :
  async healthCheck() {
    try {
      const response = await this.testConnection()
      return {
        status: 'healthy',
        timestamp: response.timestamp,
        message: 'API accessible',
        authenticated: !!this.token  // ← AJOUTER CETTE LIGNE
     }
    } catch (error) {
      return {
       status: 'unhealthy',
       timestamp: new Date().toISOString(),
       message: this.formatError(error),
       authenticated: false  // ← AJOUTER CETTE LIGNE
    }
  }
}
}

// Instance singleton
export const dashboardAPI = new DashboardAPI()

// Export de la classe pour les tests
export default DashboardAPI