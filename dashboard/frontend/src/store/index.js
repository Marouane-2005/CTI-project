import { createStore } from 'vuex'
import { dashboardAPI } from '@/services/api'

// Modules du store
const dashboard = {
  namespaced: true,
  state: {
    overview: {
      total_iocs_today: 0,
      active_threats: 0,
      critical_alerts: 0,
      risk_score_avg: 0,
      recent_iocs: [],
      geographical_threats: {},
      last_updated: null
    },
    stats: {},
    loading: false,
    error: null
  },
  mutations: {
    SET_OVERVIEW(state, overview) {
      state.overview = { ...state.overview, ...overview }
    },
    SET_STATS(state, stats) {
      state.stats = stats
    },
    SET_LOADING(state, loading) {
      state.loading = loading
    },
    SET_ERROR(state, error) {
      state.error = error
    }
  },
  actions: {
    async fetchOverview({ commit }) {
      try {
        commit('SET_LOADING', true)
        commit('SET_ERROR', null)
        const overview = await dashboardAPI.getOverview()
        commit('SET_OVERVIEW', overview)
        return overview
      } catch (error) {
        commit('SET_ERROR', error.message)
        throw error
      } finally {
        commit('SET_LOADING', false)
      }
    },
    async fetchStats({ commit }) {
      try {
        const stats = await dashboardAPI.getDashboardStats()
        commit('SET_STATS', stats)
        return stats
      } catch (error) {
        console.error('Erreur fetchStats:', error)
        throw error
      }
    }
  },
  getters: {
    isLoading: state => state.loading,
    hasError: state => !!state.error,
    criticalAlertsCount: state => state.overview.critical_alerts,
    riskLevel: state => {
      const avg = state.overview.risk_score_avg
      if (avg >= 8) return 'critical'
      if (avg >= 6) return 'high' 
      if (avg >= 4) return 'medium'
      return 'low'
    }
  }
}

const threats = {
  namespaced: true,
  state: {
    liveThreats: [],
    threatLandscape: {},
    loading: false,
    error: null,
    filters: {
      timeRange: '24h',
      riskLevel: 'all',
      source: 'all'
    }
  },
  mutations: {
    SET_LIVE_THREATS(state, threats) {
      state.liveThreats = threats
    },
    SET_THREAT_LANDSCAPE(state, landscape) {
      state.threatLandscape = landscape
    },
    ADD_LIVE_THREAT(state, threat) {
      state.liveThreats.unshift(threat)
      if (state.liveThreats.length > 100) {
        state.liveThreats = state.liveThreats.slice(0, 100)
      }
    },
    SET_FILTERS(state, filters) {
      state.filters = { ...state.filters, ...filters }
    },
    SET_LOADING(state, loading) {
      state.loading = loading
    },
    SET_ERROR(state, error) {
      state.error = error
    }
  },
  actions: {
    async fetchLiveThreats({ commit, state }) {
      try {
        commit('SET_LOADING', true)
        const params = {
          hours: state.filters.timeRange === '24h' ? 24 : 1
        }
        const data = await dashboardAPI.getLiveThreats(params)
        commit('SET_LIVE_THREATS', data.threats || [])
        return data
      } catch (error) {
        commit('SET_ERROR', error.message)
        throw error
      } finally {
        commit('SET_LOADING', false)
      }
    },
    async fetchThreatLandscape({ commit }) {
      try {
        const data = await dashboardAPI.getThreatLandscape()
        commit('SET_THREAT_LANDSCAPE', data)
        return data
      } catch (error) {
        commit('SET_ERROR', error.message)
        throw error
      }
    },
    updateFilters({ commit, dispatch }, filters) {
      commit('SET_FILTERS', filters)
      dispatch('fetchLiveThreats')
    }
  }
}

const alerts = {
  namespaced: true,
  state: {
    alerts: [],
    unacknowledgedCount: 0,
    loading: false,
    error: null
  },
  mutations: {
    SET_ALERTS(state, alerts) {
      state.alerts = alerts
      state.unacknowledgedCount = alerts.filter(a => !a.acknowledged).length
    },
    ADD_ALERT(state, alert) {
      state.alerts.unshift(alert)
      if (!alert.acknowledged) {
        state.unacknowledgedCount++
      }
    },
    ACKNOWLEDGE_ALERT(state, alertId) {
      const alert = state.alerts.find(a => a.id === alertId)
      if (alert && !alert.acknowledged) {
        alert.acknowledged = true
        alert.acknowledged_at = new Date()
        state.unacknowledgedCount--
      }
    },
    SET_LOADING(state, loading) {
      state.loading = loading
    },
    SET_ERROR(state, error) {
      state.error = error
    }
  },
  actions: {
    async fetchAlerts({ commit }, acknowledged = null) {
      try {
        commit('SET_LOADING', true)
        const data = await dashboardAPI.getAlerts(acknowledged)
        commit('SET_ALERTS', data.alerts || [])
        return data
      } catch (error) {
        commit('SET_ERROR', error.message)
        throw error
      } finally {
        commit('SET_LOADING', false)
      }
    },
    async acknowledgeAlert({ commit }, alertId) {
      try {
        await dashboardAPI.acknowledgeAlert(alertId)
        commit('ACKNOWLEDGE_ALERT', alertId)
      } catch (error) {
        commit('SET_ERROR', error.message)
        throw error
      }
    }
  },
  getters: {
    criticalAlerts: state => state.alerts.filter(a => a.level === 'critical'),
    unacknowledgedAlerts: state => state.alerts.filter(a => !a.acknowledged)
  }
}

const mitre = {
  namespaced: true,
  state: {
    overview: {},
    heatmapData: [],
    threatActors: [],
    software: [],
    coverage: {},
    timeline: [],
    loading: false,
    error: null
  },
  mutations: {
    SET_OVERVIEW(state, overview) {
      state.overview = overview
    },
    SET_HEATMAP_DATA(state, data) {
      state.heatmapData = data
    },
    SET_THREAT_ACTORS(state, actors) {
      state.threatActors = actors
    },
    SET_SOFTWARE(state, software) {
      state.software = software
    },
    SET_COVERAGE(state, coverage) {
      state.coverage = coverage
    },
    SET_TIMELINE(state, timeline) {
      state.timeline = timeline
    },
    SET_LOADING(state, loading) {
      state.loading = loading
    },
    SET_ERROR(state, error) {
      state.error = error
    }
  },
  actions: {
    async fetchOverview({ commit }) {
      try {
        commit('SET_LOADING', true)
        const data = await dashboardAPI.getMitreOverview()
        commit('SET_OVERVIEW', data)
        return data
      } catch (error) {
        commit('SET_ERROR', error.message)
        throw error
      } finally {
        commit('SET_LOADING', false)
      }
    },
    async fetchHeatmapData({ commit }, days = 30) {
      try {
        const data = await dashboardAPI.getEnhancedMitreHeatmap(days)
        commit('SET_HEATMAP_DATA', data.heatmap || [])
        return data
      } catch (error) {
        commit('SET_ERROR', error.message)
        throw error
      }
    },
    async fetchAllMitreData({ dispatch }) {
      try {
        const results = await Promise.allSettled([
          dispatch('fetchOverview'),
          dispatch('fetchHeatmapData'),
          dashboardAPI.getMitreThreatActors(),
          dashboardAPI.getMitreSoftware(),
          dashboardAPI.getMitreCoverage(),
          dashboardAPI.getMitreTimeline()
        ])

        // Traiter les résultats
        results.forEach((result, index) => {
          if (result.status === 'fulfilled') {
            switch (index) {
              case 2: // Threat actors
                dispatch('setThreatActors', result.value.threat_actors || [])
                break
              case 3: // Software
                dispatch('setSoftware', result.value.software_list || [])
                break
              case 4: // Coverage
                dispatch('setCoverage', result.value)
                break
              case 5: // Timeline
                dispatch('setTimeline', result.value.timeline || [])
                break
            }
          }
        })

        return results
      } catch (error) {
        console.error('Erreur fetchAllMitreData:', error)
        throw error
      }
    },
    setThreatActors({ commit }, actors) {
      commit('SET_THREAT_ACTORS', actors)
    },
    setSoftware({ commit }, software) {
      commit('SET_SOFTWARE', software)
    },
    setCoverage({ commit }, coverage) {
      commit('SET_COVERAGE', coverage)
    },
    setTimeline({ commit }, timeline) {
      commit('SET_TIMELINE', timeline)
    }
  }
}

// Store principal
export default createStore({
  state: {
    user: {
      id: 'dashboard-user',
      name: 'CTI User',
      role: 'analyst'
    },
    notifications: [],
    websocketConnected: false,
    apiStatus: 'disconnected', // 'disconnected', 'connecting', 'connected', 'error'
    appConfig: {
      refreshInterval: 30000, // 30 secondes
      enableNotifications: true,
      theme: 'light'
    }
  },
  
  mutations: {
    SET_USER(state, user) {
      state.user = { ...state.user, ...user }
    },
    ADD_NOTIFICATION(state, notification) {
      state.notifications.unshift({
        id: Date.now(),
        timestamp: new Date(),
        read: false,
        ...notification
      })
      
      // Limiter à 50 notifications
      if (state.notifications.length > 50) {
        state.notifications = state.notifications.slice(0, 50)
      }
    },
    REMOVE_NOTIFICATION(state, notificationId) {
      const index = state.notifications.findIndex(n => n.id === notificationId)
      if (index > -1) {
        state.notifications.splice(index, 1)
      }
    },
    MARK_NOTIFICATION_READ(state, notificationId) {
      const notification = state.notifications.find(n => n.id === notificationId)
      if (notification) {
        notification.read = true
      }
    },
    MARK_ALL_NOTIFICATIONS_READ(state) {
      state.notifications.forEach(n => n.read = true)
    },
    SET_WEBSOCKET_STATUS(state, connected) {
      state.websocketConnected = connected
    },
    SET_API_STATUS(state, status) {
      state.apiStatus = status
    },
    UPDATE_CONFIG(state, config) {
      state.appConfig = { ...state.appConfig, ...config }
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
    
    showNotification({ commit }, notification) {
      commit('ADD_NOTIFICATION', notification)
    },
    
    dismissNotification({ commit }, notificationId) {
      commit('REMOVE_NOTIFICATION', notificationId)
    }
  },
  
  getters: {
    unreadNotifications: state => state.notifications.filter(n => !n.read),
    unreadCount: (state, getters) => getters.unreadNotifications.length,
    isApiConnected: state => state.apiStatus === 'connected',
    isWebSocketConnected: state => state.websocketConnected,
    systemStatus: state => ({
      api: state.apiStatus,
      websocket: state.websocketConnected,
      overall: state.apiStatus === 'connected' && state.websocketConnected ? 'healthy' : 'degraded'
    })
  },
  
  modules: {
    dashboard,
    threats,
    alerts,
    mitre
  }
})