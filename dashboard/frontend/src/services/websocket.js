import { ref, reactive } from 'vue'
import { io } from 'socket.io-client'

const WS_URL = process.env.VUE_APP_WS_URL || 'http://localhost:5001'

export function useWebSocket() {
  const socket = ref(null)
  const isConnected = ref(false)
  const connectionAttempts = ref(0)
  const maxReconnectAttempts = 5

  // État réactif pour les données temps réel
  const liveData = reactive({
    threats: [],
    alerts: [],
    notifications: [],
    stats: {},
    mitreUpdates: [],
    iocUpdates: []
  })

  // Map des callbacks pour les événements
  const eventCallbacks = new Map()

  const connect = () => {
    if (socket.value && socket.value.connected) {
      console.log('WebSocket déjà connecté')
      return
    }

    console.log('🔌 Connexion WebSocket à', WS_URL)

    socket.value = io(WS_URL, {
      transports: ['polling', 'websocket'],
      timeout: 20000,
      reconnection: true,
      reconnectionAttempts: 3,
      reconnectionDelay: 2000,
      autoConnect: true
    })
    
    socket.value.on('connect_error', (error) => {
    console.warn('⚠️ WebSocket: Tentative de connexion en mode dégradé')
    isConnected.value = false
    
    // Fallback : Polling HTTP si WebSocket échoue
    if (connectionAttempts.value < 3) {
      setupPollingFallback()
    }
  })
    // Événements de connexion
    socket.value.on('connect', () => {
      isConnected.value = true
      connectionAttempts.value = 0
      console.log('✅ WebSocket connecté')
      socket.value.emit('subscribe', {
        channels: ['threats', 'alerts', 'iocs', 'mitre', 'stats']
      })

    socket.value.on('connect_error', (error) => {
    console.warn('⚠️ WebSocket connexion échouée, mode dégradé activé')
    isConnected.value = false
    // Ne pas bloquer l'application
  })
      
      // S'abonner aux canaux
      socket.value.emit('subscribe', {
        channels: ['threats', 'alerts', 'iocs', 'mitre', 'stats']
      })

      // Rejoindre la room du dashboard
      socket.value.emit('join_room', 'dashboard')
    })

    socket.value.on('disconnect', (reason) => {
      isConnected.value = false
      console.log('❌ WebSocket déconnecté:', reason)
    })

    socket.value.on('connect_error', (error) => {
      connectionAttempts.value++
      console.error('🔥 Erreur WebSocket:', error)
      
      if (connectionAttempts.value >= maxReconnectAttempts) {
        console.error('❌ Nombre maximum de tentatives de reconnexion atteint')
      }
    })

    socket.value.on('reconnect', (attemptNumber) => {
      console.log(`🔄 Reconnexion réussie (tentative ${attemptNumber})`)
      isConnected.value = true
      connectionAttempts.value = 0
    })
  
  const setupPollingFallback = () => {
  console.log('📡 Activation du fallback HTTP polling')
  
  const pollInterval = setInterval(async () => {
    if (isConnected.value) {
      clearInterval(pollInterval)
      return
    }
    
    try {
      const response = await fetch(`${WS_URL}/api/dashboard/overview`)
      if (response.ok) {
        const data = await response.json()
        // Simuler une mise à jour WebSocket
        triggerCallback('stats_update', data)
      }
    } catch (error) {
      console.warn('Fallback polling failed:', error)
    }
  }, 5000)
}
  
    // Événements métier
    setupBusinessEventListeners()
  }

  const setupBusinessEventListeners = () => {
    if (!socket.value) return

    // Nouvelles menaces
    socket.value.on('threat_update', (data) => {
      console.log('🎯 Nouvelle menace:', data)
      liveData.threats.unshift({
        ...data,
        id: `threat_${Date.now()}`,
        timestamp: new Date()
      })
      
      // Limiter à 100 éléments
      if (liveData.threats.length > 100) {
        liveData.threats = liveData.threats.slice(0, 100)
      }
      
      triggerCallback('threat_update', data)
    })

    // Nouvelles alertes
    socket.value.on('new_alert', (alert) => {
      console.log('🚨 Nouvelle alerte:', alert)
      liveData.alerts.unshift({
        ...alert,
        id: alert.id || `alert_${Date.now()}`,
        timestamp: alert.timestamp || new Date()
      })
      
      // Limiter à 50 alertes
      if (liveData.alerts.length > 50) {
        liveData.alerts = liveData.alerts.slice(0, 50)
      }
      
      triggerCallback('new_alert', alert)
    })

    // Mises à jour IOCs
    socket.value.on('ioc_update', (ioc) => {
      console.log('🔍 Mise à jour IOC:', ioc)
      liveData.iocUpdates.unshift({
        ...ioc,
        id: ioc.id || `ioc_${Date.now()}`,
        timestamp: new Date()
      })
      
      if (liveData.iocUpdates.length > 100) {
        liveData.iocUpdates = liveData.iocUpdates.slice(0, 100)
      }
      
      triggerCallback('ioc_update', ioc)
    })

    // Mises à jour statistiques
    socket.value.on('stats_update', (stats) => {
      console.log('📊 Mise à jour stats:', stats)
      Object.assign(liveData.stats, stats)
      triggerCallback('stats_update', stats)
    })

    // Notifications système
    socket.value.on('system_notification', (notification) => {
      console.log('📢 Notification système:', notification)
      liveData.notifications.unshift({
        ...notification,
        id: `notif_${Date.now()}`,
        timestamp: new Date(),
        read: false
      })
      
      // Limiter à 20 notifications
      if (liveData.notifications.length > 20) {
        liveData.notifications = liveData.notifications.slice(0, 20)
      }
      
      triggerCallback('system_notification', notification)
    })

    // Mises à jour MITRE
    socket.value.on('mitre_update', (data) => {
      console.log('⚔️ Mise à jour MITRE:', data)
      liveData.mitreUpdates.unshift({
        ...data,
        id: `mitre_${Date.now()}`,
        timestamp: new Date()
      })
      
      if (liveData.mitreUpdates.length > 50) {
        liveData.mitreUpdates = liveData.mitreUpdates.slice(0, 50)
      }
      
      triggerCallback('mitre_update', data)
    })
  }

  const disconnect = () => {
    if (socket.value) {
      socket.value.disconnect()
      socket.value = null
      isConnected.value = false
      console.log('🔌 WebSocket déconnecté manuellement')
    }
  }

  // Système de callbacks personnalisés
  const on = (event, callback) => {
    if (!eventCallbacks.has(event)) {
      eventCallbacks.set(event, [])
    }
    eventCallbacks.get(event).push(callback)
  }

  const off = (event, callback) => {
    if (eventCallbacks.has(event)) {
      const callbacks = eventCallbacks.get(event)
      const index = callbacks.indexOf(callback)
      if (index > -1) {
        callbacks.splice(index, 1)
      }
    }
  }

  const triggerCallback = (event, data) => {
    if (eventCallbacks.has(event)) {
      eventCallbacks.get(event).forEach(callback => {
        try {
          callback(data)
        } catch (error) {
          console.error(`Erreur dans callback ${event}:`, error)
        }
      })
    }
  }

  // Méthodes pour envoyer des données
  const emit = (event, data) => {
    if (socket.value && socket.value.connected) {
      socket.value.emit(event, data)
    } else {
      console.warn('WebSocket non connecté, impossible d\'envoyer:', event)
    }
  }

  // Méthodes utilitaires
  const acknowledgeAlert = (alertId) => {
    emit('acknowledge_alert', { alert_id: alertId, user_id: 'dashboard-user' })
  }

  const markNotificationAsRead = (notificationId) => {
    const notification = liveData.notifications.find(n => n.id === notificationId)
    if (notification) {
      notification.read = true
    }
  }

  const clearNotifications = () => {
    liveData.notifications.splice(0)
  }

  const getConnectionStatus = () => ({
    connected: isConnected.value,
    attempts: connectionAttempts.value,
    maxAttempts: maxReconnectAttempts
  })

  // Auto-reconnection avec backoff exponentiel
  const forceReconnect = () => {
    if (socket.value) {
      socket.value.disconnect()
    }
    
    setTimeout(() => {
      connect()
    }, 1000)
  }

  return {
    socket,
    isConnected,
    liveData,
    connect,
    disconnect,
    on,
    off,
    emit,
    acknowledgeAlert,
    markNotificationAsRead,
    clearNotifications,
    getConnectionStatus,
    forceReconnect
  }
}