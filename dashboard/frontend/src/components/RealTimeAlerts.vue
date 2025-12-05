<!-- dashboard/frontend/src/components/RealTimeAlerts.vue -->
<template>
  <div class="real-time-alerts">
    <!-- Panel d'alertes en temps réel -->
    <div class="alerts-header">
      <h3>
        <i class="fas fa-shield-alt"></i>
        Détection d'Attaques
        <span class="badge" :class="alertBadgeClass">{{ alerts.length }}</span>
      </h3>
      <div class="alerts-controls">
        <button @click="clearAlerts" class="btn btn-sm btn-outline-secondary">
          Effacer
        </button>
        <button @click="toggleAutoScroll" class="btn btn-sm" 
                :class="{ 'btn-primary': autoScroll, 'btn-outline-primary': !autoScroll }">
          Auto-scroll
        </button>
      </div>
    </div>

    <!-- Liste des alertes -->
    <div class="alerts-container" ref="alertsContainer">
      <div v-for="alert in sortedAlerts" 
           :key="alert.id" 
           :class="['alert-item', `alert-${alert.level}`, { 'alert-new': alert.isNew }]"
           @click="viewAlertDetails(alert)">
        
        <!-- Header de l'alerte -->
        <div class="alert-header">
          <div class="alert-icon">
            <i :class="getAlertIcon(alert.level)"></i>
          </div>
          <div class="alert-title">
            <strong>{{ alert.title }}</strong>
            <span class="alert-time">{{ formatTime(alert.timestamp) }}</span>
          </div>
          <div class="alert-actions">
            <button @click.stop="acknowledgeAlert(alert)" 
                    class="btn btn-xs btn-outline-primary"
                    :disabled="alert.acknowledged">
              {{ alert.acknowledged ? 'Acquitté' : 'Acquitter' }}
            </button>
          </div>
        </div>

        <!-- Contenu de l'alerte -->
        <div class="alert-content">
          <p>{{ alert.description }}</p>
          
          <!-- Indicateurs MITRE si disponibles -->
          <div v-if="alert.mitre_techniques?.length" class="mitre-techniques">
            <small class="text-muted">Techniques MITRE:</small>
            <span v-for="technique in alert.mitre_techniques" 
                  :key="technique" 
                  class="badge badge-technique">
              {{ technique }}
            </span>
          </div>

          <!-- Score de risque -->
          <div v-if="alert.risk_score" class="risk-score">
            <small class="text-muted">Score de risque:</small>
            <div class="progress progress-sm">
              <div class="progress-bar" 
                   :class="getRiskScoreClass(alert.risk_score)"
                   :style="{ width: (alert.risk_score / 10 * 100) + '%' }">
                {{ alert.risk_score }}/10
              </div>
            </div>
          </div>

          <!-- Indicateur source -->
          <div class="alert-source">
            <small class="text-muted">
              Source: {{ alert.source || 'Système' }} | 
              IOC: {{ getMainIOC(alert.indicator) }}
            </small>
          </div>
        </div>
      </div>

      <!-- Message si aucune alerte -->
      <div v-if="alerts.length === 0" class="no-alerts">
        <i class="fas fa-shield-alt text-muted"></i>
        <p class="text-muted">Aucune alerte détectée</p>
      </div>
    </div>

    <!-- Statistiques -->
    <div class="alerts-stats">
      <div class="stat-item">
        <span class="stat-label">Critiques:</span>
        <span class="stat-value critical">{{ criticalCount }}</span>
      </div>
      <div class="stat-item">
        <span class="stat-label">Hautes:</span>
        <span class="stat-value high">{{ highCount }}</span>
      </div>
      <div class="stat-item">
        <span class="stat-label">Moyennes:</span>
        <span class="stat-value medium">{{ mediumCount }}</span>
      </div>
    </div>
  </div>
</template>

<script>
import { ref, computed, onMounted, onUnmounted, nextTick } from 'vue'
import { useWebSocket } from '@/services/websocket'
import { dashboardAPI } from '@/services/api'

export default {
  name: 'RealTimeAlerts',
  setup() {
    const alerts = ref([])
    const autoScroll = ref(true)
    const alertsContainer = ref(null)
    
    // WebSocket connection
    const { connect, disconnect, on, acknowledgeAlert: wsAcknowledgeAlert } = useWebSocket()
    
    // Computed properties
    const sortedAlerts = computed(() => {
      return alerts.value
        .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
        .slice(0, 50) // Limiter à 50 alertes récentes
    })
    
    const criticalCount = computed(() => 
      alerts.value.filter(a => a.level === 'critical').length
    )
    
    const highCount = computed(() => 
      alerts.value.filter(a => a.level === 'high').length
    )
    
    const mediumCount = computed(() => 
      alerts.value.filter(a => a.level === 'medium').length
    )
    
    const alertBadgeClass = computed(() => {
      if (criticalCount.value > 0) return 'badge-danger'
      if (highCount.value > 0) return 'badge-warning' 
      return 'badge-secondary'
    })
    
    // Methods
    const addAlert = (alert) => {
      // Marquer comme nouvelle
      alert.isNew = true
      alerts.value.unshift(alert)
      
      // Retirer le marqueur "nouveau" après 3 secondes
      setTimeout(() => {
        alert.isNew = false
      }, 3000)
      
      // Auto-scroll si activé
      if (autoScroll.value) {
        nextTick(() => {
          if (alertsContainer.value) {
            alertsContainer.value.scrollTop = 0
          }
        })
      }
      
      // Notification sonore pour alertes critiques
      if (alert.level === 'critical') {
        playAlertSound()
      }
    }
    
    const acknowledgeAlert = async (alert) => {
      try {
        await dashboardAPI.acknowledgeAlert(alert.id)
        alert.acknowledged = true
        wsAcknowledgeAlert(alert.id)
        
        console.log(`✅ Alerte ${alert.id} acquittée`)
      } catch (error) {
        console.error('Erreur acquittement alerte:', error)
      }
    }
    
    const viewAlertDetails = (alert) => {
      // Ouvrir modal ou naviguer vers détails
      console.log('Détails alerte:', alert)
      // Ici vous pouvez implémenter une modal détaillée
    }
    
    const clearAlerts = () => {
      alerts.value = []
    }
    
    const toggleAutoScroll = () => {
      autoScroll.value = !autoScroll.value
    }
    
    const formatTime = (timestamp) => {
      return new Date(timestamp).toLocaleTimeString('fr-FR')
    }
    
    const getAlertIcon = (level) => {
      const icons = {
        critical: 'fas fa-exclamation-triangle text-danger',
        high: 'fas fa-exclamation-circle text-warning',
        medium: 'fas fa-info-circle text-info',
        low: 'fas fa-check-circle text-success'
      }
      return icons[level] || icons.medium
    }
    
    const getRiskScoreClass = (score) => {
      if (score >= 8) return 'bg-danger'
      if (score >= 6) return 'bg-warning'
      if (score >= 4) return 'bg-info'
      return 'bg-success'
    }
    
    const getMainIOC = (indicator) => {
      if (!indicator) return 'N/A'
      return indicator.value || indicator.ip || indicator.domain || 'N/A'
    }
    
    const playAlertSound = () => {
      // Son d'alerte pour les alertes critiques
      if (window.Audio) {
        const audio = new Audio('/sounds/alert.mp3')
        audio.play().catch(e => console.log('Cannot play alert sound:', e))
      }
    }
    
    const loadInitialAlerts = async () => {
      try {
        const response = await dashboardAPI.getAlerts()
        alerts.value = response.alerts || []
      } catch (error) {
        console.error('Erreur chargement alertes initiales:', error)
      }
    }
    
    // Lifecycle
    onMounted(async () => {
      await loadInitialAlerts()
      connect()
      
      // Écouter les nouvelles alertes via WebSocket
      on('new_alert', (alertData) => {
        console.log('🚨 Nouvelle alerte reçue:', alertData)
        addAlert(alertData.alert || alertData)
      })
      
      // Écouter les mises à jour de menaces
      on('threat_update', (threatData) => {
        console.log('🎯 Mise à jour menace:', threatData)
        // Optionnel: créer une alerte légère pour les mises à jour de menaces
      })
    })
    
    onUnmounted(() => {
      disconnect()
    })
    
    return {
      alerts,
      sortedAlerts,
      autoScroll,
      alertsContainer,
      criticalCount,
      highCount,
      mediumCount,
      alertBadgeClass,
      acknowledgeAlert,
      viewAlertDetails,
      clearAlerts,
      toggleAutoScroll,
      formatTime,
      getAlertIcon,
      getRiskScoreClass,
      getMainIOC
    }
  }
}
</script>

<style scoped>
.real-time-alerts {
  background: white;
  border-radius: 8px;
  box-shadow: 0 2px 10px rgba(0,0,0,0.1);
  height: 100%;
  display: flex;
  flex-direction: column;
}

.alerts-header {
  padding: 15px 20px;
  border-bottom: 1px solid #eee;
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.alerts-header h3 {
  margin: 0;
  display: flex;
  align-items: center;
  gap: 10px;
}

.badge {
  padding: 4px 8px;
  border-radius: 12px;
  font-size: 0.8em;
  font-weight: bold;
}

.badge-danger { background: #dc3545; color: white; }
.badge-warning { background: #ffc107; color: black; }
.badge-secondary { background: #6c757d; color: white; }

.alerts-controls {
  display: flex;
  gap: 10px;
}

.alerts-container {
  flex: 1;
  overflow-y: auto;
  padding: 0 20px;
  max-height: 500px;
}

.alert-item {
  padding: 15px;
  margin: 10px 0;
  border-radius: 6px;
  border-left: 4px solid;
  cursor: pointer;
  transition: all 0.3s ease;
  background: #f8f9fa;
}

.alert-item:hover {
  background: #e9ecef;
  transform: translateX(5px);
}

.alert-new {
  animation: pulse 1s ease-in-out;
  box-shadow: 0 0 10px rgba(0,123,255,0.3);
}

@keyframes pulse {
  0% { box-shadow: 0 0 0 0 rgba(0,123,255,0.7); }
  70% { box-shadow: 0 0 0 10px rgba(0,123,255,0); }
  100% { box-shadow: 0 0 0 0 rgba(0,123,255,0); }
}

.alert-critical { border-left-color: #dc3545; }
.alert-high { border-left-color: #ffc107; }
.alert-medium { border-left-color: #17a2b8; }
.alert-low { border-left-color: #28a745; }

.alert-header {
  display: flex;
  align-items: flex-start;
  gap: 15px;
  margin-bottom: 10px;
}

.alert-icon {
  font-size: 1.2em;
  margin-top: 2px;
}

.alert-title {
  flex: 1;
}

.alert-time {
  font-size: 0.8em;
  color: #6c757d;
  margin-left: 10px;
}

.alert-content p {
  margin: 5px 0;
  color: #495057;
}

.mitre-techniques {
  margin: 8px 0;
}

.badge-technique {
  background: #007bff;
  color: white;
  padding: 2px 6px;
  margin: 0 3px;
  border-radius: 3px;
  font-size: 0.7em;
}

.risk-score {
  margin: 8px 0;
}

.progress {
  height: 6px;
  margin: 4px 0;
}

.progress-sm {
  height: 4px;
}

.alert-source {
  font-size: 0.8em;
  margin-top: 8px;
  padding-top: 8px;
  border-top: 1px solid #dee2e6;
}

.no-alerts {
  text-align: center;
  padding: 40px 20px;
  color: #6c757d;
}

.no-alerts i {
  font-size: 3em;
  margin-bottom: 10px;
}

.alerts-stats {
  padding: 10px 20px;
  border-top: 1px solid #eee;
  display: flex;
  justify-content: space-around;
  background: #f8f9fa;
}

.stat-item {
  text-align: center;
}

.stat-label {
  font-size: 0.8em;
  color: #6c757d;
}

.stat-value {
  font-weight: bold;
  margin-left: 5px;
}

.stat-value.critical { color: #dc3545; }
.stat-value.high { color: #ffc107; }
.stat-value.medium { color: #17a2b8; }

.btn-xs {
  padding: 2px 6px;
  font-size: 0.7em;
}
</style>