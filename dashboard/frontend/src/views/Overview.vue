<template>
  <div class="dashboard-overview">
    <!-- Header avec métriques principales -->
    <div class="metrics-grid">
      <div class="metric-card critical">
        <h3>Alertes Critiques</h3>
        <div class="metric-value">{{ overview.critical_alerts }}</div>
      </div>
      <div class="metric-card">
        <h3>IOCs Aujourd'hui</h3>
        <div class="metric-value">{{ overview.total_iocs_today }}</div>
      </div>
      <div class="metric-card">
        <h3>Menaces Actives</h3>
        <div class="metric-value">{{ overview.active_threats }}</div>
      </div>
      <div class="metric-card">
        <h3>Score Risque Moyen</h3>
        <div class="metric-value">{{ overview.risk_score_avg.toFixed(1) }}</div>
      </div>
    </div>

    <!-- Grille principale à 3 colonnes -->
    <div class="dashboard-grid-3col">
      <!-- Colonne 1 -->
      <div class="dashboard-column">
        <div class="dashboard-card">
          <h3>Carte des Menaces</h3>
          <ThreatMap :threat-data="overview.geographical_threats" />
        </div>
        
        <div class="dashboard-card">
          <h3>Alertes</h3>
          <AlertPanel 
            @alert-acknowledged="onAlertAcknowledged"
            @new-alert="onNewAlert"
            @alerts-updated="onAlertsUpdated"
          />
        </div>
      </div>
      
      <!-- Colonne 2 -->
      <div class="dashboard-column">
        <div class="dashboard-card">
          <h3>IOCs Récents</h3>
          <IOCTable :iocs="overview.recent_iocs" />
        </div>
        
        <div class="dashboard-card">
          <h3>Métriques Temporelles</h3>
          <MetricsChart 
            :alerts="currentAlerts" 
            :real-time-enabled="true"
            @metrics-updated="onMetricsUpdated"
          />
        </div>
      </div>
      
      <!-- Colonne 3 -->
      <div class="dashboard-column">
        <div class="dashboard-card full-height">
          <h3>MITRE ATT&CK Heatmap</h3>
          <MitreHeatmap :techniques="mitreData" />
        </div>
      </div>
    </div>

    <!-- Debug Panel - À retirer en production -->
    <div v-if="showDebug" class="debug-panel mt-4">
      <div class="card">
        <div class="card-header d-flex justify-content-between">
          <h6>Debug - État des alertes</h6>
          <div>
            <button class="btn btn-sm btn-outline-primary me-2" @click="testAlertsAPI">
              Test API Alertes
            </button>
            <button class="btn btn-sm btn-outline-secondary" @click="showDebug = false">
              Fermer
            </button>
          </div>
        </div>
        <div class="card-body">
          <div class="row">
            <div class="col-md-6">
              <h6>Réponse API brute :</h6>
              <pre class="bg-light p-2 small">{{ JSON.stringify(debugApiResponse, null, 2) }}</pre>
            </div>
            <div class="col-md-6">
              <h6>Alertes actuelles ({{ currentAlerts.length }}) :</h6>
              <pre class="bg-light p-2 small">{{ JSON.stringify(currentAlerts, null, 2) }}</pre>
            </div>
          </div>
          <div class="mt-3">
            <h6>État WebSocket :</h6>
            <div class="d-flex gap-3">
              <span class="badge" :class="wsConnected ? 'bg-success' : 'bg-danger'">
                {{ wsConnected ? 'Connecté' : 'Déconnecté' }}
              </span>
              <span class="badge bg-info">Alertes live: {{ liveAlertsCount }}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import { ref, reactive, onMounted, onUnmounted, computed } from 'vue'
import ThreatMap from '@/components/ThreatMap.vue'
import IOCTable from '@/components/IOCTable.vue'
import AlertPanel from '@/components/AlertPanel.vue'
import MetricsChart from '@/components/MetricsChart.vue'
import MitreHeatmap from '@/components/MitreHeatmap.vue'
import { useWebSocket } from '@/services/websocket'
import { dashboardAPI } from '@/services/api'

export default {
  name: 'Overview',
  components: {
    ThreatMap,
    IOCTable,
    AlertPanel,
    MetricsChart,
    MitreHeatmap
  },
  setup() {
    const overview = reactive({
      total_iocs_today: 28,
      active_threats: 25,
      critical_alerts: 0,
      risk_score_avg: 7.8,
      recent_iocs: [],
      geographical_threats: {},
      last_updated: null
    })
    
    const currentAlerts = ref([])
    const mitreData = ref([])
    
    // Debug
    const showDebug = ref(process.env.NODE_ENV === 'development')
    const debugApiResponse = ref(null)
    
    // WebSocket pour les mises à jour temps réel
    const { socket, connect, disconnect, isConnected, liveData } = useWebSocket()
    
    // Computed pour l'état WebSocket
    const wsConnected = computed(() => isConnected.value)
    const liveAlertsCount = computed(() => liveData.alerts?.length || 0)
    
    // Chargement des données du dashboard
    const loadDashboardData = async () => {
      try {
        console.log('🔄 Chargement des données dashboard...')
        
        const [overviewData, alertsResponse, mitreHeatmap] = await Promise.all([
          dashboardAPI.getOverview(),
          dashboardAPI.getAlerts(),
          dashboardAPI.getMitreHeatmap()
        ])
        
        // Mise à jour de l'overview
        Object.assign(overview, overviewData)
        
        // CORRECTION PRINCIPALE : Extraire correctement les alertes
        console.log('📋 Réponse alertes reçue:', alertsResponse)
        debugApiResponse.value = alertsResponse
        
        if (alertsResponse && alertsResponse.alerts) {
          currentAlerts.value = Array.isArray(alertsResponse.alerts) ? alertsResponse.alerts : []
          console.log(`✅ ${currentAlerts.value.length} alerte(s) extraite(s)`)
        } else if (Array.isArray(alertsResponse)) {
          currentAlerts.value = alertsResponse
          console.log(`✅ ${currentAlerts.value.length} alerte(s) directes`)
        } else {
          console.warn('⚠️ Format de réponse alertes inattendu:', alertsResponse)
          currentAlerts.value = []
        }
        
        // ✅ AJOUT: Mettre à jour le compteur d'alertes critiques basé sur les alertes réelles
        overview.critical_alerts = currentAlerts.value.filter(alert => alert.level === 'critical').length
        
        // Mise à jour des données MITRE
        if (mitreHeatmap && mitreHeatmap.heatmap) {
          mitreData.value = mitreHeatmap.heatmap
        } else if (Array.isArray(mitreHeatmap)) {
          mitreData.value = mitreHeatmap
        }
        
        console.log('✅ Données dashboard chargées avec succès')
        console.log(`📊 ${currentAlerts.value.length} alertes disponibles pour MetricsChart`)
        
      } catch (error) {
        console.error('❌ Erreur lors du chargement des données:', error)
        debugApiResponse.value = { error: error.message }
      }
    }
    
    // Test spécifique de l'API des alertes
    const testAlertsAPI = async () => {
      try {
        console.log('🧪 Test API alertes...')
        const response = await dashboardAPI.getAlerts()
        console.log('🔍 Réponse complète:', response)
        debugApiResponse.value = response
        
        // Afficher dans la console pour debug
        if (response.alerts) {
          console.table(response.alerts)
        }
      } catch (error) {
        console.error('❌ Erreur test API alertes:', error)
        debugApiResponse.value = { error: error.message }
      }
    }
    
    // Gestionnaires d'événements pour AlertPanel
    const onAlertAcknowledged = (alertId) => {
      console.log('✅ Alerte acquittée:', alertId)
      
      // Supprimer de la liste locale si elle y est
      const index = currentAlerts.value.findIndex(alert => alert.id === alertId)
      if (index > -1) {
        const acknowledgedAlert = currentAlerts.value[index]
        currentAlerts.value.splice(index, 1)
        
        // Mettre à jour le compteur d'alertes critiques
        if (acknowledgedAlert && acknowledgedAlert.level === 'critical') {
          overview.critical_alerts = Math.max(0, overview.critical_alerts - 1)
        }
        
        console.log(`📊 Alerte supprimée, ${currentAlerts.value.length} restantes`)
      }
    }
    
    const onNewAlert = (newAlert) => {
      console.log('🆕 Nouvelle alerte reçue:', newAlert)
      
      // Vérifier si l'alerte n'existe pas déjà
      const exists = currentAlerts.value.some(alert => alert.id === newAlert.id)
      if (!exists) {
        currentAlerts.value.unshift(newAlert)
        
        // Mettre à jour les métriques
        if (newAlert.level === 'critical') {
          overview.critical_alerts++
        }
        
        // Limiter le nombre d'alertes
        if (currentAlerts.value.length > 50) {
          currentAlerts.value = currentAlerts.value.slice(0, 50)
        }
        
        console.log(`📊 Nouvelle alerte ajoutée, ${currentAlerts.value.length} au total`)
      }
    }
    
    const onAlertsUpdated = (updatedAlerts) => {
      console.log('🔄 Alertes mises à jour:', updatedAlerts.length)
      currentAlerts.value = updatedAlerts
      
      // Recalculer les alertes critiques
      overview.critical_alerts = updatedAlerts.filter(alert => alert.level === 'critical').length
      
      console.log(`📊 ${updatedAlerts.length} alertes mises à jour`)
    }
    
    // ✅ NOUVEAU: Gestionnaire pour les événements du MetricsChart
    const onMetricsUpdated = (metricsInfo) => {
      console.log('📈 Métriques mises à jour:', metricsInfo)
      
      // Optionnel: mettre à jour overview.total_iocs_today basé sur les métriques
      if (metricsInfo.metric === 'iocs' && metricsInfo.totalValue) {
        overview.total_iocs_today = Math.max(overview.total_iocs_today, metricsInfo.totalValue)
      }
    }
    
    // Cycle de vie du composant
    onMounted(async () => {
      console.log('🚀 Overview monté, initialisation...')
      
      // Charger les données initiales
      await loadDashboardData()
      
      // Connexion WebSocket pour les mises à jour temps réel
      connect()
      
      // Écouter les événements WebSocket
      if (socket.value) {
        socket.value.on('threat_update', (data) => {
          console.log('🎯 Mise à jour menace:', data)
          if (data.type === 'new_indicator') {
            overview.total_iocs_today++
            overview.recent_iocs.unshift(data.data)
            overview.recent_iocs = overview.recent_iocs.slice(0, 10)
          }
        })
        
        socket.value.on('stats_update', (stats) => {
          console.log('📊 Mise à jour stats:', stats)
          Object.assign(overview, stats)
        })
        
        // ✅ AJOUT: Écouter les nouvelles alertes via WebSocket
        socket.value.on('new_alert', (alertData) => {
          console.log('🚨 Nouvelle alerte WebSocket:', alertData)
          onNewAlert(alertData)
        })
      }
      
      // Actualisation périodique (toutes les 30 secondes)
      const interval = setInterval(() => {
        if (!document.hidden) { // Seulement si la page est visible
          loadDashboardData()
        }
      }, 30000)
      
      // Nettoyer l'intervalle à la destruction
      onUnmounted(() => {
        clearInterval(interval)
      })
    })
    
    onUnmounted(() => {
      disconnect()
    })
    
    return {
      // État
      overview,
      currentAlerts,
      mitreData,
      
      // Debug
      showDebug,
      debugApiResponse,
      wsConnected,
      liveAlertsCount,
      
      // Méthodes
      onAlertAcknowledged,
      onNewAlert,
      onAlertsUpdated,
      onMetricsUpdated, // ✅ NOUVEAU
      testAlertsAPI
    }
  }
}
</script>

<style scoped>
.dashboard-overview {
  padding: 20px;
}

.metrics-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 15px;
  margin-bottom: 20px;
}

.metric-card {
  background: white;
  border-radius: 6px;
  padding: 12px 15px;
  box-shadow: 0 2px 8px rgba(0,0,0,0.08);
  text-align: center;
  transition: transform 0.2s ease;
}

.metric-card:hover {
  transform: translateY(-1px);
}

.metric-card.critical {
  border-left: 3px solid #ff4757;
}

.metric-card h3 {
  font-size: 0.85rem;
  font-weight: 600;
  color: #666;
  margin: 0 0 8px 0;
}

.metric-value {
  font-size: 1.8rem;
  font-weight: bold;
  color: #2f3542;
  margin: 0;
}

/* Nouvelle grille à 3 colonnes */
.dashboard-grid-3col {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 20px;
  align-items: start;
}

.dashboard-column {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.dashboard-card {
  background: white;
  border-radius: 8px;
  padding: 20px;
  box-shadow: 0 2px 10px rgba(0,0,0,0.1);
  transition: transform 0.2s ease;
}

.dashboard-card:hover {
  transform: translateY(-1px);
}

.dashboard-card.full-height {
  height: calc(100vh - 400px);
  min-height: 500px;
}

.dashboard-card h3 {
  margin: 0 0 20px 0;
  color: #2f3542;
  border-bottom: 2px solid #eee;
  padding-bottom: 10px;
  font-size: 1.1rem;
}

/* Debug Panel */
.debug-panel {
  border: 2px dashed #ffc107;
  border-radius: 8px;
  background: rgba(255, 193, 7, 0.1);
}

.debug-panel pre {
  max-height: 200px;
  overflow-y: auto;
  font-size: 0.8rem;
}

/* Responsive */
@media (max-width: 1200px) {
  .dashboard-grid-3col {
    grid-template-columns: repeat(2, 1fr);
  }
  
  .metrics-grid {
    grid-template-columns: repeat(2, 1fr);
  }
}

@media (max-width: 768px) {
  .dashboard-overview {
    padding: 15px;
  }
  
  .dashboard-grid-3col {
    grid-template-columns: 1fr;
    gap: 15px;
  }
  
  .metrics-grid {
    grid-template-columns: repeat(2, 1fr);
    gap: 10px;
  }
  
  .metric-card {
    padding: 10px;
  }
  
  .metric-card h3 {
    font-size: 0.75rem;
  }
  
  .metric-value {
    font-size: 1.5rem;
  }
  
  .dashboard-card.full-height {
    height: auto;
    min-height: 300px;
  }
}

@media (max-width: 576px) {
  .metrics-grid {
    grid-template-columns: 1fr;
    gap: 8px;
  }
  
  .metric-card {
    padding: 8px 12px;
  }
  
  .metric-card h3 {
    font-size: 0.7rem;
  }
  
  .metric-value {
    font-size: 1.3rem;
  }
  
  .dashboard-card {
    padding: 15px;
  }
}
</style>