<!-- dashboard/frontend/src/components/AlertPanel.vue -->
<template>
  <div class="alert-panel">
    <!-- En-tête avec compteur -->
    <div class="d-flex justify-content-between align-items-center mb-3">
      <h6 class="mb-0">
        <i class="fas fa-exclamation-triangle me-2"></i>
        Alertes
        <span v-if="alerts.length > 0" class="badge bg-danger ms-2">{{ alerts.length }}</span>
      </h6>
      <button 
        v-if="alerts.length > 0" 
        class="btn btn-sm btn-outline-secondary"
        @click="refreshAlerts"
        :disabled="loading"
      >
        <i class="fas fa-sync-alt" :class="{ 'fa-spin': loading }"></i>
      </button>
    </div>

    <!-- Indicateur de chargement -->
    <div v-if="loading" class="text-center py-3">
      <div class="spinner-border spinner-border-sm text-primary" role="status"></div>
      <span class="ms-2">Chargement des alertes...</span>
    </div>
    
    <!-- Aucune alerte -->
    <div v-else-if="alerts.length === 0" class="text-center py-4 text-muted">
      <i class="fas fa-check-circle fa-2x mb-2 text-success"></i>
      <div>Aucune alerte active</div>
      <small>Toutes les alertes ont été traitées</small>
    </div>
    
    <!-- Liste des alertes -->
    <div v-else class="alerts-list">
      <div 
        v-for="alert in alerts" 
        :key="alert.id || `alert_${alert.timestamp}`"
        :class="getAlertClass(alert.level)"
        class="alert alert-dismissible fade show mb-2 alert-item"
        role="alert"
      >
        <!-- Icône selon le niveau -->
        <div class="d-flex align-items-start">
          <div class="alert-icon me-2">
            <i :class="getAlertIcon(alert.level)"></i>
          </div>
          
          <div class="flex-grow-1">
            <!-- Titre de l'alerte -->
            <div class="alert-title">
              <strong>{{ alert.title || 'Alerte de sécurité' }}</strong>
              <span :class="getLevelBadgeClass(alert.level)" class="badge ms-2">
                {{ getLevelText(alert.level) }}
              </span>
            </div>
            
            <!-- Description -->
            <div class="alert-description mt-1">
              {{ alert.description || alert.message || 'Aucune description disponible' }}
            </div>
            
            <!-- Métadonnées -->
            <div class="alert-meta mt-2">
              <small class="text-muted d-flex flex-wrap gap-3">
                <span v-if="alert.source">
                  <i class="fas fa-source me-1"></i>{{ alert.source }}
                </span>
                <span>
                  <i class="fas fa-clock me-1"></i>{{ formatDate(alert.timestamp) }}
                </span>
                <span v-if="alert.id">
                  <i class="fas fa-hashtag me-1"></i>{{ alert.id }}
                </span>
              </small>
            </div>
          </div>
          
          <!-- Bouton de fermeture -->
          <button 
            type="button" 
            class="btn-close ms-2" 
            @click="acknowledgeAlert(alert)"
            :disabled="alert.acknowledging"
            aria-label="Acquitter l'alerte"
            :title="`Acquitter l'alerte ${alert.id}`"
          ></button>
        </div>
      </div>
    </div>

    <!-- Actions en lot si plusieurs alertes -->
    <div v-if="alerts.length > 1" class="mt-3 text-center">
      <button 
        class="btn btn-sm btn-outline-danger"
        @click="acknowledgeAllAlerts"
        :disabled="loading"
      >
        <i class="fas fa-check-double me-1"></i>
        Acquitter toutes les alertes ({{ alerts.length }})
      </button>
    </div>
  </div>
</template>

<script>
import { ref, onMounted, onUnmounted, watch, computed } from 'vue'
import { dashboardAPI } from '@/services/api'
import { useWebSocket } from '@/services/websocket'

export default {
  name: 'AlertPanel',
  emits: ['alert-acknowledged', 'new-alert', 'alerts-updated'],
  
  setup(props, { emit }) {
    // État réactif
    const loading = ref(true)
    const alerts = ref([])
    const error = ref(null)
    
    // WebSocket
    const { isConnected, liveData, on, off, acknowledgeAlert: wsAcknowledgeAlert } = useWebSocket()
    
    // Méthodes utilitaires pour le style des alertes
    const getAlertClass = (level) => {
      const classes = {
        'critical': 'alert-danger border-danger',
        'high': 'alert-warning border-warning',
        'medium': 'alert-info border-info',
        'low': 'alert-secondary border-secondary'
      }
      return classes[level] || 'alert-secondary'
    }
    
    const getAlertIcon = (level) => {
      const icons = {
        'critical': 'fas fa-exclamation-triangle text-danger',
        'high': 'fas fa-exclamation-circle text-warning', 
        'medium': 'fas fa-info-circle text-info',
        'low': 'fas fa-bell text-secondary'
      }
      return icons[level] || 'fas fa-bell'
    }
    
    const getLevelBadgeClass = (level) => {
      const classes = {
        'critical': 'bg-danger',
        'high': 'bg-warning text-dark',
        'medium': 'bg-info',
        'low': 'bg-secondary'
      }
      return classes[level] || 'bg-secondary'
    }
    
    const getLevelText = (level) => {
      const texts = {
        'critical': 'Critique',
        'high': 'Élevé',
        'medium': 'Moyen',
        'low': 'Faible'
      }
      return texts[level] || level
    }
    
    // Chargement des alertes depuis l'API
    const loadAlerts = async () => {
      try {
        loading.value = true
        error.value = null
        
        console.log('🔄 Chargement des alertes...')
        const response = await dashboardAPI.getAlerts()
        
        console.log('✅ Réponse API alerts:', response)
        
        // Gérer différents formats de réponse
        if (response && response.alerts) {
          alerts.value = Array.isArray(response.alerts) ? response.alerts : []
        } else if (Array.isArray(response)) {
          alerts.value = response
        } else {
          console.warn('Format de réponse inattendu:', response)
          alerts.value = []
        }
        
        console.log(`📊 ${alerts.value.length} alerte(s) chargée(s)`)
        emit('alerts-updated', alerts.value)
        
      } catch (err) {
        console.error('❌ Erreur chargement alertes:', err)
        error.value = err.message
        alerts.value = []
      } finally {
        loading.value = false
      }
    }
    
    // Acquittement d'une alerte
    const acknowledgeAlert = async (alert) => {
      try {
        // Marquer l'alerte comme en cours d'acquittement
        alert.acknowledging = true
        
        console.log('🔄 Acquittement alerte:', alert.id)
        await dashboardAPI.acknowledgeAlert(alert.id, 'dashboard-user')
        
        // Supprimer l'alerte de la liste locale
        const index = alerts.value.findIndex(a => a.id === alert.id)
        if (index > -1) {
          alerts.value.splice(index, 1)
        }
        
        // Notifier via WebSocket si connecté
        if (isConnected.value) {
          wsAcknowledgeAlert(alert.id)
        }
        
        console.log('✅ Alerte acquittée:', alert.id)
        emit('alert-acknowledged', alert.id)
        emit('alerts-updated', alerts.value)
        
      } catch (err) {
        console.error('❌ Erreur acquittement:', err)
        alert.acknowledging = false
        // Optionnel : afficher un message d'erreur à l'utilisateur
      }
    }
    
    // Acquittement de toutes les alertes
    const acknowledgeAllAlerts = async () => {
      try {
        loading.value = true
        
        const promises = alerts.value.map(alert => 
          dashboardAPI.acknowledgeAlert(alert.id, 'dashboard-user')
        )
        
        await Promise.all(promises)
        
        console.log(`✅ Toutes les alertes acquittées (${alerts.value.length})`)
        alerts.value = []
        emit('alerts-updated', [])
        
      } catch (err) {
        console.error('❌ Erreur acquittement en lot:', err)
      } finally {
        loading.value = false
      }
    }
    
    // Actualisation manuelle
    const refreshAlerts = () => {
      loadAlerts()
    }
    
    // Formatage de date
    const formatDate = (dateString) => {
      if (!dateString) return 'Date inconnue'
      
      try {
        const date = new Date(dateString)
        return date.toLocaleString('fr-FR', {
          day: '2-digit',
          month: '2-digit', 
          year: 'numeric',
          hour: '2-digit',
          minute: '2-digit'
        })
      } catch (err) {
        return 'Date invalide'
      }
    }
    
    // Gestion des nouvelles alertes via WebSocket
    const handleNewAlert = (newAlert) => {
      console.log('🆕 Nouvelle alerte WebSocket:', newAlert)
      
      // Vérifier si l'alerte existe déjà
      const exists = alerts.value.some(alert => alert.id === newAlert.id)
      if (!exists) {
        alerts.value.unshift({
          ...newAlert,
          timestamp: newAlert.timestamp || new Date().toISOString()
        })
        
        // Limiter le nombre d'alertes affichées
        if (alerts.value.length > 50) {
          alerts.value = alerts.value.slice(0, 50)
        }
        
        emit('new-alert', newAlert)
        emit('alerts-updated', alerts.value)
      }
    }
    
    // Cycle de vie du composant
    onMounted(async () => {
      console.log('🚀 AlertPanel monté, chargement des alertes...')
      
      // Charger les alertes initiales
      await loadAlerts()
      
      // Écouter les nouvelles alertes via WebSocket
      on('new_alert', handleNewAlert)
      
      // Synchroniser avec les données WebSocket si disponibles
      if (liveData.alerts && liveData.alerts.length > 0) {
        console.log('📡 Synchronisation avec données WebSocket:', liveData.alerts.length)
        liveData.alerts.forEach(handleNewAlert)
      }
    })
    
    onUnmounted(() => {
      // Nettoyer les écouteurs WebSocket
      off('new_alert', handleNewAlert)
    })
    
    // Surveiller les changements de connexion WebSocket
    watch(isConnected, (connected) => {
      if (connected) {
        console.log('🔗 WebSocket connecté, synchronisation des alertes')
        // Recharger les alertes à la reconnexion
        setTimeout(loadAlerts, 1000)
      }
    })
    
    return {
      // État
      loading,
      alerts,
      error,
      isConnected,
      
      // Méthodes
      getAlertClass,
      getAlertIcon,
      getLevelBadgeClass,
      getLevelText,
      acknowledgeAlert,
      acknowledgeAllAlerts,
      refreshAlerts,
      formatDate
    }
  }
}
</script>

<style scoped>
.alert-panel {
  max-height: 600px;
  overflow-y: auto;
}

.alerts-list {
  max-height: 500px;
  overflow-y: auto;
}

.alert-item {
  border-left-width: 4px;
  transition: all 0.3s ease;
  position: relative;
}

.alert-item:hover {
  transform: translateX(2px);
  box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
}

.alert-icon {
  width: 20px;
  text-align: center;
  margin-top: 2px;
}

.alert-title {
  font-size: 0.95rem;
  line-height: 1.3;
}

.alert-description {
  font-size: 0.85rem;
  line-height: 1.4;
  color: #495057;
}

.alert-meta {
  font-size: 0.75rem;
}

.btn-close {
  font-size: 0.75rem;
  margin-top: -2px;
}

/* Animations pour les nouvelles alertes */
@keyframes slideInAlert {
  from {
    opacity: 0;
    transform: translateY(-20px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

.alert-item {
  animation: slideInAlert 0.3s ease-out;
}

/* Responsive */
@media (max-width: 768px) {
  .alert-meta {
    font-size: 0.7rem;
  }
  
  .alert-meta .d-flex {
    flex-direction: column !important;
    gap: 0.25rem !important;
  }
}

/* Style pour les alertes selon leur ancienneté */
.alert-item.old-alert {
  opacity: 0.8;
  border-left-color: #dee2e6 !important;
}

/* Scrollbar personnalisée */
.alerts-list::-webkit-scrollbar {
  width: 4px;
}

.alerts-list::-webkit-scrollbar-track {
  background: #f1f1f1;
  border-radius: 2px;
}

.alerts-list::-webkit-scrollbar-thumb {
  background: #ccc;
  border-radius: 2px;
}

.alerts-list::-webkit-scrollbar-thumb:hover {
  background: #999;
}
</style>