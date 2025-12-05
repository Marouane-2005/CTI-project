<template>
  <div class="threats-view">
    <div class="container-fluid">
      <h2><i class="fas fa-shield-virus"></i> Menaces Actives</h2>
      
      <div class="row mt-4">
        <div class="col-12">
          <div class="card">
            <div class="card-header d-flex justify-content-between">
              <h5><i class="fas fa-exclamation-triangle"></i> Alertes Récentes</h5>
              <button class="btn btn-sm btn-primary" @click="refreshThreats">
                <i class="fas fa-sync-alt"></i> Actualiser
              </button>
            </div>
            <div class="card-body">
              <div v-if="loading" class="text-center">
                <div class="spinner-border" role="status"></div>
              </div>
              <div v-else-if="threats.length === 0" class="text-muted">
                Aucune menace active
              </div>
              <div v-else class="table-responsive">
                <table class="table table-striped">
                  <thead>
                    <tr>
                      <th>Type</th>
                      <th>Valeur</th>
                      <th>Niveau</th>
                      <th>Source</th>
                      <th>Détecté le</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr v-for="threat in threats" :key="threat.id">
                      <td>
                        <span class="badge bg-secondary">{{ threat.type }}</span>
                      </td>
                      <td>{{ threat.value }}</td>
                      <td>
                        <span :class="getRiskClass(threat.risk_score)">
                          {{ threat.risk_score }}
                        </span>
                      </td>
                      <td>{{ threat.source }}</td>
                      <td>{{ formatDate(threat.timestamp) }}</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import { ref, onMounted } from 'vue'
import { dashboardAPI } from '@/services/api'

export default {
  name: 'Threats',
  setup() {
    const threats = ref([])
    const loading = ref(false)
    
    const refreshThreats = async () => {
      try {
        loading.value = true
        const response = await dashboardAPI.getLiveThreats({ hours: 24 })
        threats.value = response.threats || []
      } catch (error) {
        console.error('Erreur chargement menaces:', error)
        threats.value = []
      } finally {
        loading.value = false
      }
    }
    
    const getRiskClass = (score) => {
      if (score >= 7) return 'badge bg-danger'
      if (score >= 4) return 'badge bg-warning'
      return 'badge bg-success'
    }
    
    const formatDate = (dateString) => {
      return new Date(dateString).toLocaleString('fr-FR')
    }
    
    onMounted(() => {
      refreshThreats()
    })
    
    return {
      threats,
      loading,
      refreshThreats,
      getRiskClass,
      formatDate
    }
  }
}
</script>
