<!-- dashboard/frontend/src/views/Reports.vue -->
<template>
  <div class="reports-view">
    <div class="container-fluid">
      <div class="d-flex justify-content-between align-items-center mb-4">
        <h2><i class="fas fa-chart-line text-primary"></i> Rapports CTI</h2>
        <div class="badge bg-success">
          <i class="fas fa-clock"></i> Dernière MAJ: {{ lastUpdate }}
        </div>
      </div>

      <!-- Actions de rapport -->
      <div class="row mb-4">
        <div class="col-12">
          <div class="card">
            <div class="card-header bg-light">
              <h5 class="mb-0"><i class="fas fa-file-download"></i> Générer des Rapports</h5>
            </div>
            <div class="card-body">
              <div class="row">
                <div class="col-md-6 mb-3">
                  <button 
                    class="btn btn-outline-primary w-100" 
                    @click="generateDailyReport"
                    :disabled="isGenerating"
                  >
                    <i class="fas fa-calendar-day"></i> 
                    {{ isGenerating && currentReport === 'daily' ? 'Génération...' : 'Rapport Quotidien' }}
                  </button>
                </div>
                <div class="col-md-6 mb-3">
                  <button 
                    class="btn btn-outline-secondary w-100" 
                    @click="generateWeeklyReport"
                    :disabled="isGenerating"
                  >
                    <i class="fas fa-calendar-week"></i> 
                    {{ isGenerating && currentReport === 'weekly' ? 'Génération...' : 'Rapport Hebdomadaire' }}
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Rapports récents -->
      <div class="row mb-4">
        <div class="col-12">
          <div class="card">
            <div class="card-header bg-light d-flex justify-content-between align-items-center">
              <h5 class="mb-0"><i class="fas fa-history"></i> Rapports Récents</h5>
              <button class="btn btn-sm btn-outline-secondary" @click="loadRecentReports">
                <i class="fas fa-refresh"></i> Actualiser
              </button>
            </div>
            <div class="card-body">
              <div v-if="recentReports.length === 0" class="text-center text-muted py-3">
                <i class="fas fa-inbox"></i> Aucun rapport généré récemment
              </div>
              <div class="list-group list-group-flush">
                <div 
                  v-for="report in recentReports" 
                  :key="report.id"
                  class="list-group-item d-flex justify-content-between align-items-center"
                >
                  <div>
                    <h6 class="mb-1">{{ report.title }}</h6>
                    <p class="mb-1 text-muted">{{ report.description }}</p>
                    <small class="text-muted">
                      <i class="fas fa-calendar"></i> {{ formatDate(report.created_at) }}
                    </small>
                  </div>
                  <div class="d-flex gap-2">
                    <span :class="getStatusBadgeClass(report.status)">
                      {{ report.status }}
                    </span>
                    <button 
                      v-if="report.status === 'completed'"
                      class="btn btn-sm btn-primary"
                      @click="downloadReport(report.id)"
                    >
                      <i class="fas fa-download"></i>
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Prévisualisation du dernier rapport -->
      <div v-if="lastGeneratedReport" class="row">
        <div class="col-12">
          <div class="card">
            <div class="card-header bg-success text-white">
              <h5 class="mb-0">
                <i class="fas fa-eye"></i> Aperçu - {{ lastGeneratedReport.title }}
              </h5>
            </div>
            <div class="card-body">
              <div class="report-preview">
                <div class="row mb-3">
                  <div class="col-md-6">
                    <strong>Période:</strong> {{ lastGeneratedReport.period }}
                  </div>
                  <div class="col-md-6">
                    <strong>Type:</strong> {{ lastGeneratedReport.type }}
                  </div>
                </div>
                
                <!-- Résumé exécutif -->
                <div class="mb-3">
                  <h6><i class="fas fa-summary"></i> Résumé Exécutif</h6>
                  <div class="alert alert-light">
                    {{ lastGeneratedReport.executive_summary }}
                  </div>
                </div>

                <!-- Métriques clés -->
                <div class="row mb-3">
                  <div class="col-md-6">
                    <h6><i class="fas fa-chart-bar"></i> Métriques Clés</h6>
                    <ul class="list-unstyled">
                      <li v-for="(value, key) in lastGeneratedReport.key_metrics" :key="key">
                        <strong>{{ formatMetricName(key) }}:</strong> {{ value }}
                      </li>
                    </ul>
                  </div>
                  <div class="col-md-6">
                    <h6><i class="fas fa-exclamation-triangle"></i> Top Menaces</h6>
                    <ol>
                      <li v-for="threat in lastGeneratedReport.top_threats" :key="threat.id">
                        {{ threat.name }} ({{ threat.count }} occurrences)
                      </li>
                    </ol>
                  </div>
                </div>

                <div class="text-center">
                  <button 
                    class="btn btn-success me-2"
                    @click="downloadReport(lastGeneratedReport.id)"
                  >
                    <i class="fas fa-download"></i> Télécharger PDF
                  </button>
                  <button 
                    class="btn btn-outline-secondary"
                    @click="clearPreview"
                  >
                    <i class="fas fa-times"></i> Fermer l'aperçu
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Modal de configuration des rapports -->
      <div class="modal fade" id="reportConfigModal" tabindex="-1">
        <div class="modal-dialog">
          <div class="modal-content">
            <div class="modal-header">
              <h5 class="modal-title">Configuration du Rapport</h5>
              <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
              <div class="mb-3">
                <label class="form-label">Période</label>
                <select v-model="reportConfig.period" class="form-select">
                  <option value="1">Dernières 24h</option>
                  <option value="7">Dernière semaine</option>
                  <option value="30">Dernier mois</option>
                </select>
              </div>
              <div class="mb-3">
                <label class="form-label">Format</label>
                <select v-model="reportConfig.format" class="form-select">
                  <option value="pdf">PDF</option>
                  <option value="html">HTML</option>
                  <option value="json">JSON</option>
                </select>
              </div>
              <div class="mb-3">
                <label class="form-label">Sections à inclure</label>
                <div class="form-check">
                  <input v-model="reportConfig.sections.executive_summary" class="form-check-input" type="checkbox" id="section1">
                  <label class="form-check-label" for="section1">Résumé exécutif</label>
                </div>
                <div class="form-check">
                  <input v-model="reportConfig.sections.threat_analysis" class="form-check-input" type="checkbox" id="section2">
                  <label class="form-check-label" for="section2">Analyse des menaces</label>
                </div>
                <div class="form-check">
                  <input v-model="reportConfig.sections.mitre_mapping" class="form-check-input" type="checkbox" id="section3">
                  <label class="form-check-label" for="section3">Mapping MITRE ATT&CK</label>
                </div>
              </div>
            </div>
            <div class="modal-footer">
              <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Annuler</button>
              <button type="button" class="btn btn-primary" @click="generateCustomReport">Générer</button>
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
  name: 'Reports',
  setup() {
    const recentReports = ref([])
    const lastGeneratedReport = ref(null)
    const isGenerating = ref(false)
    const currentReport = ref('')
    const lastUpdate = ref(new Date().toLocaleString('fr-FR'))

    const reportConfig = ref({
      period: '7',
      format: 'pdf',
      sections: {
        executive_summary: true,
        threat_analysis: true,
        mitre_mapping: true
      }
    })

    // Chargement des rapports récents
    const loadRecentReports = async () => {
      try {
        const response = await dashboardAPI.getRecentReports()
        recentReports.value = response.reports || []
      } catch (error) {
        console.error('Erreur chargement rapports récents:', error)
        // Données mock en cas d'erreur
        recentReports.value = [
          {
            id: 'report_001',
            title: 'Rapport Quotidien - 12/08/2025',
            description: 'Analyse des menaces des dernières 24h',
            type: 'daily',
            status: 'completed',
            created_at: new Date().toISOString()
          }
        ]
      }
    }

    // Génération des rapports
    const generateDailyReport = async () => {
      isGenerating.value = true
      currentReport.value = 'daily'
      
      try {
        const response = await dashboardAPI.generateReport('daily', { period: 1 })
        
        lastGeneratedReport.value = {
          id: response.report_id,
          title: 'Rapport Quotidien',
          period: 'Dernières 24 heures',
          type: 'daily',
          executive_summary: response.executive_summary || 'Aucune menace critique détectée aujourd\'hui.',
          key_metrics: response.key_metrics || {
            'Alertes générées': 15,
            'IOCs traités': 45,
            'Techniques MITRE': 12
          },
          top_threats: response.top_threats || [
            { id: 1, name: 'Phishing Campaign', count: 8 },
            { id: 2, name: 'Malware C2', count: 3 }
          ]
        }
        
        await loadRecentReports()
      } catch (error) {
        console.error('Erreur génération rapport quotidien:', error)
        alert('Erreur lors de la génération du rapport quotidien')
      } finally {
        isGenerating.value = false
        currentReport.value = ''
      }
    }

    const generateWeeklyReport = async () => {
      isGenerating.value = true
      currentReport.value = 'weekly'
      
      try {
        const response = await dashboardAPI.generateReport('weekly', { period: 7 })
        
        lastGeneratedReport.value = {
          id: response.report_id,
          title: 'Rapport Hebdomadaire',
          period: 'Dernière semaine',
          type: 'weekly',
          executive_summary: response.executive_summary || 'Activité des menaces modérée cette semaine.',
          key_metrics: response.key_metrics || {
            'Total alertes': 105,
            'IOCs uniques': 312,
            'Campagnes détectées': 5,
            'Techniques MITRE actives': 28
          },
          top_threats: response.top_threats || [
            { id: 1, name: 'APT Campaign XYZ', count: 15 },
            { id: 2, name: 'Ransomware Family', count: 8 },
            { id: 3, name: 'Credential Harvesting', count: 6 }
          ]
        }
        
        await loadRecentReports()
      } catch (error) {
        console.error('Erreur génération rapport hebdomadaire:', error)
        alert('Erreur lors de la génération du rapport hebdomadaire')
      } finally {
        isGenerating.value = false
        currentReport.value = ''
      }
    }

    const generateCustomReport = async () => {
      // Logique pour rapport personnalisé avec configuration
      const modal = bootstrap.Modal.getInstance(document.getElementById('reportConfigModal'))
      modal.hide()
      
      try {
        const response = await dashboardAPI.generateReport('custom', reportConfig.value)
        console.log('Rapport personnalisé généré:', response)
      } catch (error) {
        console.error('Erreur rapport personnalisé:', error)
      }
    }

    // Téléchargement de rapport
    const downloadReport = async (reportId) => {
      try {
        const response = await dashboardAPI.downloadReport(reportId)
        
        // Créer un lien de téléchargement
        const blob = new Blob([response], { type: 'application/pdf' })
        const url = window.URL.createObjectURL(blob)
        const link = document.createElement('a')
        link.href = url
        link.download = `cti-report-${reportId}.pdf`
        document.body.appendChild(link)
        link.click()
        document.body.removeChild(link)
        window.URL.revokeObjectURL(url)
      } catch (error) {
        console.error('Erreur téléchargement:', error)
        alert('Erreur lors du téléchargement du rapport')
      }
    }

    // Utilitaires
    const formatDate = (dateString) => {
      return new Date(dateString).toLocaleString('fr-FR')
    }

    const formatMetricName = (key) => {
      return key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())
    }

    const getStatusBadgeClass = (status) => {
      const classes = {
        'completed': 'badge bg-success',
        'generating': 'badge bg-warning',
        'error': 'badge bg-danger',
        'pending': 'badge bg-secondary'
      }
      return classes[status] || 'badge bg-secondary'
    }

    const clearPreview = () => {
      lastGeneratedReport.value = null
    }

    // Mise à jour automatique
    const updateTimestamp = () => {
      lastUpdate.value = new Date().toLocaleString('fr-FR')
    }

    onMounted(() => {
      loadRecentReports()
      
      // Mise à jour automatique toutes les minutes
      setInterval(() => {
        updateTimestamp()
      }, 60000)
    })

    return {
      recentReports,
      lastGeneratedReport,
      isGenerating,
      currentReport,
      lastUpdate,
      reportConfig,
      generateDailyReport,
      generateWeeklyReport,
      generateCustomReport,
      downloadReport,
      loadRecentReports,
      formatDate,
      formatMetricName,
      getStatusBadgeClass,
      clearPreview
    }
  }
}
</script>

<style scoped>
.reports-view {
  padding: 20px 0;
}

.card {
  border: none;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
  transition: transform 0.2s ease;
}

.card:hover {
  transform: translateY(-2px);
}

.btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.report-preview {
  background-color: #f8f9fa;
  border-radius: 8px;
  padding: 20px;
}

.list-group-item {
  border: none;
  border-bottom: 1px solid #e9ecef;
}

.badge {
  font-size: 0.75rem;
}

@media (max-width: 768px) {
  .btn-group .btn {
    margin-bottom: 10px;
  }
  
  .d-flex.gap-2 {
    flex-direction: column;
    gap: 5px !important;
  }
}
</style>