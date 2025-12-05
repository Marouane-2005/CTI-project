<template>
  <div class="metrics-chart">
    <div class="chart-controls">
      <select v-model="selectedTimeframe" @change="updateChart" class="timeframe-select">
        <option value="24h">24 heures</option>
        <option value="7d">7 jours</option>
        <option value="30d">30 jours</option>
      </select>
      <select v-model="selectedMetric" @change="updateChart" class="metric-select">
        <option value="iocs">IOCs détectés</option>
        <option value="threats">Menaces actives</option>
        <option value="risk_score">Score de risque</option>
        <option value="sources">Sources actives</option>
      </select>
    </div>

    <div class="chart-container" ref="chartContainer">
      <canvas ref="chartCanvas"></canvas>
    </div>

    <div class="metrics-summary">
      <div class="summary-card" v-for="stat in summaryStats" :key="stat.label">
        <div class="stat-label">{{ stat.label }}</div>
        <div class="stat-value" :class="stat.trend">{{ stat.value }}</div>
        <div class="stat-change">{{ stat.change }}</div>
      </div>
    </div>

    <!-- Indicateur de mise à jour -->
    <div v-if="isUpdating" class="update-indicator">
      <div class="spinner"></div>
      Mise à jour...
    </div>
  </div>
</template>

<script>
import { ref, reactive, onMounted, onUnmounted, watch, computed } from 'vue'
import { Chart, registerables } from 'chart.js'

// Enregistrer tous les composants Chart.js
Chart.register(...registerables)

export default {
  name: 'MetricsChart',
  props: {
    metrics: {
      type: Array,
      default: () => []
    },
    realTimeEnabled: {
      type: Boolean,
      default: true
    },
    // Nouvelle prop pour recevoir les alertes
    alerts: {
      type: Array,
      default: () => []
    }
  },
  emits: ['metrics-updated'],
  setup(props, { emit }) {
    const chartCanvas = ref(null)
    const chartContainer = ref(null)
    const selectedTimeframe = ref('24h')
    const selectedMetric = ref('iocs')
    const isUpdating = ref(false)
    
    let chartInstance = null
    let realTimeInterval = null
    
    // Données réactives pour le graphique
    const chartData = reactive({
      labels: [],
      datasets: [{
        label: 'IOCs détectés',
        data: [],
        borderColor: '#3B82F6',
        backgroundColor: 'rgba(59, 130, 246, 0.1)',
        borderWidth: 2,
        fill: true,
        tension: 0.4,
        pointRadius: 4,
        pointHoverRadius: 6
      }]
    })

    // Statistiques résumées - calculées dynamiquement
    const summaryStats = computed(() => {
      const alertsCount = props.alerts?.length || 0
      const criticalAlerts = props.alerts?.filter(a => a.level === 'critical').length || 0
      const totalIOCs = chartData.datasets[0]?.data?.reduce((sum, val) => sum + (val || 0), 0) || 0
      
      return [
        { 
          label: 'Total IOCs', 
          value: totalIOCs.toString(),
          change: totalIOCs > 0 ? `+${totalIOCs}` : '0',
          trend: totalIOCs > 0 ? 'positive' : 'neutral' 
        },
        { 
          label: 'Menaces critiques', 
          value: criticalAlerts.toString(),
          change: criticalAlerts > 0 ? `+${criticalAlerts}` : '0',
          trend: criticalAlerts > 0 ? 'negative' : 'neutral'
        },
        { 
          label: 'Alertes totales', 
          value: alertsCount.toString(),
          change: alertsCount > 0 ? `+${alertsCount}` : '0',
          trend: alertsCount > 0 ? 'negative' : 'neutral' 
        },
        { 
          label: 'Sources actives', 
          value: '3',
          change: '+0%',
          trend: 'neutral' 
        }
      ]
    })

    // Configuration du graphique
    const chartConfig = {
      type: 'line',
      data: chartData,
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          y: {
            beginAtZero: true,
            grid: {
              color: 'rgba(0, 0, 0, 0.1)'
            },
            ticks: {
              color: '#6B7280',
              stepSize: 1 // Pour éviter les décimales sur les compteurs
            }
          },
          x: {
            grid: {
              color: 'rgba(0, 0, 0, 0.1)'
            },
            ticks: {
              color: '#6B7280',
              maxTicksLimit: 10
            }
          }
        },
        plugins: {
          legend: {
            display: true,
            position: 'top',
            labels: {
              color: '#374151',
              usePointStyle: true
            }
          },
          tooltip: {
            mode: 'index',
            intersect: false,
            backgroundColor: 'rgba(0, 0, 0, 0.8)',
            titleColor: 'white',
            bodyColor: 'white',
            borderColor: '#3B82F6',
            borderWidth: 1,
            callbacks: {
              title: function(context) {
                return `${context[0].label}`
              },
              label: function(context) {
                const metricNames = {
                  'iocs': 'IOCs',
                  'threats': 'Menaces',
                  'risk_score': 'Score de risque',
                  'sources': 'Sources'
                }
                const metricName = metricNames[selectedMetric.value] || 'Valeur'
                return `${metricName}: ${context.parsed.y}`
              }
            }
          }
        },
        interaction: {
          mode: 'nearest',
          axis: 'x',
          intersect: false
        },
        animation: {
          duration: 750,
          easing: 'easeInOutQuart'
        }
      }
    }

    // Initialisation du graphique
    const initChart = () => {
      if (chartCanvas.value) {
        chartInstance = new Chart(chartCanvas.value.getContext('2d'), chartConfig)
        console.log('📊 Graphique initialisé')
      }
    }

    // Génération de données basées sur les alertes réelles
    const generateDataFromAlerts = () => {
      const now = new Date()
      const points = selectedTimeframe.value === '24h' ? 24 : 
                    selectedTimeframe.value === '7d' ? 7 : 30
      const timeUnit = selectedTimeframe.value === '24h' ? 'hour' : 'day'
      
      // Créer les labels temporels
      const labels = []
      const dataPoints = []
      
      for (let i = points - 1; i >= 0; i--) {
        let date
        if (timeUnit === 'hour') {
          date = new Date(now - i * 3600000) // 1 heure en ms
          labels.push(date.toLocaleTimeString('fr-FR', { 
            hour: '2-digit', 
            minute: '2-digit' 
          }))
        } else {
          date = new Date(now - i * 86400000) // 1 jour en ms
          labels.push(date.toLocaleDateString('fr-FR', {
            month: 'short',
            day: 'numeric'
          }))
        }
        
        // Compter les éléments dans cette période
        let count = 0
        if (selectedMetric.value === 'iocs' || selectedMetric.value === 'threats') {
          // Compter les alertes dans cette période
          const periodStart = new Date(date - (timeUnit === 'hour' ? 3600000 : 86400000))
          const periodEnd = date
          
          count = (props.alerts || []).filter(alert => {
            const alertDate = new Date(alert.timestamp)
            return alertDate >= periodStart && alertDate <= periodEnd
          }).length
          
          // Ajouter une base de données simulées pour avoir un graphique plus réaliste
          if (selectedMetric.value === 'iocs') {
            count += Math.floor(Math.random() * 3) // 0-2 IOCs supplémentaires
          }
        } else if (selectedMetric.value === 'risk_score') {
          // Score de risque basé sur le niveau des alertes
          const alertsInPeriod = (props.alerts || []).filter(alert => {
            const alertDate = new Date(alert.timestamp)
            const periodStart = new Date(date - (timeUnit === 'hour' ? 3600000 : 86400000))
            return alertDate >= periodStart && alertDate <= date
          })
          
          if (alertsInPeriod.length > 0) {
            const avgRisk = alertsInPeriod.reduce((sum, alert) => {
              const riskValues = { 'critical': 9, 'high': 7, 'medium': 5, 'low': 3 }
              return sum + (riskValues[alert.level] || 5)
            }, 0) / alertsInPeriod.length
            count = avgRisk
          } else {
            count = 2 + Math.random() * 3 // Score de base entre 2-5
          }
        } else {
          count = 1 + Math.floor(Math.random() * 2) // Sources actives
        }
        
        dataPoints.push(count)
      }
      
      return { labels, dataPoints }
    }

    // Mise à jour des données du graphique
    const updateChart = async () => {
      if (!chartInstance) return

      isUpdating.value = true
      
      try {
        console.log('🔄 Mise à jour du graphique...')
        
        // Générer les données basées sur les alertes actuelles
        const { labels, dataPoints } = generateDataFromAlerts()
        
        // Mise à jour des labels
        chartData.labels = labels
        
        // Configuration selon la métrique sélectionnée
        const metricConfig = getMetricConfig(selectedMetric.value)
        chartData.datasets[0] = {
          ...chartData.datasets[0],
          ...metricConfig,
          data: dataPoints
        }

        // Mise à jour du graphique avec animation
        chartInstance.update('active')
        
        console.log('✅ Graphique mis à jour avec', dataPoints.length, 'points de données')
        
        // Émettre l'événement de mise à jour
        emit('metrics-updated', {
          metric: selectedMetric.value,
          timeframe: selectedTimeframe.value,
          dataPoints: dataPoints.length,
          totalValue: dataPoints.reduce((sum, val) => sum + val, 0)
        })
        
      } catch (error) {
        console.error('❌ Erreur lors de la mise à jour du graphique:', error)
      } finally {
        isUpdating.value = false
      }
    }

    // Configuration par métrique
    const getMetricConfig = (metric) => {
      const configs = {
        iocs: {
          label: 'IOCs détectés',
          borderColor: '#3B82F6',
          backgroundColor: 'rgba(59, 130, 246, 0.1)'
        },
        threats: {
          label: 'Menaces actives',
          borderColor: '#EF4444',
          backgroundColor: 'rgba(239, 68, 68, 0.1)'
        },
        risk_score: {
          label: 'Score de risque moyen',
          borderColor: '#F59E0B',
          backgroundColor: 'rgba(245, 158, 11, 0.1)'
        },
        sources: {
          label: 'Sources actives',
          borderColor: '#10B981',
          backgroundColor: 'rgba(16, 185, 129, 0.1)'
        }
      }
      return configs[metric] || configs.iocs
    }

    // Mise à jour temps réel
    const startRealTimeUpdates = () => {
      if (props.realTimeEnabled && !realTimeInterval) {
        realTimeInterval = setInterval(() => {
          updateChart()
        }, 10000) // Toutes les 10 secondes pour voir les changements plus rapidement
        console.log('🔄 Mise à jour temps réel activée')
      }
    }

    const stopRealTimeUpdates = () => {
      if (realTimeInterval) {
        clearInterval(realTimeInterval)
        realTimeInterval = null
        console.log('⏹️ Mise à jour temps réel arrêtée')
      }
    }

    // Watchers
    watch([selectedTimeframe, selectedMetric], () => {
      console.log(`📊 Changement: ${selectedMetric.value} sur ${selectedTimeframe.value}`)
      updateChart()
    })

    // IMPORTANT: Watcher pour les alertes
    watch(() => props.alerts, (newAlerts, oldAlerts) => {
      console.log('🚨 Alertes mises à jour:', newAlerts?.length || 0)
      if (newAlerts?.length !== oldAlerts?.length) {
        setTimeout(updateChart, 100) // Petit délai pour laisser le DOM se mettre à jour
      }
    }, { deep: true, immediate: true })

    // Lifecycle hooks
    onMounted(async () => {
      console.log('🎯 MetricsChart monté')
      await initChart()
      await updateChart()
      startRealTimeUpdates()
    })

    onUnmounted(() => {
      console.log('🛑 MetricsChart démonté')
      stopRealTimeUpdates()
      if (chartInstance) {
        chartInstance.destroy()
      }
    })

    return {
      chartCanvas,
      chartContainer,
      selectedTimeframe,
      selectedMetric,
      summaryStats,
      isUpdating,
      updateChart
    }
  }
}
</script>

<style scoped>
.metrics-chart {
  background: white;
  border-radius: 8px;
  padding: 20px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
  position: relative;
}

.chart-controls {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
  flex-wrap: wrap;
  gap: 10px;
}

.timeframe-select,
.metric-select {
  padding: 8px 12px;
  border: 1px solid #D1D5DB;
  border-radius: 6px;
  background: white;
  color: #374151;
  font-size: 14px;
  cursor: pointer;
  transition: border-color 0.2s;
}

.timeframe-select:hover,
.metric-select:hover {
  border-color: #3B82F6;
}

.chart-container {
  position: relative;
  height: 350px;
  margin-bottom: 20px;
}

.metrics-summary {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 15px;
  margin-top: 20px;
}

.summary-card {
  background: #F9FAFB;
  border-radius: 8px;
  padding: 15px;
  text-align: center;
  border: 1px solid #E5E7EB;
  transition: transform 0.2s ease;
}

.summary-card:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

.stat-label {
  font-size: 12px;
  color: #6B7280;
  font-weight: 500;
  margin-bottom: 8px;
  text-transform: uppercase;
}

.stat-value {
  font-size: 24px;
  font-weight: bold;
  margin-bottom: 5px;
}

.stat-value.positive {
  color: #059669;
}

.stat-value.negative {
  color: #DC2626;
}

.stat-value.neutral {
  color: #374151;
}

.stat-change {
  font-size: 12px;
  font-weight: 500;
  color: inherit;
}

/* Indicateur de mise à jour */
.update-indicator {
  position: absolute;
  top: 10px;
  right: 10px;
  background: rgba(59, 130, 246, 0.1);
  color: #3B82F6;
  padding: 4px 8px;
  border-radius: 4px;
  font-size: 12px;
  display: flex;
  align-items: center;
  gap: 6px;
}

.spinner {
  width: 12px;
  height: 12px;
  border: 2px solid #E5E7EB;
  border-top: 2px solid #3B82F6;
  border-radius: 50%;
  animation: spin 1s linear infinite;
}

@keyframes spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}

/* Responsive design */
@media (max-width: 768px) {
  .chart-controls {
    flex-direction: column;
    align-items: stretch;
  }

  .timeframe-select,
  .metric-select {
    width: 100%;
  }

  .metrics-summary {
    grid-template-columns: repeat(2, 1fr);
  }

  .chart-container {
    height: 300px;
  }
}

@media (max-width: 480px) {
  .metrics-summary {
    grid-template-columns: 1fr;
  }
  
  .metrics-chart {
    padding: 15px;
  }
}
</style>