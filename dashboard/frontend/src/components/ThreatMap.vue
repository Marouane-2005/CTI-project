<template>
  <div class="threat-map-container">
    <div class="map-header">
      <h3>Répartition Géographique des Menaces</h3>
      <div class="map-controls">
        <select v-model="selectedTimeRange" @change="updateMapData" class="time-select">
          <option value="1h">Dernière heure</option>
          <option value="24h">24 heures</option>
          <option value="7d">7 jours</option>
          <option value="30d">30 jours</option>
        </select>
        <button @click="toggleHeatmap" class="toggle-btn" :class="{ active: showHeatmap }">
          {{ showHeatmap ? 'Désactiver Heatmap' : 'Activer Heatmap' }}
        </button>
      </div>
    </div>
    
    <div class="map-legend">
      <div class="legend-item critical">
        <span class="legend-color"></span>
        <span>Critique ({{ threatCounts.critical }})</span>
      </div>
      <div class="legend-item high">
        <span class="legend-color"></span>
        <span>Élevé ({{ threatCounts.high }})</span>
      </div>
      <div class="legend-item medium">
        <span class="legend-color"></span>
        <span>Moyen ({{ threatCounts.medium }})</span>
      </div>
      <div class="legend-item low">
        <span class="legend-color"></span>
        <span>Faible ({{ threatCounts.low }})</span>
      </div>
    </div>
    
    <div id="threat-map" ref="mapContainer" class="map-canvas"></div>
    
    <div v-if="selectedThreat" class="threat-details">
      <div class="threat-popup">
        <div class="popup-header">
          <h4>{{ selectedThreat.country }}</h4>
          <button @click="closePopup" class="close-btn">&times;</button>
        </div>
        <div class="popup-content">
          <div class="threat-stat">
            <span class="label">Total IOCs:</span>
            <span class="value">{{ selectedThreat.total_threats }}</span>
          </div>
          <div class="threat-stat">
            <span class="label">Score de risque moyen:</span>
            <span class="value risk-score" :class="getRiskClass(selectedThreat.avg_risk_score)">
              {{ selectedThreat.avg_risk_score.toFixed(1) }}
            </span>
          </div>
          <div class="threat-stat">
            <span class="label">Dernière activité:</span>
            <span class="value">{{ formatTime(selectedThreat.last_activity) }}</span>
          </div>
          <div class="threat-types">
            <h5>Types de menaces:</h5>
            <div class="threat-type-list">
              <span v-for="(count, type) in selectedThreat.threat_types" 
                    :key="type" 
                    class="threat-type-tag">
                {{ type }}: {{ count }}
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
    
    <div v-if="loading" class="map-loading">
      <div class="spinner"></div>
      <p>Chargement des données géographiques...</p>
    </div>
  </div>
</template>

<script>
import { ref, reactive, onMounted, onUnmounted, watch } from 'vue'
import L from 'leaflet'

export default {
  name: 'ThreatMap',
  props: {
    threatData: {
      type: Object,
      default: () => ({})
    },
    refreshInterval: {
      type: Number,
      default: 30000 // 30 secondes
    }
  },
  emits: ['threat-selected', 'region-filtered'],
  setup(props, { emit }) {
    const mapContainer = ref(null)
    const selectedTimeRange = ref('24h')
    const selectedThreat = ref(null)
    const showHeatmap = ref(true)
    const loading = ref(false)
    
    let map = null
    let markers = []
    let heatmapLayer = null
    
    const threatCounts = reactive({
      critical: 0,
      high: 0,
      medium: 0,
      low: 0
    })
    
    const mapData = ref([])
    
    // Configuration de la carte
    const initMap = () => {
      if (!mapContainer.value || map) return
      
      // Initialisation de la carte Leaflet
      map = L.map(mapContainer.value, {
        center: [20, 0],
        zoom: 2,
        zoomControl: true,
        scrollWheelZoom: true
      })
      
      // Couche de base
      L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '© OpenStreetMap contributors',
        maxZoom: 18
      }).addTo(map)
      
      // Configuration des icônes personnalisées
      const createThreatIcon = (riskLevel) => {
        const colors = {
          critical: '#ff4757',
          high: '#ff7675',
          medium: '#fdcb6e',
          low: '#74b9ff'
        }
        
        const sizes = {
          critical: [25, 25],
          high: [20, 20],
          medium: [15, 15],
          low: [12, 12]
        }
        
        return L.divIcon({
          html: `<div style="background-color: ${colors[riskLevel]}; 
                           width: ${sizes[riskLevel][0]}px; 
                           height: ${sizes[riskLevel][1]}px; 
                           border-radius: 50%; 
                           border: 2px solid white;
                           box-shadow: 0 2px 5px rgba(0,0,0,0.3);
                           display: flex;
                           align-items: center;
                           justify-content: center;
                           color: white;
                           font-weight: bold;
                           font-size: 10px;">
                  ${riskLevel === 'critical' ? '!' : ''}
                 </div>`,
          className: 'custom-threat-marker',
          iconSize: sizes[riskLevel],
          iconAnchor: [sizes[riskLevel][0] / 2, sizes[riskLevel][1] / 2]
        })
      }
      
      updateMapData()
    }
    
    // Mise à jour des données de la carte
    const updateMapData = async () => {
      if (!map) return
      
      loading.value = true
      clearMarkers()
      
      try {
        // Simulation des données géographiques (à remplacer par votre API)
        const geoData = await fetchThreatGeoData()
        mapData.value = geoData
        
        // Remise à zéro des compteurs
        threatCounts.critical = 0
        threatCounts.high = 0
        threatCounts.medium = 0
        threatCounts.low = 0
        
        // Ajout des marqueurs
        geoData.forEach(threat => {
          const riskLevel = getRiskLevel(threat.avg_risk_score)
          threatCounts[riskLevel]++
          
          const marker = L.marker([threat.latitude, threat.longitude], {
            icon: createThreatIcon(riskLevel)
          })
          .bindPopup(createPopupContent(threat))
          .on('click', () => selectThreat(threat))
          .addTo(map)
          
          markers.push(marker)
        })
        
        // Mise à jour de la heatmap si activée
        if (showHeatmap.value) {
          updateHeatmap(geoData)
        }
        
      } catch (error) {
        console.error('Erreur lors du chargement des données géographiques:', error)
      } finally {
        loading.value = false
      }
    }
    
    // Simulation de récupération des données géographiques
    const fetchThreatGeoData = async () => {
      // À remplacer par votre appel API réel
      return [
        {
          country: 'États-Unis',
          latitude: 39.8283,
          longitude: -98.5795,
          total_threats: 245,
          avg_risk_score: 7.8,
          last_activity: new Date(),
          threat_types: { malware: 123, phishing: 67, botnet: 55 }
        },
        {
          country: 'Russie',
          latitude: 61.5240,
          longitude: 105.3188,
          total_threats: 189,
          avg_risk_score: 8.2,
          last_activity: new Date(Date.now() - 1800000),
          threat_types: { apt: 89, malware: 100 }
        },
        {
          country: 'Chine',
          latitude: 35.8617,
          longitude: 104.1954,
          total_threats: 156,
          avg_risk_score: 7.5,
          last_activity: new Date(Date.now() - 3600000),
          threat_types: { espionage: 78, malware: 78 }
        },
        {
          country: 'Allemagne',
          latitude: 51.1657,
          longitude: 10.4515,
          total_threats: 78,
          avg_risk_score: 5.2,
          last_activity: new Date(Date.now() - 7200000),
          threat_types: { phishing: 45, malware: 33 }
        }
      ]
    }
    
    const createThreatIcon = (riskLevel) => {
      const colors = {
        critical: '#ff4757',
        high: '#ff7675',
        medium: '#fdcb6e',
        low: '#74b9ff'
      }
      
      const sizes = {
        critical: [25, 25],
        high: [20, 20],
        medium: [15, 15],
        low: [12, 12]
      }
      
      return L.divIcon({
        html: `<div style="background-color: ${colors[riskLevel]}; 
                         width: ${sizes[riskLevel][0]}px; 
                         height: ${sizes[riskLevel][1]}px; 
                         border-radius: 50%; 
                         border: 2px solid white;
                         box-shadow: 0 2px 5px rgba(0,0,0,0.3);
                         display: flex;
                         align-items: center;
                         justify-content: center;
                         color: white;
                         font-weight: bold;
                         font-size: 10px;">
                ${riskLevel === 'critical' ? '!' : ''}
               </div>`,
        className: 'custom-threat-marker',
        iconSize: sizes[riskLevel],
        iconAnchor: [sizes[riskLevel][0] / 2, sizes[riskLevel][1] / 2]
      })
    }
    
    const createPopupContent = (threat) => {
      return `
        <div class="threat-popup-mini">
          <h4>${threat.country}</h4>
          <p><strong>IOCs:</strong> ${threat.total_threats}</p>
          <p><strong>Risque:</strong> <span class="risk-${getRiskLevel(threat.avg_risk_score)}">${threat.avg_risk_score.toFixed(1)}</span></p>
        </div>
      `
    }
    
    const getRiskLevel = (score) => {
      if (score >= 8) return 'critical'
      if (score >= 6) return 'high'
      if (score >= 4) return 'medium'
      return 'low'
    }
    
    const getRiskClass = (score) => {
      return `risk-${getRiskLevel(score)}`
    }
    
    const clearMarkers = () => {
      markers.forEach(marker => {
        map.removeLayer(marker)
      })
      markers = []
      
      if (heatmapLayer) {
        map.removeLayer(heatmapLayer)
        heatmapLayer = null
      }
    }
    
    const selectThreat = (threat) => {
      selectedThreat.value = threat
      emit('threat-selected', threat)
    }
    
    const closePopup = () => {
      selectedThreat.value = null
    }
    
    const toggleHeatmap = () => {
      showHeatmap.value = !showHeatmap.value
      if (showHeatmap.value) {
        updateHeatmap(mapData.value)
      } else if (heatmapLayer) {
        map.removeLayer(heatmapLayer)
        heatmapLayer = null
      }
    }
    
    const updateHeatmap = (data) => {
      // Implémentation basique de heatmap avec des cercles
      if (heatmapLayer) {
        map.removeLayer(heatmapLayer)
      }
      
      const heatmapPoints = data.map(threat => [
        threat.latitude,
        threat.longitude,
        threat.avg_risk_score / 10
      ])
      
      // Création de cercles pour simuler une heatmap
      heatmapPoints.forEach(([lat, lng, intensity]) => {
        const circle = L.circle([lat, lng], {
          color: intensity > 0.8 ? '#ff4757' : intensity > 0.6 ? '#ff7675' : '#fdcb6e',
          fillColor: intensity > 0.8 ? '#ff4757' : intensity > 0.6 ? '#ff7675' : '#fdcb6e',
          fillOpacity: 0.3,
          radius: intensity * 500000
        })
        
        if (!heatmapLayer) {
          heatmapLayer = L.layerGroup()
        }
        heatmapLayer.addLayer(circle)
      })
      
      if (heatmapLayer) {
        heatmapLayer.addTo(map)
      }
    }
    
    const formatTime = (date) => {
      const now = new Date()
      const diff = now - date
      const minutes = Math.floor(diff / 60000)
      
      if (minutes < 1) return 'À l\'instant'
      if (minutes < 60) return `Il y a ${minutes}min`
      const hours = Math.floor(minutes / 60)
      if (hours < 24) return `Il y a ${hours}h`
      const days = Math.floor(hours / 24)
      return `Il y a ${days}j`
    }
    
    // Watchers
    watch(() => props.threatData, () => {
      updateMapData()
    }, { deep: true })
    
    watch(selectedTimeRange, () => {
      updateMapData()
    })
    
    // Lifecycle
    onMounted(() => {
      setTimeout(initMap, 100)
      
      // Mise à jour périodique
      const interval = setInterval(updateMapData, props.refreshInterval)
      onUnmounted(() => clearInterval(interval))
    })
    
    onUnmounted(() => {
      if (map) {
        map.remove()
        map = null
      }
    })
    
    return {
      mapContainer,
      selectedTimeRange,
      selectedThreat,
      showHeatmap,
      loading,
      threatCounts,
      updateMapData,
      toggleHeatmap,
      closePopup,
      getRiskClass,
      formatTime
    }
  }
}
</script>

<style scoped>
.threat-map-container {
  width: 100%;
  height: 100%;
  position: relative;
  background: white;
  border-radius: 8px;
  overflow: hidden;
}

.map-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 15px 20px;
  border-bottom: 1px solid #eee;
  background: #f8f9fa;
}

.map-header h3 {
  margin: 0;
  color: #2c3e50;
  font-size: 1.2em;
}

.map-controls {
  display: flex;
  gap: 10px;
  align-items: center;
}

.time-select {
  padding: 5px 10px;
  border: 1px solid #ddd;
  border-radius: 4px;
  font-size: 12px;
}

.toggle-btn {
  padding: 6px 12px;
  background: #6c757d;
  color: white;
  border: none;
  border-radius: 4px;
  font-size: 12px;
  cursor: pointer;
  transition: background-color 0.2s;
}

.toggle-btn.active {
  background: #28a745;
}

.toggle-btn:hover {
  opacity: 0.9;
}

.map-legend {
  display: flex;
  justify-content: center;
  gap: 20px;
  padding: 10px;
  background: #f8f9fa;
  border-bottom: 1px solid #eee;
  font-size: 12px;
}

.legend-item {
  display: flex;
  align-items: center;
  gap: 5px;
}

.legend-color {
  width: 12px;
  height: 12px;
  border-radius: 50%;
  border: 1px solid white;
}

.legend-item.critical .legend-color {
  background: #ff4757;
}

.legend-item.high .legend-color {
  background: #ff7675;
}

.legend-item.medium .legend-color {
  background: #fdcb6e;
}

.legend-item.low .legend-color {
  background: #74b9ff;
}

.map-canvas {
  height: 400px;
  width: 100%;
  z-index: 1;
}

.threat-details {
  position: absolute;
  top: 60px;
  right: 20px;
  z-index: 1000;
}

.threat-popup {
  background: white;
  border-radius: 8px;
  box-shadow: 0 4px 12px rgba(0,0,0,0.2);
  min-width: 250px;
  max-width: 300px;
}

.popup-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 15px;
  border-bottom: 1px solid #eee;
  background: #f8f9fa;
  border-radius: 8px 8px 0 0;
}

.popup-header h4 {
  margin: 0;
  color: #2c3e50;
  font-size: 1.1em;
}

.close-btn {
  background: none;
  border: none;
  font-size: 20px;
  color: #6c757d;
  cursor: pointer;
  padding: 0;
  width: 25px;
  height: 25px;
  display: flex;
  align-items: center;
  justify-content: center;
}

.close-btn:hover {
  color: #495057;
}

.popup-content {
  padding: 15px;
}

.threat-stat {
  display: flex;
  justify-content: space-between;
  margin-bottom: 10px;
  font-size: 13px;
}

.threat-stat .label {
  color: #6c757d;
}

.threat-stat .value {
  font-weight: 600;
  color: #2c3e50;
}

.risk-score.risk-critical {
  color: #ff4757;
}

.risk-score.risk-high {
  color: #ff7675;
}

.risk-score.risk-medium {
  color: #fdcb6e;
}

.risk-score.risk-low {
  color: #74b9ff;
}

.threat-types {
  margin-top: 15px;
  padding-top: 15px;
  border-top: 1px solid #eee;
}

.threat-types h5 {
  margin: 0 0 10px 0;
  font-size: 13px;
  color: #2c3e50;
}

.threat-type-list {
  display: flex;
  flex-wrap: wrap;
  gap: 5px;
}

.threat-type-tag {
  background: #e9ecef;
  padding: 3px 8px;
  border-radius: 12px;
  font-size: 11px;
  color: #495057;
}

.map-loading {
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  text-align: center;
  z-index: 1000;
  background: rgba(255, 255, 255, 0.9);
  padding: 20px;
  border-radius: 8px;
}

.spinner {
  width: 30px;
  height: 30px;
  border: 3px solid #f3f3f3;
  border-top: 3px solid #007bff;
  border-radius: 50%;
  animation: spin 1s linear infinite;
  margin: 0 auto 10px;
}

@keyframes spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}

/* Styles pour les popups Leaflet */
:deep(.leaflet-popup-content-wrapper) {
  border-radius: 6px;
  padding: 0;
}

:deep(.threat-popup-mini) {
  padding: 10px;
  font-size: 12px;
}

:deep(.threat-popup-mini h4) {
  margin: 0 0 8px 0;
  font-size: 14px;
  color: #2c3e50;
}

:deep(.threat-popup-mini p) {
  margin: 3px 0;
}

:deep(.risk-critical) {
  color: #ff4757;
  font-weight: bold;
}

:deep(.risk-high) {
  color: #ff7675;
  font-weight: bold;
}

:deep(.risk-medium) {
  color: #fdcb6e;
  font-weight: bold;
}

:deep(.risk-low) {
  color: #74b9ff;
  font-weight: bold;
}
</style>