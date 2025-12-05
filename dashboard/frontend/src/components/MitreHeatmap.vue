<template>
  <div class="mitre-heatmap">
    <div class="heatmap-controls">
      <div class="control-group">
        <select v-model="selectedTimeRange" @change="loadHeatmapData" class="time-select">
          <option value="7">7 jours</option>
          <option value="30">30 jours</option>
          <option value="90">90 jours</option>
        </select>
        
        <select v-model="selectedTactic" @change="filterByTactic" class="tactic-select">
          <option value="">Toutes les tactiques</option>
          <option v-for="tactic in availableTactics" :key="tactic.id" :value="tactic.id">
            {{ tactic.name }}
          </option>
        </select>
      </div>

      <div class="legend">
        <span class="legend-label">Fréquence:</span>
        <div class="legend-scale">
          <div class="legend-item" v-for="level in legendLevels" :key="level.label">
            <div class="color-box" :style="{ backgroundColor: level.color }"></div>
            <span>{{ level.label }}</span>
          </div>
        </div>
      </div>
    </div>

    <div class="heatmap-container" ref="heatmapContainer">
      <div v-if="loading" class="loading-overlay">
        <div class="loading-spinner"></div>
        <p>Chargement de la matrice MITRE ATT&CK...</p>
      </div>

      <div class="tactics-header" v-if="!loading">
        <div 
          v-for="tactic in visibleTactics" 
          :key="tactic.id"
          class="tactic-column"
          :title="tactic.description"
        >
          {{ tactic.name }}
        </div>
      </div>

      <div class="techniques-grid" v-if="!loading">
        <div 
          v-for="technique in visibleTechniques" 
          :key="technique.id"
          class="technique-cell"
          :class="getTechniqueCellClass(technique)"
          :style="getTechniqueCellStyle(technique)"
          :title="getTechniqueTooltip(technique)"
          @click="selectTechnique(technique)"
        >
          <div class="technique-id">{{ technique.technique_id }}</div>
          <div class="technique-name">{{ truncateName(technique.name) }}</div>
          <div class="technique-count" v-if="technique.count > 0">{{ technique.count }}</div>
        </div>
      </div>
    </div>

    <!-- Panneau de détails de la technique sélectionnée -->
    <div v-if="selectedTechnique" class="technique-details">
      <div class="details-header">
        <h4>{{ selectedTechnique.technique_id }} - {{ selectedTechnique.name }}</h4>
        <button @click="selectedTechnique = null" class="close-btn">&times;</button>
      </div>
      
      <div class="details-content">
        <div class="detail-section">
          <strong>Tactique:</strong> {{ selectedTechnique.tactic_name }}
        </div>
        <div class="detail-section">
          <strong>Occurrences:</strong> {{ selectedTechnique.count }} sur {{ selectedTimeRange }} jours
        </div>
        <div class="detail-section">
          <strong>Dernière détection:</strong> 
          {{ formatDate(selectedTechnique.last_seen) }}
        </div>
        <div class="detail-section">
          <strong>Indicateurs associés:</strong>
          <ul class="indicators-list">
            <li v-for="indicator in selectedTechnique.related_indicators" :key="indicator.id">
              {{ indicator.value }} ({{ indicator.type }})
            </li>
          </ul>
        </div>
      </div>
    </div>

    <!-- Statistiques résumées -->
    <div class="heatmap-stats">
      <div class="stat-item">
        <div class="stat-value">{{ totalTechniques }}</div>
        <div class="stat-label">Techniques détectées</div>
      </div>
      <div class="stat-item">
        <div class="stat-value">{{ activeTactics }}</div>
        <div class="stat-label">Tactiques actives</div>
      </div>
      <div class="stat-item">
        <div class="stat-value">{{ totalDetections }}</div>
        <div class="stat-label">Détections totales</div>
      </div>
      <div class="stat-item">
        <div class="stat-value">{{ topTechnique?.technique_id || 'N/A' }}</div>
        <div class="stat-label">Technique la plus fréquente</div>
      </div>
    </div>
  </div>
</template>

<script>
import { ref, reactive, computed, onMounted, watch } from 'vue'

export default {
  name: 'MitreHeatmap',
  props: {
    techniques: {
      type: Array,
      default: () => []
    },
    realTimeEnabled: {
      type: Boolean,
      default: true
    }
  },
  setup(props, { emit }) {
    const heatmapContainer = ref(null)
    const loading = ref(true)
    const selectedTimeRange = ref(30)
    const selectedTactic = ref('')
    const selectedTechnique = ref(null)

    // Données réactives
    const heatmapData = reactive({
      techniques: [],
      tactics: [],
      maxCount: 0
    })

    // Tactiques MITRE ATT&CK standard
    const availableTactics = ref([
      { id: 'reconnaissance', name: 'Reconnaissance' },
      { id: 'resource-development', name: 'Resource Development' },
      { id: 'initial-access', name: 'Initial Access' },
      { id: 'execution', name: 'Execution' },
      { id: 'persistence', name: 'Persistence' },
      { id: 'privilege-escalation', name: 'Privilege Escalation' },
      { id: 'defense-evasion', name: 'Defense Evasion' },
      { id: 'credential-access', name: 'Credential Access' },
      { id: 'discovery', name: 'Discovery' },
      { id: 'lateral-movement', name: 'Lateral Movement' },
      { id: 'collection', name: 'Collection' },
      { id: 'command-and-control', name: 'Command and Control' },
      { id: 'exfiltration', name: 'Exfiltration' },
      { id: 'impact', name: 'Impact' }
    ])

    // Légende des niveaux de couleur
    const legendLevels = ref([
      { label: 'Aucune', color: '#F3F4F6' },
      { label: 'Faible', color: '#FEF3C7' },
      { label: 'Modérée', color: '#FCD34D' },
      { label: 'Élevée', color: '#F59E0B' },
      { label: 'Très élevée', color: '#D97706' },
      { label: 'Critique', color: '#DC2626' }
    ])

    // Techniques visibles après filtrage
    const visibleTechniques = computed(() => {
      if (!selectedTactic.value) {
        return heatmapData.techniques
      }
      return heatmapData.techniques.filter(tech => 
        tech.tactic_id === selectedTactic.value
      )
    })

    // Tactiques visibles
    const visibleTactics = computed(() => {
      if (selectedTactic.value) {
        return availableTactics.value.filter(tactic => tactic.id === selectedTactic.value)
      }
      return availableTactics.value
    })

    // Statistiques calculées
    const totalTechniques = computed(() => 
      heatmapData.techniques.filter(tech => tech.count > 0).length
    )

    const activeTactics = computed(() => {
      const tactics = new Set(
        heatmapData.techniques
          .filter(tech => tech.count > 0)
          .map(tech => tech.tactic_id)
      )
      return tactics.size
    })

    const totalDetections = computed(() => 
      heatmapData.techniques.reduce((sum, tech) => sum + tech.count, 0)
    )

    const topTechnique = computed(() => 
      heatmapData.techniques.reduce((max, tech) => 
        tech.count > (max?.count || 0) ? tech : max, null
      )
    )

    // Chargement des données de la heatmap
    const loadHeatmapData = async () => {
      loading.value = true
      try {
        const response = await fetch(
          `/api/dashboard/mitre/heatmap?days=${selectedTimeRange.value}`
        )
        const data = await response.json()

        if (data && data.techniques) {
          heatmapData.techniques = data.techniques
          heatmapData.maxCount = Math.max(...data.techniques.map(t => t.count), 0)
        } else {
          // Données de démonstration si l'API n'est pas disponible
          generateMockData()
        }
      } catch (error) {
        console.error('Erreur lors du chargement des données MITRE:', error)
        generateMockData()
      } finally {
        loading.value = false
      }
    }

    // Génération de données fictives
    const generateMockData = () => {
      const mockTechniques = [
        { technique_id: 'T1566', name: 'Phishing', tactic_id: 'initial-access', tactic_name: 'Initial Access' },
        { technique_id: 'T1059', name: 'Command and Scripting Interpreter', tactic_id: 'execution', tactic_name: 'Execution' },
        { technique_id: 'T1055', name: 'Process Injection', tactic_id: 'privilege-escalation', tactic_name: 'Privilege Escalation' },
        { technique_id: 'T1027', name: 'Obfuscated Files or Information', tactic_id: 'defense-evasion', tactic_name: 'Defense Evasion' },
        { technique_id: 'T1003', name: 'OS Credential Dumping', tactic_id: 'credential-access', tactic_name: 'Credential Access' },
        { technique_id: 'T1082', name: 'System Information Discovery', tactic_id: 'discovery', tactic_name: 'Discovery' },
        { technique_id: 'T1021', name: 'Remote Services', tactic_id: 'lateral-movement', tactic_name: 'Lateral Movement' },
        { technique_id: 'T1005', name: 'Data from Local System', tactic_id: 'collection', tactic_name: 'Collection' },
        { technique_id: 'T1071', name: 'Application Layer Protocol', tactic_id: 'command-and-control', tactic_name: 'Command and Control' },
        { technique_id: 'T1041', name: 'Exfiltration Over C2 Channel', tactic_id: 'exfiltration', tactic_name: 'Exfiltration' },
        { technique_id: 'T1486', name: 'Data Encrypted for Impact', tactic_id: 'impact', tactic_name: 'Impact' }
      ]

      heatmapData.techniques = mockTechniques.map(tech => ({
        ...tech,
        count: Math.floor(Math.random() * 50) + 1,
        last_seen: new Date(Date.now() - Math.random() * 7 * 24 * 3600 * 1000).toISOString(),
        related_indicators: Array.from({ length: Math.floor(Math.random() * 3) + 1 }, (_, i) => ({
          id: i,
          value: `indicator_${i + 1}`,
          type: 'ip'
        }))
      }))

      heatmapData.maxCount = Math.max(...heatmapData.techniques.map(t => t.count))
    }

    // Style de la cellule de technique
    const getTechniqueCellStyle = (technique) => {
      if (technique.count === 0) {
        return { backgroundColor: '#F3F4F6' }
      }

      const intensity = technique.count / heatmapData.maxCount
      const colors = [
        '#FEF3C7', // Faible
        '#FCD34D', // Modérée  
        '#F59E0B', // Élevée
        '#D97706', // Très élevée
        '#DC2626'  // Critique
      ]

      const colorIndex = Math.min(Math.floor(intensity * colors.length), colors.length - 1)
      return { backgroundColor: colors[colorIndex] }
    }

    // Classe CSS de la cellule
    const getTechniqueCellClass = (technique) => {
      return {
        'has-detections': technique.count > 0,
        'selected': selectedTechnique.value?.technique_id === technique.technique_id
      }
    }

    // Tooltip de la technique
    const getTechniqueTooltip = (technique) => {
      return `${technique.technique_id} - ${technique.name}\n` +
             `Tactique: ${technique.tactic_name}\n` +
             `Occurrences: ${technique.count}\n` +
             `Dernière détection: ${formatDate(technique.last_seen)}`
    }

    // Sélection d'une technique
    const selectTechnique = (technique) => {
      if (technique.count > 0) {
        selectedTechnique.value = technique
        emit('technique-selected', technique)
      }
    }

    // Filtrage par tactique
    const filterByTactic = () => {
      // Le filtrage est géré par le computed visibleTechniques
    }

    // Utilitaires
    const truncateName = (name, maxLength = 25) => {
      return name.length > maxLength ? name.substring(0, maxLength) + '...' : name
    }

    const formatDate = (dateString) => {
      if (!dateString) return 'N/A'
      return new Date(dateString).toLocaleDateString('fr-FR', {
        day: 'numeric',
        month: 'short',
        year: 'numeric'
      })
    }

    // Watchers
    watch(() => props.techniques, (newTechniques) => {
      if (newTechniques && newTechniques.length > 0) {
        heatmapData.techniques = newTechniques
        heatmapData.maxCount = Math.max(...newTechniques.map(t => t.count), 0)
      }
    }, { deep: true })

    // Lifecycle
    onMounted(() => {
      loadHeatmapData()
      
      // Mise à jour temps réel si activée
      if (props.realTimeEnabled) {
        setInterval(loadHeatmapData, 300000) // 5 minutes
      }
    })

    return {
      heatmapContainer,
      loading,
      selectedTimeRange,
      selectedTactic,
      selectedTechnique,
      availableTactics,
      legendLevels,
      visibleTechniques,
      visibleTactics,
      totalTechniques,
      activeTactics,
      totalDetections,
      topTechnique,
      loadHeatmapData,
      getTechniqueCellStyle,
      getTechniqueCellClass,
      getTechniqueTooltip,
      selectTechnique,
      filterByTactic,
      truncateName,
      formatDate,
      filterByTactic
    }
  }
}
</script>

<style scoped>
.mitre-heatmap {
  background: white;
  border-radius: 8px;
  padding: 20px;
  height: 100%;
}

.heatmap-controls {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
  flex-wrap: wrap;
  gap: 15px;
}

.control-group {
  display: flex;
  gap: 10px;
}

.time-select, .tactic-select {
  padding: 8px 12px;
  border: 1px solid #ddd;
  border-radius: 4px;
  background: white;
  font-size: 14px;
}

.legend {
  display: flex;
  align-items: center;
  gap: 10px;
}

.legend-label {
  font-weight: bold;
  color: #2f3542;
}

.legend-scale {
  display: flex;
  gap: 8px;
}

.legend-item {
  display: flex;
  align-items: center;
  gap: 4px;
  font-size: 12px;
}

.color-box {
  width: 16px;
  height: 16px;
  border-radius: 2px;
  border: 1px solid #ddd;
}

.heatmap-container {
  position: relative;
  min-height: 400px;
  border: 1px solid #eee;
  border-radius: 4px;
}

.loading-overlay {
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(255, 255, 255, 0.9);
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  z-index: 10;
}

.loading-spinner {
  width: 40px;
  height: 40px;
  border: 4px solid #f3f3f3;
  border-top: 4px solid #3498db;
  border-radius: 50%;
  animation: spin 1s linear infinite;
  margin-bottom: 10px;
}

@keyframes spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}

.tactics-header {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
  gap: 2px;
  background: #f8f9fa;
  padding: 10px;
  border-bottom: 1px solid #dee2e6;
}

.tactic-column {
  font-weight: bold;
  font-size: 12px;
  text-align: center;
  padding: 8px 4px;
  background: #e9ecef;
  border-radius: 3px;
  cursor: help;
  color: #495057;
}

.techniques-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
  gap: 2px;
  padding: 10px;
}

.technique-cell {
  border: 1px solid #dee2e6;
  border-radius: 4px;
  padding: 8px;
  min-height: 80px;
  cursor: pointer;
  transition: all 0.2s ease;
  display: flex;
  flex-direction: column;
  justify-content: space-between;
  position: relative;
}

.technique-cell:hover {
  border-color: #007bff;
  transform: translateY(-2px);
  box-shadow: 0 4px 8px rgba(0,0,0,0.1);
}

.technique-cell.has-detections {
  cursor: pointer;
}

.technique-cell.selected {
  border-color: #007bff;
  box-shadow: 0 0 0 2px rgba(0,123,255,0.25);
}

.technique-id {
  font-weight: bold;
  font-size: 11px;
  color: #6c757d;
  margin-bottom: 4px;
}

.technique-name {
  font-size: 12px;
  line-height: 1.3;
  color: #1d2022ff;
  flex-grow: 1;
}

.technique-count {
  position: absolute;
  top: 4px;
  right: 4px;
  background: #dc3545;
  color: white;
  border-radius: 50%;
  width: 20px;
  height: 20px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 10px;
  font-weight: bold;
}

.technique-details {
  margin-top: 20px;
  background: #f8f9fa;
  border: 1px solid #dee2e6;
  border-radius: 8px;
  overflow: hidden;
}

.details-header {
  background: #007bff;
  color: white;
  padding: 15px 20px;
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.details-header h4 {
  margin: 0;
  font-size: 16px;
}

.close-btn {
  background: none;
  border: none;
  color: white;
  font-size: 24px;
  cursor: pointer;
  padding: 0;
  width: 30px;
  height: 30px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: background-color 0.2s;
}

.close-btn:hover {
  background-color: rgba(255,255,255,0.2);
}

.details-content {
  padding: 20px;
}

.detail-section {
  margin-bottom: 15px;
  line-height: 1.5;
}

.detail-section strong {
  color: #495057;
  display: inline-block;
  margin-bottom: 5px;
}

.indicators-list {
  list-style: none;
  padding: 0;
  margin: 0;
}

.indicators-list li {
  padding: 4px 8px;
  background: white;
  border: 1px solid #dee2e6;
  border-radius: 4px;
  margin-bottom: 4px;
  font-family: monospace;
  font-size: 12px;
}

.heatmap-stats {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 15px;
  margin-top: 20px;
  padding-top: 20px;
  border-top: 1px solid #dee2e6;
}

.stat-item {
  text-align: center;
  padding: 15px;
  background: #f8f9fa;
  border-radius: 8px;
  border: 1px solid #e9ecef;
}

.stat-value {
  font-size: 24px;
  font-weight: bold;
  color: #007bff;
  margin-bottom: 5px;
}

.stat-label {
  font-size: 12px;
  color: #6c757d;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

/* Responsive design */
@media (max-width: 768px) {
  .heatmap-controls {
    flex-direction: column;
    align-items: stretch;
  }
  
  .control-group {
    justify-content: center;
  }
  
  .legend {
    justify-content: center;
  }
  
  .techniques-grid {
    grid-template-columns: repeat(auto-fill, minmax(120px, 1fr));
  }
  
  .heatmap-stats {
    grid-template-columns: repeat(2, 1fr);
  }
}

@media (max-width: 480px) {
  .heatmap-stats {
    grid-template-columns: 1fr;
  }
  
  .tactics-header {
    grid-template-columns: repeat(auto-fit, minmax(80px, 1fr));
  }
  
  .tactic-column {
    font-size: 10px;
    padding: 6px 2px;
  }
}</style>