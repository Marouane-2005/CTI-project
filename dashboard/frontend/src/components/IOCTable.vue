<template>
  <div class="ioc-table">
    <div class="table-header">
      <h3>IOCs Récents</h3>
      <div class="filters">
        <select v-model="selectedType" @change="filterIOCs">
          <option value="all">Tous les types</option>
          <option value="ip">Adresses IP</option>
          <option value="domain">Domaines</option>
          <option value="url">URLs</option>
          <option value="hash">Hash</option>
          <option value="email">Emails</option>
        </select>
        <select v-model="selectedRiskLevel" @change="filterIOCs">
          <option value="all">Tous niveaux</option>
          <option value="critical">Critique (8-10)</option>
          <option value="high">Élevé (6-7)</option>
          <option value="medium">Moyen (4-5)</option>
          <option value="low">Faible (0-3)</option>
        </select>
      </div>
    </div>

    <div class="table-container">
      <table class="ioc-data-table">
        <thead>
          <tr>
            <th>Indicateur</th>
            <th>Type</th>
            <th>Source</th>
            <th>Risque</th>
            <th>Détecté</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="ioc in filteredIOCs" :key="ioc.id" :class="getRiskClass(ioc.risk_score)">
            <td class="indicator-cell">
              <span class="indicator-value" @click="copyToClipboard(ioc.value)">
                {{ truncateText(ioc.value, 40) }}
              </span>
              <span class="copy-icon" v-if="ioc.value.length > 40" title="Copier">📋</span>
            </td>
            <td>
              <span class="type-badge" :class="ioc.type">
                {{ ioc.type.toUpperCase() }}
              </span>
            </td>
            <td class="source-cell">{{ ioc.source }}</td>
            <td class="risk-cell">
              <div class="risk-indicator">
                <span class="risk-score">{{ ioc.risk_score.toFixed(1) }}</span>
                <div class="risk-bar">
                  <div class="risk-fill" :style="{ width: (ioc.risk_score * 10) + '%' }"></div>
                </div>
              </div>
            </td>
            <td class="timestamp-cell">{{ formatTime(ioc.created_at) }}</td>
            <td class="actions-cell">
              <button @click="viewDetails(ioc)" class="btn-action" title="Détails">
                👁️
              </button>
              <button @click="enrichIOC(ioc)" class="btn-action" title="Enrichir">
                🔍
              </button>
            </td>
          </tr>
        </tbody>
      </table>

      <div v-if="filteredIOCs.length === 0" class="no-data">
        <p>Aucun IOC trouvé avec les critères sélectionnés</p>
      </div>
    </div>

    <!-- Modal de détails -->
    <div v-if="showModal" class="modal-overlay" @click="closeModal">
      <div class="modal-content" @click.stop>
        <h4>Détails de l'IOC</h4>
        <div v-if="selectedIOC" class="ioc-details">
          <div class="detail-row">
            <strong>Indicateur:</strong> {{ selectedIOC.value }}
          </div>
          <div class="detail-row">
            <strong>Type:</strong> {{ selectedIOC.type }}
          </div>
          <div class="detail-row">
            <strong>Source:</strong> {{ selectedIOC.source }}
          </div>
          <div class="detail-row">
            <strong>Score de risque:</strong> {{ selectedIOC.risk_score }}/10
          </div>
          <div class="detail-row">
            <strong>Techniques MITRE:</strong> 
            <span v-if="selectedIOC.mitre_techniques && selectedIOC.mitre_techniques.length > 0">
              {{ selectedIOC.mitre_techniques.join(', ') }}
            </span>
            <span v-else>Aucune</span>
          </div>
          <div class="detail-row">
            <strong>Enrichissements:</strong>
            <pre v-if="selectedIOC.enrichments">{{ JSON.stringify(selectedIOC.enrichments, null, 2) }}</pre>
            <span v-else>Aucun enrichissement disponible</span>
          </div>
        </div>
        <button @click="closeModal" class="btn-close">Fermer</button>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  name: 'IOCTable',
  props: {
    iocs: {
      type: Array,
      default: () => []
    }
  },
  data() {
    return {
      selectedType: 'all',
      selectedRiskLevel: 'all',
      filteredIOCs: [],
      showModal: false,
      selectedIOC: null
    }
  },
  watch: {
    iocs: {
      handler(newIOCs) {
        this.filteredIOCs = [...newIOCs];
        this.filterIOCs();
      },
      immediate: true,
      deep: true
    }
  },
  methods: {
    filterIOCs() {
      let filtered = [...this.iocs];

      // Filtrage par type
      if (this.selectedType !== 'all') {
        filtered = filtered.filter(ioc => ioc.type === this.selectedType);
      }

      // Filtrage par niveau de risque
      if (this.selectedRiskLevel !== 'all') {
        switch (this.selectedRiskLevel) {
          case 'critical':
            filtered = filtered.filter(ioc => ioc.risk_score >= 8);
            break;
          case 'high':
            filtered = filtered.filter(ioc => ioc.risk_score >= 6 && ioc.risk_score < 8);
            break;
          case 'medium':
            filtered = filtered.filter(ioc => ioc.risk_score >= 4 && ioc.risk_score < 6);
            break;
          case 'low':
            filtered = filtered.filter(ioc => ioc.risk_score < 4);
            break;
        }
      }

      this.filteredIOCs = filtered;
    },

    getRiskClass(riskScore) {
      if (riskScore >= 8) return 'risk-critical';
      if (riskScore >= 6) return 'risk-high';
      if (riskScore >= 4) return 'risk-medium';
      return 'risk-low';
    },

    formatTime(timestamp) {
      const date = new Date(timestamp);
      return date.toLocaleString('fr-FR', {
        day: '2-digit',
        month: '2-digit',
        hour: '2-digit',
        minute: '2-digit'
      });
    },

    truncateText(text, maxLength) {
      if (text.length <= maxLength) return text;
      return text.substring(0, maxLength) + '...';
    },

    copyToClipboard(text) {
      navigator.clipboard.writeText(text).then(() => {
        // Vous pouvez ajouter une notification de succès ici
        console.log('IOC copié dans le presse-papiers');
      });
    },

    viewDetails(ioc) {
      this.selectedIOC = ioc;
      this.showModal = true;
    },

    closeModal() {
      this.showModal = false;
      this.selectedIOC = null;
    },

    enrichIOC(ioc) {
      // Émission d'un événement pour enrichir l'IOC
      this.$emit('enrich-ioc', ioc);
    }
  }
}
</script>

<style scoped>
.ioc-table {
  background: white;
  border-radius: 8px;
  box-shadow: 0 2px 10px rgba(0,0,0,0.1);
  overflow: hidden;
}

.table-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 20px;
  background: #f8f9fa;
  border-bottom: 1px solid #eee;
}

.table-header h3 {
  margin: 0;
  color: #2f3542;
}

.filters {
  display: flex;
  gap: 10px;
}

.filters select {
  padding: 8px 12px;
  border: 1px solid #ddd;
  border-radius: 4px;
  background: white;
}

.table-container {
  max-height: 500px;
  overflow-y: auto;
}

.ioc-data-table {
  width: 100%;
  border-collapse: collapse;
}

.ioc-data-table th {
  background: #f1f2f6;
  padding: 12px;
  text-align: left;
  font-weight: 600;
  color: #2f3542;
  border-bottom: 2px solid #ddd;
  position: sticky;
  top: 0;
  z-index: 10;
}

.ioc-data-table td {
  padding: 12px;
  border-bottom: 1px solid #eee;
}

.ioc-data-table tr:hover {
  background: #f8f9fa;
}

/* Classes de risque */
.risk-critical {
  border-left: 4px solid #ff4757;
}

.risk-high {
  border-left: 4px solid #ff6b35;
}

.risk-medium {
  border-left: 4px solid #ffa502;
}

.risk-low {
  border-left: 4px solid #26de81;
}

.indicator-cell {
  font-family: monospace;
  position: relative;
}

.indicator-value {
  cursor: pointer;
}

.indicator-value:hover {
  background: #e1e8ed;
  border-radius: 3px;
}

.copy-icon {
  margin-left: 5px;
  cursor: pointer;
  opacity: 0.6;
}

.type-badge {
  padding: 4px 8px;
  border-radius: 12px;
  font-size: 0.8em;
  font-weight: bold;
  text-transform: uppercase;
}

.type-badge.ip {
  background: #e1f5fe;
  color: #01579b;
}

.type-badge.domain {
  background: #f3e5f5;
  color: #4a148c;
}

.type-badge.url {
  background: #e8f5e8;
  color: #1b5e20;
}

.type-badge.hash {
  background: #fff3e0;
  color: #e65100;
}

.type-badge.email {
  background: #fce4ec;
  color: #880e4f;
}

.risk-indicator {
  display: flex;
  align-items: center;
  gap: 8px;
}

.risk-score {
  font-weight: bold;
  min-width: 30px;
}

.risk-bar {
  flex: 1;
  height: 8px;
  background: #eee;
  border-radius: 4px;
  overflow: hidden;
}

.risk-fill {
  height: 100%;
  background: linear-gradient(90deg, #26de81, #ffa502, #ff6b35, #ff4757);
  transition: width 0.3s ease;
}

.actions-cell {
  text-align: center;
}

.btn-action {
  background: none;
  border: none;
  cursor: pointer;
  font-size: 16px;
  padding: 4px;
  margin: 0 2px;
  border-radius: 3px;
}

.btn-action:hover {
  background: #f0f0f0;
}

.no-data {
  text-align: center;
  padding: 40px;
  color: #666;
}

/* Modal */
.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0,0,0,0.5);
  display: flex;
  justify-content: center;
  align-items: center;
  z-index: 1000;
}

.modal-content {
  background: white;
  border-radius: 8px;
  padding: 20px;
  max-width: 600px;
  max-height: 80vh;
  overflow-y: auto;
  width: 90%;
}

.ioc-details {
  margin: 20px 0;
}

.detail-row {
  margin: 10px 0;
  padding: 8px 0;
  border-bottom: 1px solid #eee;
}

.detail-row strong {
  display: inline-block;
  min-width: 150px;
}

.detail-row pre {
  background: #f5f5f5;
  padding: 10px;
  border-radius: 4px;
  overflow-x: auto;
  font-size: 0.9em;
  margin: 5px 0;
}

.btn-close {
  background: #007bff;
  color: white;
  border: none;
  padding: 10px 20px;
  border-radius: 4px;
  cursor: pointer;
}

.btn-close:hover {
  background: #0056b3;
}
</style>