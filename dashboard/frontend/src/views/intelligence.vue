<template>
  <div class="intelligence-view">
    <div class="container-fluid">
      <h2><i class="fas fa-brain"></i> Intelligence CTI</h2>
      
      <div class="row mt-4">
        <!-- Recherche IOCs -->
        <div class="col-md-6">
          <div class="card">
            <div class="card-header">
              <h5><i class="fas fa-search"></i> Recherche IOCs</h5>
            </div>
            <div class="card-body">
              <div class="mb-3">
                <input 
                  type="text" 
                  class="form-control" 
                  placeholder="IP, domaine, hash..."
                  v-model="searchQuery"
                  @keyup.enter="searchIOCs"
                >
              </div>
              <button class="btn btn-primary" @click="searchIOCs">
                <i class="fas fa-search"></i> Rechercher
              </button>
            </div>
          </div>
        </div>
        
        <!-- Résultats -->
        <div class="col-md-6">
          <div class="card">
            <div class="card-header">
              <h5><i class="fas fa-list"></i> Résultats</h5>
            </div>
            <div class="card-body">
              <div v-if="loading" class="text-center">
                <div class="spinner-border" role="status"></div>
              </div>
              <div v-else-if="results.length === 0" class="text-muted">
                Aucun résultat
              </div>
              <div v-else>
                <div v-for="result in results" :key="result.id" class="mb-2">
                  <small class="badge bg-info">{{ result.type }}</small>
                  {{ result.value }}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import { ref } from 'vue'
import { dashboardAPI } from '@/services/api'

export default {
  name: 'Intelligence',
  setup() {
    const searchQuery = ref('')
    const results = ref([])
    const loading = ref(false)
    
    const searchIOCs = async () => {
      if (!searchQuery.value.trim()) return
      
      try {
        loading.value = true
        const response = await dashboardAPI.searchIOCs({
          query: searchQuery.value.trim()
        })
        results.value = response.indicators || []
      } catch (error) {
        console.error('Erreur recherche:', error)
        results.value = []
      } finally {
        loading.value = false
      }
    }
    
    return {
      searchQuery,
      results,
      loading,
      searchIOCs
    }
  }
}
</script>
