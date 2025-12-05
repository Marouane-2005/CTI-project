<template>
  <div style="min-height: 100vh; background: linear-gradient(135deg, #0f172a 0%, #581c87 50%, #0f172a 100%); display: flex; align-items: center; justify-content: center; padding: 1rem;">
    <!-- Pattern de fond -->
    <div style="position: absolute; top: 0; left: 0; right: 0; bottom: 0; opacity: 0.2;" :style="backgroundPattern"></div>
    
    <div style="position: relative; width: 100%; max-width: 28rem;">
      <div style="background: rgba(255, 255, 255, 0.1); backdrop-filter: blur(12px); border-radius: 1rem; padding: 2rem; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25); border: 1px solid rgba(255, 255, 255, 0.2);">
        <!-- Header -->
        <div style="text-align: center; margin-bottom: 2rem;">
          <div style="display: inline-flex; align-items: center; justify-content: center; width: 4rem; height: 4rem; background: linear-gradient(135deg, #8b5cf6, #3b82f6); border-radius: 50%; margin-bottom: 1rem;">
            <svg style="width: 2rem; height: 2rem; color: white;" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
            </svg>
          </div>
          <h1 style="font-size: 1.5rem; font-weight: bold; color: white; margin-bottom: 0.5rem;">CTI Dashboard</h1>
          <p style="color: #d1d5db; font-size: 0.875rem;">Cyber Threat Intelligence Platform</p>
        </div>

        <!-- Messages de statut -->
        <div v-if="loginStatus === 'success'" style="margin-bottom: 1.5rem; padding: 0.75rem; background: rgba(34, 197, 94, 0.2); border: 1px solid rgba(34, 197, 94, 0.3); border-radius: 0.5rem; display: flex; align-items: center; gap: 0.5rem;">
          <svg style="width: 1.25rem; height: 1.25rem; color: #4ade80;" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
          </svg>
          <span style="color: #86efac; font-size: 0.875rem;">Connexion réussie ! Redirection...</span>
        </div>
        
        <div v-if="loginStatus === 'error'" style="margin-bottom: 1.5rem; padding: 0.75rem; background: rgba(239, 68, 68, 0.2); border: 1px solid rgba(239, 68, 68, 0.3); border-radius: 0.5rem; display: flex; align-items: center; gap: 0.5rem;">
          <svg style="width: 1.25rem; height: 1.25rem; color: #f87171;" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
          </svg>
          <span style="color: #fca5a5; font-size: 0.875rem;">{{ errorMessage }}</span>
        </div>

        <!-- Formulaire -->
        <form @submit.prevent="handleLogin" style="display: flex; flex-direction: column; gap: 1.5rem;">
          <div>
            <label for="username" style="display: block; font-size: 0.875rem; font-weight: 500; color: #d1d5db; margin-bottom: 0.5rem;">
              Nom d'utilisateur
            </label>
            <input
              v-model="credentials.username"
              type="text"
              id="username"
              style="width: 100%; padding: 0.75rem 1rem; background: rgba(255, 255, 255, 0.1); border: 1px solid rgba(255, 255, 255, 0.2); border-radius: 0.5rem; color: white; transition: all 0.2s;"
              placeholder="Entrez votre nom d'utilisateur"
              required
            />
          </div>

          <div>
            <label for="password" style="display: block; font-size: 0.875rem; font-weight: 500; color: #d1d5db; margin-bottom: 0.5rem;">
              Mot de passe
            </label>
            <div style="position: relative;">
              <input
                v-model="credentials.password"
                :type="showPassword ? 'text' : 'password'"
                id="password"
                style="width: 100%; padding: 0.75rem 3rem 0.75rem 1rem; background: rgba(255, 255, 255, 0.1); border: 1px solid rgba(255, 255, 255, 0.2); border-radius: 0.5rem; color: white; transition: all 0.2s;"
                placeholder="Entrez votre mot de passe"
                required
              />
              <button
                type="button"
                @click="showPassword = !showPassword"
                style="position: absolute; right: 0.75rem; top: 50%; transform: translateY(-50%); color: #9ca3af; background: none; border: none; cursor: pointer; transition: color 0.2s;"
              >
                <svg v-if="showPassword" style="width: 1.25rem; height: 1.25rem;" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.878 9.878L3 3m6.878 6.878L21 21"/>
                </svg>
                <svg v-else style="width: 1.25rem; height: 1.25rem;" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/>
                </svg>
              </button>
            </div>
          </div>

          <div style="display: flex; align-items: center; justify-content: space-between; font-size: 0.875rem;">
            <label style="display: flex; align-items: center; color: #d1d5db; cursor: pointer;">
              <input
                v-model="rememberMe"
                type="checkbox"
                style="margin-right: 0.5rem; accent-color: #8b5cf6;"
              />
              Se souvenir de moi
            </label>
            <a href="#" style="color: #c084fc; text-decoration: none; transition: color 0.2s;" @mouseover="$event.target.style.color='#a855f7'" @mouseout="$event.target.style.color='#c084fc'">
              Mot de passe oublié ?
            </a>
          </div>

          <button
            type="submit"
            :disabled="isLoading || loginStatus === 'success'"
            style="width: 100%; padding: 0.75rem; background: linear-gradient(135deg, #8b5cf6, #3b82f6); color: white; font-weight: 500; border-radius: 0.5rem; border: none; cursor: pointer; transition: all 0.2s; display: flex; align-items: center; justify-content: center; gap: 0.5rem;"
            :style="{ opacity: (isLoading || loginStatus === 'success') ? 0.6 : 1, cursor: (isLoading || loginStatus === 'success') ? 'not-allowed' : 'pointer' }"
          >
            <div v-if="isLoading" style="width: 1.25rem; height: 1.25rem; border: 2px solid rgba(255, 255, 255, 0.3); border-top: 2px solid white; border-radius: 50%; animation: spin 1s linear infinite;"></div>
            <span>{{ isLoading ? 'Connexion...' : 'Se connecter' }}</span>
          </button>
        </form>

        <div style="margin-top: 2rem; text-align: center;">
          <p style="color: #9ca3af; font-size: 0.75rem;">
            Accès sécurisé au tableau de bord CTI
          </p>
        </div>
      </div>

      <div style="margin-top: 1.5rem; text-align: center;">
        <div style="display: inline-flex; align-items: center; gap: 0.5rem; color: #9ca3af; font-size: 0.75rem;">
          <svg style="width: 1rem; height: 1rem;" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
          </svg>
          <span>Connexion sécurisée SSL/TLS</span>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import { ref, computed } from 'vue'
import { useStore } from 'vuex'
import { useRouter } from 'vue-router'

export default {
  name: 'LoginView',
  setup() {
    const store = useStore()
    const router = useRouter()
    
    const credentials = ref({
      username: '',
      password: ''
    })
    
    const rememberMe = ref(false)
    const showPassword = ref(false)
    const isLoading = ref(false)
    const loginStatus = ref(null)
    const errorMessage = ref('')

    // Pattern de fond en tant que propriété calculée
    const backgroundPattern = computed(() => ({
      backgroundImage: `url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%239C92AC' fill-opacity='0.1'%3E%3Ccircle cx='30' cy='30' r='4'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E")`
    }))

    const handleLogin = async () => {
      if (isLoading.value) return
      
      isLoading.value = true
      loginStatus.value = null
      errorMessage.value = ''

      try {
        const result = await store.dispatch('login', {
          credentials: credentials.value,
          rememberMe: rememberMe.value
        })

        if (result.success) {
          loginStatus.value = 'success'
          setTimeout(() => {
            router.push('/')
          }, 1500)
        } else {
          loginStatus.value = 'error'
          errorMessage.value = result.error || 'Erreur de connexion'
        }
      } catch (error) {
        loginStatus.value = 'error'
        errorMessage.value = error.message || 'Une erreur inattendue s\'est produite'
      } finally {
        isLoading.value = false
      }
    }

    return {
      credentials,
      rememberMe,
      showPassword,
      isLoading,
      loginStatus,
      errorMessage,
      backgroundPattern,
      handleLogin
    }
  }
}
</script>

<style scoped>
@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}

input:focus {
  outline: none;
  box-shadow: 0 0 0 2px #8b5cf6;
}

button:hover:not(:disabled) {
  background: linear-gradient(135deg, #7c3aed, #2563eb);
  transform: scale(1.02);
}
</style>