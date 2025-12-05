import { createRouter, createWebHistory } from 'vue-router'

// Import des vues
import Overview from '@/views/Overview.vue'
import Intelligence from '@/views/Intelligence.vue' 
import Threats from '@/views/Threats.vue'
import Reports from '@/views/Reports.vue'

// Routes de l'application
const routes = [
  {
    path: '/',
    name: 'Overview',
    component: Overview,
    meta: { 
      title: 'Tableau de bord',
      icon: 'dashboard',
      requiresAuth: false
    }
  },
  {
    path: '/intelligence',
    name: 'Intelligence', 
    component: Intelligence,
    meta: { 
      title: 'Intelligence',
      icon: 'brain',
      requiresAuth: false
    }
  },
  {
    path: '/threats',
    name: 'Threats',
    component: Threats,
    meta: { 
      title: 'Menaces',
      icon: 'shield-alert',
      requiresAuth: false
    }
  },
  {
    path: '/reports',
    name: 'Reports',
    component: Reports,
    meta: { 
      title: 'Rapports',
      icon: 'file-text',
      requiresAuth: false
    }
  },
  {
    path: '/mitre',
    name: 'Mitre',
    component: () => import('@/views/MitreView.vue'),
    meta: { 
      title: 'MITRE ATT&CK',
      icon: 'target',
      requiresAuth: false
    }
  },
  {
    path: '/iocs',
    name: 'IOCs',
    component: () => import('@/views/IOCsView.vue'),
    meta: { 
      title: 'Indicateurs',
      icon: 'search',
      requiresAuth: false
    }
  },
  {
    path: '/alerts',
    name: 'Alerts',
    component: () => import('@/views/AlertsView.vue'),
    meta: { 
      title: 'Alertes',
      icon: 'bell',
      requiresAuth: false
    }
  },
  {
    path: '/settings',
    name: 'Settings',
    component: () => import('@/views/SettingsView.vue'),
    meta: { 
      title: 'Paramètres',
      icon: 'settings',
      requiresAuth: false
    }
  },
  // Route pour les détails d'une menace
  {
    path: '/threats/:id',
    name: 'ThreatDetails',
    component: () => import('@/views/ThreatDetailsView.vue'),
    meta: { 
      title: 'Détail menace',
      requiresAuth: false
    },
    props: true
  },
  // Route pour les détails d'une alerte
  {
    path: '/alerts/:id',
    name: 'AlertDetails',
    component: () => import('@/views/AlertDetailsView.vue'),
    meta: { 
      title: 'Détail alerte',
      requiresAuth: false
    },
    props: true
  },
  // Route pour les détails d'un IOC
  {
    path: '/iocs/:id',
    name: 'IOCDetails',
    component: () => import('@/views/IOCDetailsView.vue'),
    meta: { 
      title: 'Détail IOC',
      requiresAuth: false
    },
    props: true
  },
  // Route 404
  {
    path: '/:pathMatch(.*)*',
    name: 'NotFound',
    component: () => import('@/views/NotFoundView.vue'),
    meta: { 
      title: 'Page non trouvée'
    }
  }
]

const router = createRouter({
  history: createWebHistory(process.env.BASE_URL),
  routes,
  scrollBehavior(to, from, savedPosition) {
    if (savedPosition) {
      return savedPosition
    } else {
      return { top: 0 }
    }
  }
})

// Navigation guard pour les titres de page
router.beforeEach((to, from, next) => {
  // Mise à jour du titre de la page
  if (to.meta.title) {
    document.title = `${to.meta.title} - CTI Dashboard`
  } else {
    document.title = 'CTI Dashboard'
  }
  
  // Ici vous pouvez ajouter la logique d'authentification si nécessaire
  // if (to.meta.requiresAuth && !isAuthenticated()) {
  //   next('/login')
  //   return
  // }
  
  next()
})

// Navigation guard après navigation
router.afterEach((to, from) => {
  // Analytics ou logging de navigation
  console.log(`Navigation: ${from.name} -> ${to.name}`)
})

export default router

// Export utilitaire pour obtenir les routes de navigation
export const getNavigationRoutes = () => {
  return routes.filter(route => 
    route.meta && 
    route.meta.title && 
    route.meta.icon && 
    !route.path.includes(':')
  )
}