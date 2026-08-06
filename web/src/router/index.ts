import { createRouter, createWebHistory } from 'vue-router'
import MainLayout from '../layout/MainLayout.vue'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/',
      component: MainLayout,
      redirect: '/dashboard',
      children: [
        {
          path: '/dashboard',
          name: 'Dashboard',
          component: () => import('../views/Dashboard.vue'),
        },
        {
          path: '/sast/repos',
          name: 'SastRepos',
          component: () => import('../views/sast/RepoList.vue'),
        },
        {
          path: '/sast/tasks',
          name: 'SastTasks',
          component: () => import('../views/sast/ScanTasks.vue'),
        },
        {
          path: '/sast/configs',
          name: 'SastConfigs',
          component: () => import('../views/sast/ConfigList.vue'),
        },
        {
          path: '/dast/configs',
          name: 'DastConfigs',
          component: () => import('../views/dast/ConfigList.vue'),
        },
        {
          path: '/dast/tasks',
          name: 'DastTasks',
          component: () => import('../views/dast/TaskList.vue'),
        },
        {
          path: '/dast/history',
          redirect: '/dast/tasks',
        },
        {
          path: '/dast/pocs',
          name: 'DastPocs',
          component: () => import('../views/dast/PocList.vue'),
        },
        {
          path: '/dast/cves',
          name: 'DastCves',
          component: () => import('../views/dast/CveList.vue'),
        },
        {
          path: '/dast/tasks/:id',
          name: 'DastTaskDetail',
          component: () => import('../views/dast/TaskDetail.vue'),
        },
        {
          path: '/sca/projects',
          name: 'ScaProjects',
          component: () => import('../views/sca/ProjectList.vue'),
        },
        {
          path: '/sca/vulnerabilities',
          name: 'ScaVulnerabilities',
          component: () => import('../views/sca/VulnerabilityList.vue'),
        },
      ],
    },
  ],
})

export default router
