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
          path: '/sast/config',
          name: 'SastScanConfig',
          component: () => import('../views/sast/ScanConfig.vue'),
        },
        {
          path: '/sast/tasks',
          name: 'SastTasks',
          component: () => import('../views/sast/ScanTasks.vue'),
        },
        {
          path: '/dast/tasks',
          name: 'DastTasks',
          component: () => import('../views/dast/TaskList.vue'),
        },
        {
          path: '/dast/history',
          name: 'DastHistory',
          component: () => import('../views/dast/DastHistory.vue'),
        },
        {
          path: '/dast/tasks/:id',
          name: 'DastTaskDetail',
          component: () => import('../views/dast/TaskDetail.vue'),
        },
        {
          path: '/sca/tasks',
          name: 'ScaTasks',
          component: () => import('../views/sca/ScaTasks.vue'),
        },
      ],
    },
  ],
})

export default router
