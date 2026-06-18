<template>
  <a-layout class="min-h-screen">
    <!-- Premium Light Sidebar - Shadcn Light style -->
    <a-layout-sider
      width="240"
      class="border-r border-zinc-200"
      :style="{ background: '#ffffff', position: 'fixed', height: '100vh', left: 0, zIndex: 100 }"
    >
      <!-- Logo Brand -->
      <div class="flex h-16 items-center gap-2.5 px-6 border-b border-zinc-200 bg-[#ffffff] overflow-hidden">
        <div class="flex items-center justify-center w-7 h-7 rounded-md bg-zinc-950 text-white shadow-sm">
          <SafetyCertificateOutlined class="text-base font-bold" />
        </div>
        <span class="text-zinc-900 font-bold text-base tracking-tight">
          DevSecOps
        </span>
      </div>

      <!-- Navigation Menu (theme="light" & inline mode) -->
      <a-menu
        v-model:selectedKeys="selectedKeys"
        v-model:openKeys="openKeys"
        theme="light"
        mode="inline"
        class="border-none bg-transparent pt-4"
        :style="{ background: 'transparent' }"
      >
        <a-menu-item key="Dashboard" @click="navigate('Dashboard')">
          <template #icon><DashboardOutlined /></template>
          <span>概览</span>
        </a-menu-item>

        <a-sub-menu key="sast" title="SAST 静态扫描">
          <template #icon><CodeOutlined /></template>
          <a-menu-item key="SastScanConfig" @click="navigate('SastScanConfig')">
            Codeql 配置
          </a-menu-item>
          <a-menu-item key="SastTasks" @click="navigate('SastTasks')">
            任务列表
          </a-menu-item>
        </a-sub-menu>

        <a-sub-menu key="dast" title="DAST 动态扫描">
          <template #icon><RadarChartOutlined /></template>
          <a-menu-item key="DastTasks" @click="navigate('DastTasks')">
            扫描任务配置
          </a-menu-item>
          <a-menu-item key="DastHistory" @click="navigate('DastHistory')">
            任务列表
          </a-menu-item>
          <a-menu-item key="DastPocs" @click="navigate('DastPocs')">
            PoC 模板管理
          </a-menu-item>
        </a-sub-menu>
      </a-menu>
    </a-layout-sider>

    <!-- Main Content Area -->
    <a-layout :style="{ marginLeft: '240px', transition: 'all 0.2s', background: '#ffffff', height: '100vh', display: 'flex', flexDirection: 'column', minWidth: 0 }">
      <!-- Shadcn Light Header -->
      <a-layout-header 
        class="flex h-16 items-center justify-between px-8 border-b border-zinc-200 bg-[#ffffff] shrink-0"
        :style="{ padding: '0 24px' }"
      >
        <div class="flex items-center">
          <a-breadcrumb class="text-zinc-500 font-medium">
            <a-breadcrumb-item class="text-zinc-400">平台首页</a-breadcrumb-item>
            <a-breadcrumb-item class="text-zinc-800 font-semibold">{{ currentRouteName }}</a-breadcrumb-item>
          </a-breadcrumb>
        </div>

        <div class="flex items-center gap-6">
          <a-badge dot class="cursor-pointer">
            <BellOutlined class="text-lg text-zinc-500 hover:text-zinc-900 transition-colors" />
          </a-badge>
          <div class="h-4 w-px bg-zinc-200"></div>
          <div class="flex items-center gap-3 cursor-pointer group">
            <a-avatar class="bg-zinc-100 text-zinc-800 border border-zinc-200 font-bold" size="small">A</a-avatar>
            <span class="text-sm font-medium text-zinc-600 group-hover:text-zinc-900 transition-colors">wsh</span>
          </div>
        </div>
      </a-layout-header>

      <!-- Main Router view -->
      <a-layout-content class="p-6 bg-[#ffffff] flex-1 overflow-y-auto overflow-x-hidden">
        <router-view v-slot="{ Component }">
          <transition name="fade-transform" mode="out-in">
            <component :is="Component" />
          </transition>
        </router-view>
      </a-layout-content>
    </a-layout>
  </a-layout>
</template>

<script setup lang="ts">
import { ref, watch, computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import {
  SafetyCertificateOutlined,
  DashboardOutlined,
  CodeOutlined,
  RadarChartOutlined,
  BellOutlined
} from '@ant-design/icons-vue'

const route = useRoute()
const router = useRouter()

const collapsed = ref(false)
const selectedKeys = ref<string[]>(['Dashboard'])
const openKeys = ref<string[]>(['sast', 'dast'])

// Keep selectedKeys in sync with active route name
watch(
  () => route.name,
  (newName) => {
    if (newName) {
      selectedKeys.value = [newName.toString()]
    }
  },
  { immediate: true }
)

const currentRouteName = computed(() => {
  const map: Record<string, string> = {
    Dashboard: '概览',
    SastScanConfig: 'Codeql 配置',
    SastTasks: '任务列表',
    SastTaskDetail: '扫描详情与日志',
    DastTasks: '扫描任务配置',
    DastHistory: '任务列表',
    DastPocs: 'PoC 模板管理',
    DastTaskDetail: '动态扫描详情'
  }
  return map[route.name as string] || route.name || '页面'
})

const navigate = (name: string) => {
  router.push({ name })
}
</script>

<style>
/* Smooth Route Transition */
.fade-transform-enter-active,
.fade-transform-leave-active {
  transition: all 0.15s ease-out;
}

.fade-transform-enter-from {
  opacity: 0;
  transform: translateX(-10px);
}

.fade-transform-leave-to {
  opacity: 0;
  transform: translateX(10px);
}
</style>
