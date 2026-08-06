<template>
  <a-layout class="min-h-screen">
    <a-layout-sider
      width="240"
      class="border-r border-zinc-200"
      :style="{ background: '#ffffff', position: 'fixed', height: '100vh', left: 0, zIndex: 100 }"
    >
      <div class="flex h-16 items-center justify-between border-b border-zinc-200 bg-white px-5">
        <div class="flex items-center gap-2">
          <div class="flex h-7 w-7 items-center justify-center rounded-md bg-zinc-950 text-white shadow-sm">
            <SafetyCertificateOutlined class="text-base font-bold" />
          </div>
          <span class="text-base font-bold tracking-tight text-zinc-900">
            DevSecOps
          </span>
        </div>
        <span class="rounded bg-emerald-100 px-1.5 py-0.5 text-[11px] font-bold text-emerald-800 border border-emerald-300">
          v1.3.3
        </span>
      </div>

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
          <a-menu-item key="SastRepos" @click="navigate('SastRepos')">
            代码仓库
          </a-menu-item>
          <a-menu-item key="SastConfigs" @click="navigate('SastConfigs')">
            扫描配置
          </a-menu-item>
          <a-menu-item key="SastTasks" @click="navigate('SastTasks')">
            任务列表
          </a-menu-item>
        </a-sub-menu>

        <a-sub-menu key="dast" title="DAST 动态扫描">
          <template #icon><RadarChartOutlined /></template>
          <a-menu-item key="DastConfigs" @click="navigate('DastConfigs')">
            扫描配置
          </a-menu-item>
          <a-menu-item key="DastTasks" @click="navigate('DastTasks')">
            任务列表
          </a-menu-item>
          <a-menu-item key="DastPocs" @click="navigate('DastPocs')">
            PoC 模板
          </a-menu-item>
          <a-menu-item key="DastCves" @click="navigate('DastCves')">
            CVE 情报中心
          </a-menu-item>
        </a-sub-menu>

        <a-sub-menu key="sca" title="SCA 软件成分分析">
          <template #icon><BranchesOutlined /></template>
          <a-menu-item key="ScaProjects" @click="navigate('ScaProjects')">
            SCA 工程管理
          </a-menu-item>
          <a-menu-item key="ScaVulnerabilities" @click="navigate('ScaVulnerabilities')">
            组件漏洞 (CVE)
          </a-menu-item>
        </a-sub-menu>
      </a-menu>
    </a-layout-sider>

    <a-layout
      :style="{
        marginLeft: '240px',
        transition: 'all 0.2s',
        background: '#ffffff',
        height: '100vh',
        display: 'flex',
        flexDirection: 'column',
        minWidth: 0,
      }"
    >
      <a-layout-header
        class="flex h-16 shrink-0 items-center justify-between border-b border-zinc-200 bg-white px-8"
        :style="{ padding: '0 24px' }"
      >
        <div class="flex items-center">
          <a-breadcrumb class="font-medium text-zinc-500">
            <a-breadcrumb-item class="text-zinc-400">平台首页</a-breadcrumb-item>
            <a-breadcrumb-item class="font-semibold text-zinc-800">{{ currentRouteName }}</a-breadcrumb-item>
          </a-breadcrumb>
        </div>

        <div class="flex items-center gap-4">
          <a-tag color="processing" class="font-mono font-semibold px-2 py-0.5">
            Build v1.3.3
          </a-tag>
          <div class="h-4 w-px bg-zinc-200"></div>
          <a-badge dot class="cursor-pointer">
            <BellOutlined class="text-lg text-zinc-500 transition-colors hover:text-zinc-900" />
          </a-badge>
          <div class="h-4 w-px bg-zinc-200"></div>
          <div class="group flex cursor-pointer items-center gap-3">
            <a-avatar class="border border-zinc-200 bg-zinc-100 font-bold text-zinc-800" size="small">A</a-avatar>
            <span class="text-sm font-medium text-zinc-600 transition-colors group-hover:text-zinc-900">wsh</span>
          </div>
        </div>
      </a-layout-header>

      <a-layout-content class="flex-1 overflow-x-hidden overflow-y-auto bg-white p-6">
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
import { computed, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import {
  BellOutlined,
  BranchesOutlined,
  CodeOutlined,
  DashboardOutlined,
  RadarChartOutlined,
  SafetyCertificateOutlined,
} from '@ant-design/icons-vue'

const route = useRoute()
const router = useRouter()

const selectedKeys = ref<string[]>(['Dashboard'])
const openKeys = ref<string[]>(['sast', 'dast', 'sca'])

watch(
  () => route.name,
  (newName) => {
    if (newName) {
      selectedKeys.value = [newName.toString()]
    }
  },
  { immediate: true },
)

const routeNameMap: Record<string, string> = {
  Dashboard: '概览',
  SastRepos: '代码仓库',
  SastConfigs: '扫描配置',
  SastTasks: '任务列表',
  SastTaskDetail: '扫描详情与日志',
  DastConfigs: '扫描配置',
  DastTasks: '任务列表',
  DastPocs: 'PoC 模板',
  DastCves: 'CVE 情报中心',
  DastTaskDetail: '动态扫描详情',
  ScaProjects: 'SCA 工程管理',
  ScaVulnerabilities: '组件漏洞 (CVE)',
}

const currentRouteName = computed(() => {
  return routeNameMap[route.name as string] || route.name?.toString() || '页面'
})

const navigate = (name: string) => {
  router.push({ name })
}
</script>

<style>
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
