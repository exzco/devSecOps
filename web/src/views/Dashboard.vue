<template>
  <div class="w-full mx-auto max-w-screen-2xl flex flex-col gap-6 bg-white p-2">
    <!-- Stats Matrix Grid (Shadcn Light style) -->
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
      <!-- Card 1: Repo Count -->
      <a-card class="rounded-lg border border-zinc-200 bg-white" :bordered="false">
        <div class="flex items-center justify-between">
          <div>
            <div class="text-xs font-semibold text-zinc-500">已接入代码仓库</div>
            <div class="text-2xl font-bold text-zinc-900 mt-1.5 font-mono">{{ repoCount }}</div>
          </div>
          <div class="p-2.5 bg-zinc-50 border border-zinc-200 rounded-md text-zinc-700">
            <GithubOutlined class="text-lg" />
          </div>
        </div>
        <div class="mt-3 text-[11px] text-zinc-400 font-medium">
          支持 Go, Java, TS, Python 审计
        </div>
      </a-card>

      <!-- Card 2: SAST Task Count -->
      <a-card class="rounded-lg border border-zinc-200 bg-white" :bordered="false">
        <div class="flex items-center justify-between">
          <div>
            <div class="text-xs font-semibold text-zinc-500">SAST 静态扫描任务</div>
            <div class="text-2xl font-bold text-zinc-900 mt-1.5 font-mono">{{ sastTaskCount }}</div>
          </div>
          <div class="p-2.5 bg-zinc-50 border border-zinc-200 rounded-md text-zinc-700">
            <CodeOutlined class="text-lg" />
          </div>
        </div>
        <div class="mt-3 text-[11px] text-zinc-500 flex items-center gap-1">
          <span class="text-zinc-800 font-bold font-mono">{{ sastVulnCount }}</span>
          <span>处静态代码隐患点</span>
        </div>
      </a-card>

      <!-- Card 3: DAST Target Count -->
      <a-card class="rounded-lg border border-zinc-200 bg-white" :bordered="false">
        <div class="flex items-center justify-between">
          <div>
            <div class="text-xs font-semibold text-zinc-500">DAST 动态扫描任务</div>
            <div class="text-2xl font-bold text-zinc-900 mt-1.5 font-mono">{{ dastTaskCount }}</div>
          </div>
          <div class="p-2.5 bg-zinc-50 border border-zinc-200 rounded-md text-zinc-700">
            <RadarChartOutlined class="text-lg" />
          </div>
        </div>
        <div class="mt-3 text-[11px] text-zinc-500 flex items-center gap-1">
          <span class="text-zinc-800 font-bold font-mono">{{ dastOpenPorts }}</span>
          <span>个资产暴露端口</span>
        </div>
      </a-card>

      <!-- Card 4: Vuln Score -->
      <a-card class="rounded-lg border border-zinc-200 bg-white" :bordered="false">
        <div class="flex items-center justify-between">
          <div>
            <div class="text-xs font-semibold text-zinc-500">漏洞发现与威胁总数</div>
            <div class="text-2xl font-bold text-zinc-900 mt-1.5 font-mono">{{ totalFindings }}</div>
          </div>
          <div class="p-2.5 bg-zinc-50 border border-zinc-200 rounded-md text-zinc-700">
            <BugOutlined class="text-lg" />
          </div>
        </div>
        <div class="mt-3 text-[11px] text-zinc-500 flex items-center gap-1">
          <span class="text-zinc-800 font-bold font-mono">{{ dastFindingsCount }}</span>
          <span>个动态 PoC 隐患</span>
        </div>
      </a-card>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed } from 'vue';
import { message } from 'ant-design-vue';
import {
  GithubOutlined,
  CodeOutlined,
  RadarChartOutlined,
  BugOutlined
} from '@ant-design/icons-vue';
import { getRepoList, getScanTasks } from '../api/sast';
import { getDastTasks } from '../api/dast';

const repoCount = ref(0);
const sastTaskCount = ref(0);
const sastVulnCount = ref(0);
const dastTaskCount = ref(0);
const dastOpenPorts = ref(0);
const dastFindingsCount = ref(0);

const totalFindings = computed(() => {
  return sastVulnCount.value + dastFindingsCount.value;
});

const refreshAll = async () => {
  try {
    const reposRes = await getRepoList(1, 100);
    repoCount.value = reposRes.data.data.total || 0;

    const sastRes = await getScanTasks(1, 100);
    const sastTasks = sastRes.data.data.data || [];
    sastTaskCount.value = sastRes.data.data.total || 0;
    sastVulnCount.value = sastTasks.reduce((sum: number, task: any) => sum + (task.vuln_count || 0), 0);

    const dastRes = await getDastTasks();
    const dastTasks = dastRes.data.data || [];
    dastTaskCount.value = dastTasks.length;
    dastOpenPorts.value = dastTasks.reduce((sum: number, task: any) => sum + (task.open_ports || 0), 0);
    dastFindingsCount.value = dastTasks.reduce((sum: number, task: any) => sum + (task.findings || 0), 0);
    message.success('数据已同步完成');
  } catch (err) {
    message.error('同步态势数据失败');
  }
};

onMounted(() => {
  refreshAll();
});
</script>
