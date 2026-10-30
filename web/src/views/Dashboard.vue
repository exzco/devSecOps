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
            <FolderGit2 :size="20" />
          </div>
        </div>
        <div class="mt-3 text-[11px] text-zinc-400 font-medium">
          支持 Go, Java, TS, Python 静态审计
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
            <Code2 :size="20" />
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
            <Radar :size="20" />
          </div>
        </div>
        <div class="mt-3 text-[11px] text-zinc-500 flex items-center gap-1">
          <span class="text-zinc-800 font-bold font-mono">{{ dastOpenPorts }}</span>
          <span>个资产暴露端口 ({{ dastFindingsCount }} 漏洞)</span>
        </div>
      </a-card>

      <!-- Card 4: Worker Nodes Cluster Summary -->
      <a-card class="rounded-lg border border-zinc-200 bg-white" :bordered="false">
        <div class="flex items-center justify-between">
          <div>
            <div class="text-xs font-semibold text-zinc-500">Worker 节点</div>
            <div class="text-2xl font-bold text-zinc-900 mt-1.5 font-mono flex items-center gap-2">
              <span>{{ workersOverview?.online_workers || 0 }}</span>
              <span class="text-xs font-normal text-zinc-400">/ {{ workersOverview?.total_workers || 0 }} 在线</span>
            </div>
          </div>
          <div
            class="p-2.5 rounded-md border"
            :class="workersOverview?.all_ready && (workersOverview?.online_workers || 0) > 0 ? 'bg-emerald-50 border-emerald-200 text-emerald-600' : 'bg-zinc-50 border-zinc-200 text-zinc-700'"
          >
            <Server :size="20" />
          </div>
        </div>
        <div class="mt-3 text-[11px] flex items-center gap-2">
          <span v-if="!workersOverview || workersOverview.online_workers === 0" class="text-amber-600 font-medium">
            暂无 Worker 在线 (等待接入)
          </span>
          <span v-else-if="workersOverview.all_ready" class="text-emerald-600 font-medium flex items-center gap-1">
            <CheckCircle2 :size="13" /> 全部节点环境就绪
          </span>
          <span v-else class="text-rose-600 font-medium flex items-center gap-1">
            <AlertTriangle :size="13" /> 存在环境依赖缺失
          </span>
          <span class="text-zinc-400 font-mono text-[10px]">
            (SAST: {{ workersOverview?.sast_online || 0 }} | DAST: {{ workersOverview?.dast_online || 0 }})
          </span>
        </div>
      </a-card>
    </div>

    <!-- Distributed Worker Nodes & Environment Health Panel -->
    <a-card class="rounded-lg border border-zinc-200 bg-white shadow-none" :bordered="false">
      <!-- Panel Header -->
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-zinc-100">
        <div>
          <div class="flex items-center gap-2.5 flex-wrap">
            <div class="p-1.5 bg-zinc-900 text-white rounded-md">
              <Cpu :size="16" />
            </div>
            <h3 class="text-base font-semibold text-zinc-900 tracking-tight">worker 节点列表</h3>
            <span
              v-if="workersOverview?.all_ready && (workersOverview?.online_workers || 0) > 0"
              class="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium bg-emerald-50 text-emerald-700 border border-emerald-200"
            >
              <span class="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
              环境正常
            </span>
            <span
              v-else-if="workersOverview?.has_missing_deps"
              class="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium bg-rose-50 text-rose-700 border border-rose-200"
            >
              <AlertTriangle :size="12" />
              检测到依赖缺失
            </span>
            <span
              v-else
              class="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium bg-zinc-100 text-zinc-600 border border-zinc-200"
            >
              等待节点接入
            </span>
          </div>
          <p class="text-xs text-zinc-500 mt-1">
            
          </p>
        </div>

        <div class="flex items-center gap-2">
          <a-button
            size="small"
            class="inline-flex items-center gap-1.5 text-xs text-zinc-700 border-zinc-200 hover:text-zinc-900"
            :loading="loadingWorkers"
            @click="fetchWorkers"
          >
            <RefreshCw :size="12" :class="{ 'animate-spin': loadingWorkers }" />
            刷新状态
          </a-button>
        </div>
      </div>

      <!-- Missing Dependencies Alert Box -->
      <div
        v-if="workersOverview?.has_missing_deps && workersOverview.missing_dependencies.length > 0"
        class="mt-4 p-4 rounded-lg bg-rose-50/90 border border-rose-200 text-rose-900"
      >
        <div class="flex items-start gap-2.5">
          <AlertTriangle :size="18" class="text-rose-600 shrink-0 mt-0.5" />
          <div class="flex-1">
            <div class="text-xs font-bold text-rose-900">
              检测到 {{ workersOverview.missing_dependencies.length }} 项工作环境依赖缺失或异常，可能导致相关任务执行失败：
            </div>
            <ul class="mt-2 space-y-1 text-xs text-rose-800 list-disc list-inside">
              <li v-for="(dep, idx) in workersOverview.missing_dependencies" :key="idx" class="font-mono text-[11px]">
                {{ dep }}
              </li>
            </ul>
          </div>
        </div>
      </div>

      <!-- Workers List Cards -->
      <div v-if="workersOverview && workersOverview.workers.length > 0" class="mt-5 space-y-4">
        <div
          v-for="w in workersOverview.workers"
          :key="w.id"
          class="border rounded-lg p-4 transition-all"
          :class="w.status === 'online' || w.status === 'busy' ? (w.ready ? 'border-zinc-200 bg-white hover:border-zinc-300' : 'border-rose-200 bg-rose-50/20') : 'border-zinc-200 bg-zinc-50/60 opacity-75'"
        >
          <!-- Worker Meta Header -->
          <div class="flex flex-col md:flex-row md:items-center justify-between gap-3 pb-3 border-b border-zinc-100">
            <div class="flex items-center gap-2.5 flex-wrap">
              <!-- Type Tag -->
              <span
                class="px-2 py-0.5 rounded text-[11px] font-bold uppercase tracking-wider"
                :class="w.type === 'sast' ? 'bg-blue-50 text-blue-700 border border-blue-200' : 'bg-purple-50 text-purple-700 border border-purple-200'"
              >
                {{ w.type }} Worker
              </span>

              <!-- Node ID -->
              <span class="font-mono text-xs font-semibold text-zinc-900">
                {{ w.id }}
              </span>

              <!-- Online/Busy/Offline Status Badge -->
              <span
                v-if="w.status === 'online'"
                class="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-medium bg-emerald-50 text-emerald-700 border border-emerald-200"
              >
                <span class="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
                在线
              </span>
              <span
                v-else-if="w.status === 'busy'"
                class="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-medium bg-blue-50 text-blue-700 border border-blue-200"
              >
                <Activity :size="11" class="animate-spin text-blue-500" />
                正在执行 ({{ w.active_tasks }} 并发)
              </span>
              <span
                v-else
                class="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-medium bg-zinc-100 text-zinc-500 border border-zinc-200"
              >
                已离线
              </span>

              <!-- Environment Ready Badge -->
              <span
                v-if="w.ready"
                class="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-medium bg-emerald-50 text-emerald-700"
              >
                <CheckCircle2 :size="12" /> 环境就绪
              </span>
              <span
                v-else
                class="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-medium bg-rose-100 text-rose-700"
              >
                <XCircle :size="12" /> 缺少依赖
              </span>
            </div>

            <!-- Host & Hardware info -->
            <div class="text-[11px] text-zinc-500 flex items-center gap-3 font-mono flex-wrap">
              <span>主机: {{ w.hostname }} ({{ w.ip }})</span>
              <span>PID: {{ w.pid }}</span>
              <span>架构: {{ w.system_info?.os }} {{ w.system_info?.arch }} ({{ w.system_info?.num_cpu }} 核)</span>
              <span v-if="w.last_heartbeat" class="text-zinc-400">心跳: {{ formatTime(w.last_heartbeat) }}</span>
            </div>
          </div>

          <!-- Dependency Checklist Grid -->
          <div class="mt-3">
            <div class="text-[11px] font-semibold text-zinc-500 mb-2 flex items-center justify-between">
              <span>外部工具与核心依赖核验结果 ({{ w.dependencies?.length || 0 }} 项)</span>
              <span class="text-zinc-400 font-mono text-[10px]">工作区: {{ w.system_info?.work_dir || '-' }}</span>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-2.5">
              <div
                v-for="dep in w.dependencies"
                :key="dep.name"
                class="p-2.5 rounded-md border text-xs flex flex-col justify-between gap-1.5"
                :class="dep.installed ? 'bg-zinc-50/50 border-zinc-200' : (dep.required ? 'bg-rose-50/60 border-rose-200' : 'bg-amber-50/60 border-amber-200')"
              >
                <div class="flex items-center justify-between gap-1">
                  <div class="flex items-center gap-1.5 font-medium" :class="dep.installed ? 'text-zinc-900' : 'text-rose-700'">
                    <CheckCircle2 v-if="dep.installed" :size="14" class="text-emerald-600 shrink-0" />
                    <XCircle v-else :size="14" class="text-rose-600 shrink-0" />
                    <span class="truncate">{{ dep.name }}</span>
                  </div>
                  <span
                    v-if="dep.required"
                    class="px-1.5 py-0.2 rounded text-[9px] font-bold"
                    :class="dep.installed ? 'bg-zinc-200 text-zinc-700' : 'bg-rose-200 text-rose-800'"
                  >
                    强依赖
                  </span>
                </div>

                <div v-if="dep.installed" class="text-[10px] text-zinc-500 font-mono truncate" :title="dep.path">
                  <span v-if="dep.version" class="text-zinc-700 font-semibold">{{ dep.version }}</span>
                  <span v-if="dep.path" class="text-zinc-400 ml-1">({{ dep.path }})</span>
                </div>
                <div v-else class="text-[10px] text-rose-600 font-mono leading-tight">
                  {{ dep.message }}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Empty State Guide -->
      <div v-else class="mt-6 py-10 px-6 rounded-lg border border-dashed border-zinc-300 text-center bg-zinc-50/50">
        <Server :size="36" class="mx-auto text-zinc-400 mb-3" />
        <h4 class="text-sm font-semibold text-zinc-800">当前暂无 Worker 节点连接</h4>
        <p class="text-xs text-zinc-500 max-w-md mx-auto mt-1 leading-relaxed">
          控制面服务运行 Server 控制台，不承担扫描负载。<br />
          请在本地计算主机分别启动对应的执行 Worker：
        </p>
        <div class="mt-4 max-w-lg mx-auto bg-zinc-900 text-zinc-200 rounded-md p-3 text-left font-mono text-xs space-y-1">
          <div class="text-zinc-500 text-[11px]"># 启动 SAST  Worker:</div>
          <div class="text-emerald-400">./worker-sast --config configs/example.yaml</div>
          <div class="text-zinc-500 text-[11px] pt-1"># 启动 DAST  Worker:</div>
          <div class="text-purple-400">./worker-dast --config configs/example.yaml</div>
        </div>
      </div>
    </a-card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue';
import { message } from 'ant-design-vue';
import {
  FolderGit2,
  Code2,
  Radar,
  Server,
  Cpu,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Activity,
  RefreshCw,
} from 'lucide-vue-next';
import { getRepoList, getScanTasks, getDastTasks, getWorkersOverview, type WorkersOverview } from '../api';

const repoCount = ref(0);
const sastTaskCount = ref(0);
const sastVulnCount = ref(0);
const dastTaskCount = ref(0);
const dastOpenPorts = ref(0);
const dastFindingsCount = ref(0);

const workersOverview = ref<WorkersOverview | null>(null);
const loadingWorkers = ref(false);
let refreshTimer: any = null;

const fetchWorkers = async () => {
  loadingWorkers.value = true;
  try {
    const res = await getWorkersOverview();
    workersOverview.value = res.data.data;
  } catch (err: any) {
    console.error('获取 Worker 状态失败', err);
  } finally {
    loadingWorkers.value = false;
  }
};

const formatTime = (isoString?: string) => {
  if (!isoString) return '-';
  try {
    const date = new Date(isoString);
    const now = new Date();
    const diffSec = Math.floor((now.getTime() - date.getTime()) / 1000);
    if (diffSec < 10) return '刚刚';
    if (diffSec < 60) return `${diffSec} 秒前`;
    if (diffSec < 3600) return `${Math.floor(diffSec / 60)} 分钟前`;
    return date.toLocaleTimeString();
  } catch {
    return isoString;
  }
};

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

    await fetchWorkers();
  } catch (err) {
    message.error('同步态势数据失败');
  }
};

onMounted(() => {
  refreshAll();
  refreshTimer = setInterval(fetchWorkers, 5000);
});

onUnmounted(() => {
  if (refreshTimer) {
    clearInterval(refreshTimer);
  }
});
</script>
