<template>
  <div class="w-full mx-auto max-w-screen-2xl flex flex-col gap-5 bg-white">
    <!-- Breadcrumb & Back action header -->
    <div class="flex items-center justify-between">
      <div class="flex items-center gap-3">
        <a-button type="default" @click="goBack">
          <template #icon><ArrowLeftOutlined /></template>
          返回任务列表
        </a-button>
        <span class="text-xl font-bold text-zinc-900 font-mono">任务详情: {{ taskId }}</span>
      </div>
      <a-space>
        <div class="flex items-center gap-2">
          <span class="text-xs text-zinc-500">实时刷新 (5s):</span>
          <a-switch v-model:checked="autoRefresh" size="small" />
        </div>
        <a-button type="primary" @click="refreshData">
          <template #icon><ReloadOutlined /></template>
          手动刷新
        </a-button>
      </a-space>
    </div>

    <!-- Status Overview Card -->
    <a-card :bordered="false" class="rounded-lg shadow-sm border border-zinc-200 bg-white">
      <div class="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-4 text-center">
        <div>
          <div class="text-xs text-zinc-500 font-medium">任务状态</div>
          <div class="mt-1.5">
            <a-tag :color="statusMap.status === 'running' ? 'processing' : 'success'" class="font-semibold px-2 py-0.5">
              {{ statusMap.status === 'running' ? 'scanning' : 'completed' }}
            </a-tag>
          </div>
        </div>
        <div>
          <div class="text-xs text-zinc-500 font-medium">总目标 IPs</div>
          <div class="text-lg font-bold text-zinc-900 mt-1 font-mono">{{ statusMap.total_ips || 0 }}</div>
        </div>
        <div>
          <div class="text-xs text-zinc-500 font-medium">已扫 IPs</div>
          <div class="text-lg font-bold text-sky-600 mt-1 font-mono">{{ statusMap.scanned_ips || 0 }}</div>
        </div>
        <div>
          <div class="text-xs text-zinc-500 font-medium">开放端口数</div>
          <div class="text-lg font-bold text-amber-600 mt-1 font-mono">{{ statusMap.open_ports || 0 }}</div>
        </div>
        <div>
          <div class="text-xs text-zinc-500 font-medium">指纹探测完成</div>
          <div class="text-lg font-bold text-indigo-600 mt-1 font-mono">{{ statusMap.fp_done || 0 }}</div>
        </div>
        <div>
          <div class="text-xs text-zinc-500 font-medium">PoC 规则检测</div>
          <div class="text-lg font-bold text-purple-600 mt-1 font-mono">{{ statusMap.poc_done || 0 }}</div>
        </div>
        <div>
          <div class="text-xs text-zinc-500 font-medium">安全漏洞检出</div>
          <div class="text-lg font-bold text-rose-600 mt-1 font-mono">{{ statusMap.findings || 0 }}</div>
        </div>
      </div>
      
      <!-- Progress Bar for Running Tasks -->
      <div v-if="statusMap.status === 'running'" class="mt-4 border-t border-zinc-200 pt-3 flex items-center gap-4">
        <span class="text-xs text-zinc-500 font-medium">整体扫描进度:</span>
        <a-progress 
          :percent="Math.round(((Number(statusMap.scanned_ips || 0)) / (Number(statusMap.total_ips || 1))) * 100) || 0" 
          status="active" 
          stroke-color="#09090b"
          class="flex-1"
        />
      </div>
    </a-card>

    <!-- Host Assets & Fingerprints Card -->
    <a-card title="发现的主机服务与端口指纹 (PortScan & Fingerprint)" :bordered="false" class="rounded-lg border border-zinc-200 bg-white">
      <div class="mt-2 bg-white">
        <a-table
          row-key="port"
          :columns="assetColumns"
          :data-source="assets"
          :scroll="{ x: '100%' }"
          size="middle"
          :loading="loading"
          class="w-full bg-white"
        >
          <template #bodyCell="{ text, record, column }">
            <template v-if="column.dataIndex === 'port'">
              <span v-if="record.port === 0" class="text-zinc-400 italic">closed</span>
              <span v-else class="font-mono text-zinc-800 font-semibold">{{ record.port }}</span>
            </template>

            <template v-if="column.dataIndex === 'proto'">
              <a-tag color="blue" class="font-mono text-xs uppercase">{{ record.proto || 'tcp' }}</a-tag>
            </template>

            <template v-if="column.dataIndex === 'service'">
              <div class="flex flex-col">
                <span class="font-semibold text-zinc-950">{{ record.service }}</span>
                <span v-if="record.product || record.version" class="text-[10px] text-zinc-400 font-mono">
                  {{ record.product }} <span v-if="record.version">v{{ record.version }}</span>
                </span>
              </div>
            </template>

            <template v-if="column.dataIndex === 'cpes'">
              <div class="flex flex-wrap gap-1">
                <span v-if="!record.cpes || record.cpes.length === 0" class="text-zinc-400 text-xs">—</span>
                <a-tag v-for="cpe in record.cpes" :key="cpe" color="orange" class="text-[10px] scale-90 origin-left">
                  {{ cpe }}
                </a-tag>
              </div>
            </template>

            <template v-if="column.key === 'asset_actions'">
              <a-button type="link" size="small" class="!p-0" :disabled="!record.raw_response" @click="viewAssetDetail(record)">
                <template #icon><EyeOutlined /></template>
                查看原始响应
              </a-button>
            </template>
          </template>
        </a-table>
      </div>
    </a-card>

    <!-- Findings Results Card -->
    <a-card title="动态漏洞扫描结果 (Nuclei PoC 检测)" :bordered="false" class="rounded-lg border border-zinc-200 bg-white">
      <div class="mt-2 bg-white">
        <a-table
          row-key="templateId"
          :columns="columns"
          :data-source="findings"
          :scroll="{ x: '100%' }"
          size="middle"
          :loading="loading"
          class="w-full bg-white"
        >
          <template #bodyCell="{ text, record, column }">
            <template v-if="column.dataIndex === 'severity'">
              <a-tag :color="severityColor(record.severity)" class="font-bold">
                {{ record.severity }}
              </a-tag>
            </template>

            <template v-if="column.dataIndex === 'matched'">
              <span class="font-mono text-zinc-200 text-xs">{{ record.matched }}</span>
            </template>

            <template v-if="column.dataIndex === 'tags'">
              <a-space :size="4" class="flex-wrap">
                <a-tag v-for="tag in record.tags" :key="tag" color="default" class="text-[10px] scale-90 origin-left">
                  {{ tag }}
                </a-tag>
              </a-space>
            </template>

            <template v-if="column.key === 'actions'">
              <a-button type="link" size="small" @click="viewDetail(record)">
                <template #icon><EyeOutlined /></template>
                查看响应载荷
              </a-button>
            </template>
          </template>
        </a-table>
      </div>
    </a-card>

    <!-- Response Payload Details Drawer -->
    <a-drawer
      v-model:open="drawerVisible"
      :title="drawerTitle"
      width="800"
      placement="right"
      :destroy-on-close="true"
    >
      <div class="flex flex-col gap-5 h-full" v-if="currentFinding">
        <a-descriptions :column="2" bordered class="bg-white border-zinc-200">
          <a-descriptions-item label="PoC 模板 ID" :span="2">
            <span class="font-mono text-zinc-900 font-bold">{{ currentFinding.templateId }}</span>
          </a-descriptions-item>
          <a-descriptions-item label="隐患" :span="2">
            <span class="text-zinc-800 font-semibold">{{ currentFinding.name }}</span>
          </a-descriptions-item>
          <a-descriptions-item label="严重级别">
            <a-tag :color="severityColor(currentFinding.severity)">{{ currentFinding.severity }}</a-tag>
          </a-descriptions-item>
          <a-descriptions-item label="漏洞命中资产">
            <span class="font-mono text-xs text-zinc-800">{{ currentFinding.matched }}</span>
          </a-descriptions-item>
        </a-descriptions>

        <div class="flex-1 flex flex-col gap-2 min-h-0">
          <span class="text-xs font-semibold text-zinc-500">漏洞触发响应/上下文信息 (Nuclei Matcher Output):</span>
          <div class="flex-1 overflow-auto rounded bg-zinc-50 p-4 border border-zinc-200 font-mono text-xs text-zinc-800 scrollbar-thin">
            <pre class="whitespace-pre-wrap break-all">{{ currentFinding.response || '该 PoC 匹配成功，但未捕获到额外响应载荷信息。' }}</pre>
          </div>
        </div>
      </div>
    </a-drawer>

    <!-- Nmap Probe Raw Details Drawer -->
    <a-drawer
      v-model:open="assetDrawerVisible"
      :title="assetDrawerTitle"
      width="800"
      placement="right"
      :destroy-on-close="true"
    >
      <div class="flex flex-col gap-5 h-full" v-if="currentAsset">
        <a-descriptions :column="2" bordered class="bg-white border-zinc-200">
          <a-descriptions-item label="主机 IP" :span="2">
            <span class="font-mono text-zinc-900 font-bold">{{ currentAsset.host }}</span>
          </a-descriptions-item>
          <a-descriptions-item label="探测端口">
            <span class="font-mono text-zinc-800 font-semibold">{{ currentAsset.port === 0 ? '关闭/过滤' : currentAsset.port }}</span>
          </a-descriptions-item>
          <a-descriptions-item label="协议">
            <a-tag color="blue">{{ currentAsset.proto || 'tcp' }}</a-tag>
          </a-descriptions-item>
          <a-descriptions-item label="应用服务" :span="2">
            <span class="text-zinc-800 font-bold">{{ currentAsset.service }}</span>
            <span class="ml-2 text-zinc-500 font-mono text-xs" v-if="currentAsset.product || currentAsset.version">
              ({{ currentAsset.product }} {{ currentAsset.version }})
            </span>
          </a-descriptions-item>
        </a-descriptions>

        <div class="flex-1 flex flex-col gap-2 min-h-0">
          <span class="text-xs font-semibold text-zinc-500">Nmap 探测原始指纹包详情 (Service Probe Output):</span>
          <div class="flex-1 overflow-auto rounded bg-zinc-50 p-4 border border-zinc-200 font-mono text-xs text-zinc-800 scrollbar-thin">
            <pre class="whitespace-pre-wrap break-all">{{ currentAsset.raw_response || '该端口未捕获到原始 Banner 数据。' }}</pre>
          </div>
        </div>
      </div>
    </a-drawer>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted, watch, computed } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { message } from 'ant-design-vue';
import { 
  ArrowLeftOutlined, 
  ReloadOutlined, 
  EyeOutlined 
} from '@ant-design/icons-vue';
import { getDastTaskStatus, getDastTaskResults, getDastTaskAssets } from '../../api';

interface Finding {
  templateId: string;
  name: string;
  severity: string;
  matched: string;
  tags: string[];
  response?: string;
}

interface DastAsset {
  host: string;
  port: number;
  proto: string;
  service: string;
  product: string;
  version: string;
  cpes: string[];
  raw_response: string;
  timestamp: string;
}

const route = useRoute();
const router = useRouter();
const taskId = route.params.id as string;

const loading = ref(false);
const drawerVisible = ref(false);
const assetDrawerVisible = ref(false);
const autoRefresh = ref(true);
let pollTimer: any = null;

const statusMap = ref<Record<string, string>>({
  status: 'running',
  total_ips: '0',
  scanned_ips: '0',
  open_ports: '0',
  fp_done: '0',
  poc_done: '0',
  findings: '0',
});

const findings = ref<Finding[]>([]);
const assets = ref<DastAsset[]>([]);
const currentFinding = ref<Finding | null>(null);
const currentAsset = ref<DastAsset | null>(null);

const columns = [
  { title: '规则模版 ID', dataIndex: 'templateId', key: 'templateId', width: 180, ellipsis: true },
  { title: '漏洞名称', dataIndex: 'name', key: 'name', width: 200, ellipsis: true },
  { title: '严重级别', dataIndex: 'severity', key: 'severity', width: 100 },
  { title: '命中的脆弱资产地址', dataIndex: 'matched', key: 'matched', width: 250, ellipsis: true },
  { title: 'PoC 标签', dataIndex: 'tags', key: 'tags', width: 160 },
  { title: '操作', key: 'actions', width: 140, fixed: 'right' as const },
];

const assetColumns = [
  { title: '目标主机 IP', dataIndex: 'host', key: 'host', width: 160 },
  { title: '开放端口', dataIndex: 'port', key: 'port', width: 110 },
  { title: '协议', dataIndex: 'proto', key: 'proto', width: 100 },
  { title: '应用/服务指纹', dataIndex: 'service', key: 'service', width: 240 },
  { title: 'CPEs 列表', dataIndex: 'cpes', key: 'cpes', ellipsis: true },
  { title: '操作', key: 'asset_actions', width: 160, fixed: 'right' as const },
];

const drawerTitle = computed(() => {
  if (!currentFinding.value) return '漏洞细节详情';
  return `脆弱资产检测详情: ${currentFinding.value.templateId}`;
});

const assetDrawerTitle = computed(() => {
  if (!currentAsset.value) return '服务指纹明细';
  return `端口探测指纹详情: ${currentAsset.value.host}:${currentAsset.value.port}`;
});

const severityColor = (severity: string) => {
  const s = (severity || '').toLowerCase();
  const map: Record<string, string> = {
    critical: 'red',
    high: 'orange',
    medium: 'gold',
    low: 'blue',
    info: 'green',
  };
  return map[s] || 'default';
};

const goBack = () => {
  router.push('/dast/tasks');
};

const loadStatus = async () => {
  try {
    const res = await getDastTaskStatus(taskId);
    statusMap.value = res.data.data || {};
  } catch (err) {
    message.error('获取任务状态失败');
  }
};

const loadResults = async () => {
  loading.value = true;
  try {
    const res = await getDastTaskResults(taskId);
    findings.value = res.data.data || [];
  } catch (err) {
    message.error('获取扫描漏洞详情失败');
  } finally {
    loading.value = false;
  }
};

const loadAssets = async () => {
  try {
    const res = await getDastTaskAssets(taskId);
    assets.value = res.data.data || [];
  } catch (err) {
    // 失败静默
  }
};

const refreshData = async () => {
  await loadStatus();
  await loadResults();
  await loadAssets();
};

const startPolling = () => {
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
  pollTimer = setInterval(() => {
    if (autoRefresh.value && statusMap.value.status === 'running') {
      refreshData();
    }
  }, 5000);
};

const viewDetail = (record: Finding) => {
  currentFinding.value = record;
  drawerVisible.value = true;
};

const viewAssetDetail = (record: DastAsset) => {
  currentAsset.value = record;
  assetDrawerVisible.value = true;
};

watch(
  () => autoRefresh.value,
  (v) => {
    if (v) startPolling();
    else if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
  }
);

onMounted(() => {
  refreshData();
  startPolling();
});

onUnmounted(() => {
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
});
</script>
