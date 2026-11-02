<template>
  <div :class="['w-full mx-auto max-w-screen-2xl flex flex-col gap-6 bg-white', viewingTaskId ? 'h-[calc(100vh-112px)] overflow-hidden' : '']">
    <!-- State 1: Task List -->
    <div v-if="!viewingTaskId" class="flex flex-col gap-6 w-full bg-white">
      <!-- Task List Card -->
      <a-card title="SAST 任务列表" :bordered="false" class="rounded-lg w-full border border-zinc-200 bg-white">
        <template #extra>
          <a-space>
            <a-select v-model:value="statusFilter" style="width: 150px" allow-clear placeholder="按状态筛选" @change="loadTasks">
              <a-select-option value="pending">PENDING</a-select-option>
              <a-select-option value="running">RUNNING</a-select-option>
              <a-select-option value="success">SUCCESS</a-select-option>
              <a-select-option value="failed">FAILED</a-select-option>
            </a-select>
            <a-button type="primary" @click="loadTasks">
              Refresh
            </a-button>
          </a-space>
        </template>

        <div class="mt-2 bg-white">
          <a-table
            row-key="id"
            :columns="taskColumns"
            :data-source="taskData"
            size="middle"
            :loading="taskLoading"
            :pagination="taskPagination"
            @change="handleTaskTableChange"
            :scroll="{ x: 'max-content' }"
            class="w-full bg-white"
          >
            <template #bodyCell="{ text, record, column }">
              <template v-if="column.key === 'target'">
                <span class="font-mono text-zinc-700 text-xs break-all">{{ record.repository?.url || '-' }}</span>
              </template>

              <template v-if="column.dataIndex === 'status'">
                <a-tag :color="statusColor(record.status)" class="font-semibold px-2 py-0.5">
                  {{ (record.status || '').toUpperCase() }}
                </a-tag>
              </template>

              <template v-if="column.dataIndex === 'created_at'">
                {{ new Date(record.created_at).toLocaleString() }}
              </template>

              <template v-if="column.key === 'vulns'">
                <span :class="record.vuln_count > 0 ? 'text-rose-600 font-bold font-mono' : 'text-zinc-600 font-mono'">
                  {{ record.vuln_count }}
                </span>
              </template>

              <template v-if="column.key === 'actions'">
                <a-space :size="8">
                  <a-button type="link" size="small" @click="enterDetailView(record.id, record)">
                    查看结果
                  </a-button>
                  <a-button type="link" size="small" @click="handleShowLogs(record.id)">
                    查看日志
                  </a-button>
                  <a-popconfirm 
                    :title="record.status === 'running' || record.status === 'pending' ? '该任务处于进行中或排队状态，确认强制删除吗？' : '确认删除该扫描任务吗？'" 
                    ok-text="确认" 
                    cancel-text="取消" 
                    @confirm="handleDeleteTask(record.id, record.status === 'running' || record.status === 'pending')">
                    <a-button type="link" danger size="small">
                      删除
                    </a-button>
                  </a-popconfirm>
                </a-space>
              </template>
            </template>
          </a-table>
        </div>
      </a-card>
    </div>

    <!-- State 2: Scan Results Details View -->
    <div v-else class="flex flex-col gap-3 flex-1 overflow-hidden bg-white">
      <!-- Detail Header Bar -->
      <div class="flex items-center justify-between border-b border-zinc-200 pb-3 bg-white">
        <div class="flex items-center gap-3">
          <a-button type="default" size="small" @click="exitDetailView" class="!bg-white !border-zinc-200">
            <template #icon><ArrowLeft :size="14" class="inline-block" /></template>
            返回任务列表
          </a-button>
          <div class="flex items-center gap-2">
            <span class="text-md font-bold text-zinc-900">SAST 扫描结果</span>
            <span class="text-xs font-mono bg-zinc-100 text-zinc-600 px-2 py-0.5 rounded border border-zinc-200">
              Task #{{ viewingTaskId }}
            </span>
            <span v-if="viewingTaskRecord?.repository?.name" class="text-xs text-zinc-500 font-mono">
              / {{ viewingTaskRecord.repository.name }}
            </span>
            <a-tag v-if="viewingTaskRecord?.language" color="blue" class="scale-90 font-mono">
              {{ viewingTaskRecord.language.toUpperCase() }}
            </a-tag>
          </div>
        </div>
        <a-space>
          <a-button type="default" size="small" @click="loadVulnerabilities">
            <template #icon><RotateCw :size="14" class="inline-block" /></template>
            刷新数据
          </a-button>
        </a-space>
      </div>

      <!-- Main Results Split Layout -->
      <div class="flex-1 flex gap-4 overflow-hidden min-h-0 bg-white">
        <!-- Left Panel: Vulnerability List & Filters -->
        <div class="w-1/3 min-w-[340px] max-w-[400px] border border-zinc-200 rounded-lg bg-white flex flex-col overflow-hidden">
          <!-- Header: Title & Total Count -->
          <div class="p-3 border-b border-zinc-200 bg-zinc-50 flex items-center justify-between shrink-0">
            <div class="flex items-center gap-2">
              <ShieldAlert :size="15" class="text-zinc-600" />
              <span class="text-xs font-bold text-zinc-800">安全漏洞发现</span>
            </div>
            <span class="text-[11px] text-zinc-500 font-medium bg-zinc-200/60 px-2 py-0.5 rounded-full">
              共 {{ vulnPagination.total }} 项
            </span>
          </div>

          <!-- Search & Filter Row -->
          <div class="p-2.5 border-b border-zinc-200 bg-white flex flex-col gap-2 shrink-0">
            <a-input 
              v-model:value="vulnKeyword" 
              placeholder="搜索规则 / 文件名 / 漏洞描述..." 
              size="small" 
              allow-clear
              @pressEnter="handleVulnSearch"
              @change="handleVulnKeywordChange"
            >
              <template #prefix><Search :size="13" class="text-zinc-400 mr-1.5 shrink-0" /></template>
            </a-input>
            <div class="flex items-center gap-2">
              <a-select 
                v-model:value="vulnSeverityFilter" 
                size="small" 
                class="flex-1" 
                allow-clear 
                placeholder="全部风险等级"
                @change="handleVulnFilterChange"
              >
                <a-select-option value="">全部等级</a-select-option>
                <a-select-option value="critical">CRITICAL (严重)</a-select-option>
                <a-select-option value="high">HIGH (高危)</a-select-option>
                <a-select-option value="medium">MEDIUM (中危)</a-select-option>
                <a-select-option value="low">LOW (低危)</a-select-option>
                <a-select-option value="info">INFO (提示)</a-select-option>
              </a-select>
            </div>
          </div>

          <!-- Vulnerability Items List -->
          <div class="flex-1 overflow-y-auto divide-y divide-zinc-100 scrollbar-thin">
            <div v-if="vulnLoading" class="p-8 text-center text-zinc-400 text-xs">
              正在加载漏洞列表...
            </div>
            <div v-else-if="vulnData.length === 0" class="p-8 text-center text-zinc-400 text-xs">
              未找到符合条件的漏洞记录
            </div>
            <div 
              v-else
              v-for="item in vulnData" 
              :key="item.id"
              :class="[
                'p-3 cursor-pointer flex flex-col gap-1.5 transition-all text-xs border-l-3',
                activeVulnId === item.id 
                  ? 'bg-sky-50/70 border-sky-600 font-medium' 
                  : 'border-transparent hover:bg-zinc-50/80 hover:border-zinc-300'
              ]"
              @click="selectVuln(item)"
            >
              <div class="flex items-center justify-between gap-1">
                <span class="font-bold text-zinc-900 truncate flex-1 pr-1">
                  {{ item.rule_name || item.rule_id }}
                </span>
                <a-tag :color="severityColor(item.severity)" class="font-bold uppercase text-[10px] scale-90 m-0">
                  {{ item.severity }}
                </a-tag>
              </div>
              <div class="flex items-center justify-between text-[11px] text-zinc-500 font-mono">
                <span class="truncate max-w-[190px] text-zinc-400">{{ item.rule_id }}</span>
                <span class="text-zinc-600 font-sans shrink-0">
                  {{ item.file_path ? item.file_path.split('/').pop() : '-' }}:{{ item.start_line }}
                </span>
              </div>
            </div>
          </div>

          <!-- Pagination Footer -->
          <div class="p-2 border-t border-zinc-200 bg-zinc-50 flex items-center justify-center shrink-0">
            <a-pagination
              size="small"
              :current="vulnPagination.current"
              :page-size="vulnPagination.pageSize"
              :total="vulnPagination.total"
              :show-size-changer="false"
              @change="handleVulnPageChange"
            />
          </div>
        </div>

        <!-- Right Panel: Metadata + Code Viewer + Taint Steps -->
        <div class="flex-1 flex flex-col gap-3 overflow-hidden min-h-0">
          <!-- Top: Vulnerability Metadata Card -->
          <div v-if="activeVuln" class="p-3.5 bg-white border border-zinc-200 rounded-lg shadow-xs flex flex-col gap-2 shrink-0">
            <div class="flex items-center justify-between gap-3">
              <div class="flex items-center gap-2 flex-wrap min-w-0">
                <a-tag :color="severityColor(activeVuln.severity)" class="font-bold uppercase px-2 py-0.5 text-xs m-0">
                  {{ (activeVuln.severity || 'UNKNOWN').toUpperCase() }}
                </a-tag>
                <span class="font-bold text-sm text-zinc-900 truncate">
                  {{ activeVuln.rule_name || activeVuln.rule_id }}
                </span>
                <span class="font-mono text-xs text-zinc-500 bg-zinc-100 px-2 py-0.5 rounded border border-zinc-200">
                  {{ activeVuln.rule_id }}
                </span>
              </div>
              <div class="text-xs text-zinc-500 font-mono flex items-center gap-1.5 shrink-0">
                <FileCode :size="13" class="text-zinc-400" />
                <span class="font-medium text-zinc-700">{{ activeVuln.file_path ? activeVuln.file_path.split('/').pop() : '-' }}</span>
                <span class="text-sky-600 font-bold">L{{ activeVuln.start_line }}</span>
              </div>
            </div>
            <div v-if="activeVuln.message" class="text-xs text-zinc-600 bg-zinc-50 p-2.5 rounded border border-zinc-100 leading-relaxed font-sans">
              <span class="font-semibold text-zinc-800">漏洞描述：</span>{{ activeVuln.message }}
            </div>
          </div>

          <!-- Middle: Code Viewer with Java Syntax Highlighting -->
          <div class="flex-1 border border-zinc-200 rounded-lg bg-zinc-50 flex flex-col overflow-hidden min-h-0">
            <div class="p-2.5 px-3 border-b border-zinc-200 bg-zinc-100/80 flex items-center justify-between text-xs text-zinc-600 font-mono">
              <div class="flex items-center gap-2 truncate pr-2">
                <FileCode :size="14" class="text-zinc-500 shrink-0" />
                <span class="truncate text-zinc-800 font-semibold">{{ activeCodeFilePath || '未选择代码文件' }}</span>
                <span class="bg-amber-100 text-amber-800 text-[10px] font-bold px-1.5 py-0.2 rounded border border-amber-200">Java</span>
              </div>
              <div class="flex items-center gap-3 shrink-0">
                <span v-if="activeStep" class="text-[11px] font-sans px-2 py-0.5 rounded font-bold"
                  :class="activeStep.point_type === 'source' ? 'bg-emerald-100 text-emerald-800' : activeStep.point_type === 'sink' ? 'bg-rose-100 text-rose-800' : 'bg-sky-100 text-sky-800'">
                  追踪节点: {{ activeStep.point_type.toUpperCase() }}
                </span>
                <span v-if="activeCodeLine" class="text-sky-700 font-bold bg-sky-50 px-2 py-0.5 rounded border border-sky-200">
                  Line: {{ activeCodeLine }}
                </span>
              </div>
            </div>
            
            <div class="flex-1 overflow-auto bg-white p-2 font-mono text-xs scrollbar-thin relative min-h-0 select-text">
              <div v-if="highlightedCodeLines.length === 0" class="h-full flex items-center justify-center text-zinc-400 text-xs">
                请在左侧选择漏洞以查看关联的代码片段
              </div>
              <div v-else class="py-1">
                <div 
                  v-for="(lineHtml, idx) in highlightedCodeLines" 
                  :key="idx"
                  :class="[
                    'flex items-start py-0.5 px-2 font-mono leading-5 transition-colors',
                    isHighlightedLine(idx) 
                      ? 'bg-amber-100/80 border-l-4 border-amber-500 font-semibold text-amber-950' 
                      : 'hover:bg-zinc-50 text-zinc-800'
                  ]"
                >
                  <span class="w-12 text-right text-zinc-400 select-none pr-3 border-r border-zinc-200 mr-3 shrink-0">
                    {{ getLineNumber(idx) }}
                  </span>
                  <span class="whitespace-pre break-all flex-1 font-mono text-xs code-line-content" v-html="lineHtml"></span>
                </div>
              </div>
            </div>
          </div>

          <!-- Bottom: Taint Flow Trace Steps -->
          <div class="h-[220px] border border-zinc-200 rounded-lg bg-white flex flex-col overflow-hidden shrink-0">
            <div class="px-3 py-2 border-b border-zinc-200 bg-zinc-50 flex items-center justify-between text-xs font-semibold text-zinc-700">
              <span>污点调用链追踪 (Taint Flow Trace)</span>
              <span class="text-zinc-400 font-normal text-[11px]">
                {{ dangerPoints.length > 0 ? `共 ${dangerPoints.length} 个传播节点` : '单点模式匹配' }}
              </span>
            </div>
            <div class="p-2 overflow-y-auto flex-1 scrollbar-thin">
              <div v-if="dangerPoints.length === 0" class="h-full py-6 flex items-center justify-center text-zinc-400 text-xs">
                无污点追踪调用链 (该规则基于 AST 模式匹配单点检出)
              </div>
              <div v-else class="flex flex-col gap-1.5">
                <div 
                  v-for="(step, index) in dangerPoints" 
                  :key="step.key"
                  :class="[
                    'p-2 rounded border transition-all cursor-pointer flex items-center justify-between text-xs',
                    activeStepIndex === index 
                      ? 'border-amber-500 bg-amber-50/70 font-medium shadow-xs' 
                      : 'border-zinc-200 hover:border-zinc-300 bg-zinc-50/40 hover:bg-zinc-50'
                  ]"
                  @click="selectStep(step, index)"
                >
                  <div class="flex items-center gap-2.5 truncate flex-1 pr-2">
                    <span class="flex items-center justify-center w-5 h-5 rounded-full bg-zinc-200 text-zinc-700 font-bold font-mono text-[10px] shrink-0">
                      {{ index + 1 }}
                    </span>
                    <a-tag 
                      :color="step.point_type === 'source' ? 'green' : step.point_type === 'sink' ? 'red' : 'blue'" 
                      class="font-bold scale-90 m-0 shrink-0"
                    >
                      {{ step.point_type.toUpperCase() }}
                    </a-tag>
                    <span class="font-mono text-zinc-700 truncate text-[11px]">{{ step.file_path }}</span>
                    <span v-if="step.message" class="text-zinc-500 truncate text-[11px] font-sans">({{ step.message }})</span>
                  </div>
                  <span class="font-mono text-sky-600 font-semibold shrink-0">L{{ step.start_line }}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Log Modal -->
    <a-modal
      v-model:open="logModalVisible"
      title="任务执行日志"
      :footer="null"
      width="800px"
      :body-style="{ padding: '0px' }"
      destroy-on-close
      @cancel="handleLogModalClose"
    >
      <div class="px-4 py-2 bg-zinc-900 border-b border-zinc-800 flex items-center justify-between text-xs text-zinc-400 font-mono">
        <span class="flex items-center gap-2">
          <span class="w-2 h-2 rounded-full bg-emerald-500"></span>
          日志详情
        </span>
        <span class="text-zinc-500">已加载 {{ taskLogs.length }} 行日志</span>
      </div>
      <div ref="logContainerRef" class="bg-zinc-950 text-zinc-100 p-4 font-mono text-xs overflow-auto h-[450px] leading-relaxed select-text">
        <div v-if="logLoading" class="h-full flex items-center justify-center text-zinc-400">
          正在读取日志数据...
        </div>
        <div v-else-if="taskLogs.length === 0" class="h-full flex items-center justify-center text-zinc-400">
          暂无执行日志记录
        </div>
        <div v-else>
          <div 
            v-for="(logLine, index) in taskLogs" 
            :key="index"
            :class="[logLine.includes('[ERROR]') || logLine.includes('失败') ? 'text-rose-400 font-bold' : logLine.includes('[WARNING]') ? 'text-amber-400' : 'text-zinc-300']"
            class="whitespace-pre-wrap mb-1"
          >
            {{ logLine }}
          </div>
        </div>
      </div>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { computed, nextTick, onMounted, reactive, ref } from 'vue';
import { message } from 'ant-design-vue';
import { ArrowLeft, RotateCw, Search, FileCode, ShieldAlert } from 'lucide-vue-next';
import Prism from 'prismjs';
import 'prismjs/components/prism-java';
import { 
  getScanTasks, 
  getScanVulnerabilities, 
  deleteScanTask, 
  getScanTaskLogs
} from '../../api';

interface ScanTaskRecord {
  id: number;
  status: string;
  branch: string;
  language: string;
  vuln_count: number;
  created_at: string;
  repository?: { name?: string; url?: string };
}

interface DangerPoint {
  key: string;
  step_index: number;
  point_type: 'source' | 'flow' | 'sink';
  file_path: string;
  start_line: number;
  snippet: string;
  message?: string;
}

// State variables
const viewingTaskId = ref<number | null>(null);
const viewingTaskRecord = ref<ScanTaskRecord | null>(null);
const activeVulnId = ref<number | null>(null);
const activeVuln = ref<any | null>(null);
const activeStepIndex = ref<number | null>(null);
const activeStep = ref<DangerPoint | null>(null);

// Log Viewer State
const logModalVisible = ref(false);
const logLoading = ref(false);
const taskLogs = ref<string[]>([]);
const logContainerRef = ref<HTMLDivElement | null>(null);

const scrollToLogBottom = () => {
  nextTick(() => {
    if (logContainerRef.value) {
      logContainerRef.value.scrollTop = logContainerRef.value.scrollHeight;
    }
  });
};

const handleShowLogs = async (taskId: number) => {
  logModalVisible.value = true;
  logLoading.value = true;
  taskLogs.value = [];

  try {
    const res = await getScanTaskLogs(taskId);
    const logs = res.data?.data?.logs || [];
    taskLogs.value = Array.isArray(logs) ? logs : [];
    scrollToLogBottom();
  } catch (err) {
    message.error('获取日志详情失败');
  } finally {
    logLoading.value = false;
  }
};

const handleLogModalClose = () => {
  logModalVisible.value = false;
};

const statusFilter = ref('');

// Task table pagination & data
const taskLoading = ref(false);
const taskData = ref<ScanTaskRecord[]>([]);
const taskPagination = reactive({
  current: 1,
  pageSize: 10,
  total: 0,
  showSizeChanger: true,
  showQuickJumper: true,
});

// Vulnerabilities split panel details
const vulnLoading = ref(false);
const vulnData = ref<any[]>([]);
const vulnKeyword = ref('');
const vulnSeverityFilter = ref('');
const vulnPagination = reactive({
  current: 1,
  pageSize: 20,
  total: 0,
});
const dangerPoints = ref<DangerPoint[]>([]);

// Code Viewer bindings
const activeCodeFilePath = ref('');
const activeCodeLine = ref<number | null>(null);
const activeCodeSnippet = ref('');

const taskColumns = [
  { title: 'Target', key: 'target', width: 260 },
  { title: 'Type', customRender: () => 'Git', width: 80 },
  { title: 'Status', dataIndex: 'status', key: 'status', width: 110 },
  { title: 'Start Time', dataIndex: 'created_at', key: 'created_at', width: 170 },
  { title: 'Vulnerabilities', key: 'vulns', width: 110 },
  { title: 'Action', key: 'actions', width: 160, fixed: 'right' as const },
];

const statusColor = (status: string) => {
  const s = (status || '').toLowerCase();
  const map: Record<string, string> = {
    pending: 'default',
    running: 'processing',
    success: 'success',
    failed: 'error',
  };
  return map[s] || 'default';
};

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

// Logic functions
const loadTasks = async () => {
  taskLoading.value = true;
  try {
    const res = await getScanTasks(taskPagination.current, taskPagination.pageSize, undefined, statusFilter.value || undefined);
    taskData.value = res.data.data.data || [];
    taskPagination.total = res.data.data.total || 0;
  } catch (err) {
    message.error('获取扫描任务失败');
  } finally {
    taskLoading.value = false;
  }
};

const handleTaskTableChange = (pag: any) => {
  taskPagination.current = pag.current;
  taskPagination.pageSize = pag.pageSize;
  loadTasks();
};

const handleDeleteTask = async (id: number, force: boolean = false) => {
  try {
    await deleteScanTask(id, force);
    message.success('扫描任务删除成功');
    loadTasks();
  } catch (err: any) {
    const errMsg = err?.response?.data?.error || err?.message || '删除任务失败';
    message.error(errMsg);
  }
};

// Details view functions
const enterDetailView = (taskId: number, record?: ScanTaskRecord) => {
  viewingTaskId.value = taskId;
  viewingTaskRecord.value = record || null;
  activeVulnId.value = null;
  activeVuln.value = null;
  activeStepIndex.value = null;
  activeStep.value = null;
  vulnData.value = [];
  vulnKeyword.value = '';
  vulnSeverityFilter.value = '';
  vulnPagination.current = 1;
  dangerPoints.value = [];
  activeCodeFilePath.value = '';
  activeCodeLine.value = null;
  activeCodeSnippet.value = '';
  loadVulnerabilities();
};

const exitDetailView = () => {
  viewingTaskId.value = null;
  viewingTaskRecord.value = null;
  loadTasks();
};

const loadVulnerabilities = async () => {
  if (!viewingTaskId.value) return;
  vulnLoading.value = true;
  try {
    const res = await getScanVulnerabilities(
      viewingTaskId.value, 
      vulnPagination.current, 
      vulnPagination.pageSize,
      vulnSeverityFilter.value || undefined,
      undefined,
      vulnKeyword.value || undefined
    );
    vulnData.value = res.data.data.data || [];
    vulnPagination.total = res.data.data.total || 0;
    if (vulnData.value.length > 0) {
      selectVuln(vulnData.value[0]);
    } else {
      activeVulnId.value = null;
      activeVuln.value = null;
      dangerPoints.value = [];
      activeCodeFilePath.value = '';
      activeCodeLine.value = null;
      activeCodeSnippet.value = '';
    }
  } catch (err) {
    message.error('获取分析漏洞结果失败');
  } finally {
    vulnLoading.value = false;
  }
};

const handleVulnPageChange = (page: number) => {
  vulnPagination.current = page;
  loadVulnerabilities();
};

const handleVulnSearch = () => {
  vulnPagination.current = 1;
  loadVulnerabilities();
};

const handleVulnKeywordChange = () => {
  if (!vulnKeyword.value) {
    vulnPagination.current = 1;
    loadVulnerabilities();
  }
};

const handleVulnFilterChange = () => {
  vulnPagination.current = 1;
  loadVulnerabilities();
};

const parseDataFlow = (dataFlowRaw: any): DangerPoint[] => {
  let parsed = dataFlowRaw;
  if (typeof parsed === 'string') {
    try {
      parsed = JSON.parse(parsed);
    } catch {
      parsed = [];
    }
  }
  if (!Array.isArray(parsed) || parsed.length === 0) return [];

  const path = parsed[0];
  if (!Array.isArray(path)) return [];

  return path.map((step: any, index: number) => {
    const isFirst = index === 0;
    const isLast = index === path.length - 1;
    const pointType: DangerPoint['point_type'] = isFirst ? 'source' : isLast ? 'sink' : 'flow';
    return {
      key: `step_${index}`,
      step_index: index + 1,
      point_type: pointType,
      file_path: step.file_path || '',
      start_line: Number(step.start_line || 0),
      snippet: step.snippet || '',
      message: step.message || '',
    };
  });
};

const selectVuln = (vuln: any) => {
  activeVulnId.value = vuln.id;
  activeVuln.value = vuln;
  activeStepIndex.value = null;
  activeStep.value = null;

  const steps = parseDataFlow(vuln.data_flow);
  dangerPoints.value = steps;

  activeCodeFilePath.value = vuln.file_path || '';
  activeCodeLine.value = vuln.start_line || null;
  activeCodeSnippet.value = vuln.code_snippet || '';
};

const selectStep = (step: DangerPoint, index: number) => {
  activeStepIndex.value = index;
  activeStep.value = step;

  activeCodeFilePath.value = step.file_path;
  activeCodeLine.value = step.start_line;
  // 如果步骤自带代码切片则展示，否则保留漏洞主体切片
  if (step.snippet) {
    activeCodeSnippet.value = step.snippet;
  }
};

// Java Code Syntax Highlighting with Prism.js
const escapeHtml = (str: string) => {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
};

const highlightedCodeLines = computed(() => {
  const snippet = activeCodeSnippet.value || '';
  if (!snippet) return [];
  const lines = snippet.split('\n');
  return lines.map((line) => {
    if (!line) return '&nbsp;';
    try {
      return Prism.highlight(line, Prism.languages.java || Prism.languages.javascript, 'java');
    } catch {
      return escapeHtml(line);
    }
  });
});

const snippetStartLine = computed(() => {
  if (activeStep.value && activeStep.value.snippet) {
    return Math.max(1, activeStep.value.start_line - 15);
  }
  if (activeVuln.value) {
    return Math.max(1, activeVuln.value.start_line - 15);
  }
  return 1;
});

const getLineNumber = (idx: number) => {
  return snippetStartLine.value + idx;
};

const isHighlightedLine = (idx: number) => {
  const currentLine = snippetStartLine.value + idx;
  if (activeStep.value) {
    return currentLine === activeStep.value.start_line;
  }
  if (activeVuln.value) {
    return currentLine >= activeVuln.value.start_line && currentLine <= activeVuln.value.end_line;
  }
  return false;
};

onMounted(() => {
  loadTasks();
});
</script>

<style scoped>
.scrollbar-thin::-webkit-scrollbar {
  width: 5px;
  height: 5px;
}
.scrollbar-thin::-webkit-scrollbar-thumb {
  background: #d4d4d8;
  border-radius: 4px;
}

/* Prism.js Java Syntax Highlighting Tokens (VS Code / GitHub Light Theme) */
:deep(.token.keyword) {
  color: #7c3aed;
  font-weight: 600;
}
:deep(.token.class-name) {
  color: #0284c7;
  font-weight: 600;
}
:deep(.token.string) {
  color: #16a34a;
}
:deep(.token.number) {
  color: #ea580c;
}
:deep(.token.function) {
  color: #4f46e5;
}
:deep(.token.comment) {
  color: #94a3b8;
  font-style: italic;
}
:deep(.token.operator) {
  color: #d97706;
}
:deep(.token.punctuation) {
  color: #475569;
}
:deep(.token.annotation) {
  color: #d97706;
  font-weight: 600;
}
:deep(.token.boolean) {
  color: #dc2626;
  font-weight: 600;
}
:deep(.token.property) {
  color: #0d9488;
}
</style>
