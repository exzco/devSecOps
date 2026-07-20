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
                  <a-button type="link" size="small" @click="enterDetailView(record.id)">
                    查看结果
                  </a-button>
                  <a-button type="link" size="small" @click="handleShowLogs(record.id)">
                    查看日志
                  </a-button>
                  <a-popconfirm title="确认删除该扫描任务吗？" ok-text="确认" cancel-text="取消" @confirm="handleDeleteTask(record.id)">
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

    <!-- State 2: Scan Results details -->
    <div v-else class="flex flex-col gap-4 flex-1 overflow-hidden bg-white">
      <!-- Detail Header bar -->
      <div class="flex items-center justify-between border-b border-zinc-200 pb-3 bg-white">
        <div class="flex items-center gap-3">
          <a-button type="default" size="small" @click="exitDetailView" class="!bg-white !border-zinc-200">
            <template #icon><ArrowLeftOutlined /></template>
            返回任务列表
          </a-button>
          <span class="text-md font-bold text-zinc-900">扫描结果 (任务 ID: {{ viewingTaskId }})</span>
        </div>
        <a-space>
          <a-button type="default" size="small" @click="loadVulnerabilities">
            刷新
          </a-button>
        </a-space>
      </div>

      <!-- Main Results Split layout -->
      <div class="flex-1 flex gap-4 overflow-hidden min-h-0 bg-white">
        <!-- Left panel: Rule list -->
        <div class="w-1/3 border border-zinc-200 rounded-lg bg-white flex flex-col overflow-hidden">
          <div class="p-3 border-b border-zinc-200 bg-zinc-50 text-xs font-semibold text-zinc-500">
            规则列表 (Rule ID)
          </div>
          <div class="flex-1 overflow-y-auto divide-y divide-zinc-100 scrollbar-thin">
            <div 
              v-for="item in vulnData" 
              :key="item.id"
              :class="['p-3.5 cursor-pointer flex items-center justify-between transition-colors', activeVulnId === item.id ? 'bg-zinc-100/70 font-semibold' : 'hover:bg-zinc-50']"
              @click="selectVuln(item)"
            >
              <div class="flex items-center gap-1 flex-1 truncate pr-2">
                <span class="font-mono text-xs text-zinc-800 truncate">{{ item.rule_id }}</span>
                <a-tag v-if="item.ai_result || item.status === 'ai_triaged'" color="purple" class="font-bold scale-90 shrink-0">
                  AI已验证
                </a-tag>
              </div>
              <a-tag :color="severityColor(item.severity)" class="font-semibold uppercase scale-90 scale-origin-right">
                {{ item.severity }}
              </a-tag>
            </div>
            <div v-if="vulnData.length === 0" class="p-8 text-center text-zinc-400 text-xs">
              该任务没有检测出任何漏洞记录。
            </div>
          </div>
        </div>

        <!-- Right panel: Code Viewer + Steps -->
        <div class="flex-1 flex flex-col gap-4 overflow-hidden">
          <!-- Top part: Code Viewer -->
          <div class="flex-1 border border-zinc-200 rounded-lg bg-zinc-50 flex flex-col overflow-hidden min-h-0">
            <div class="p-3 border-b border-zinc-200 bg-zinc-100/70 flex items-center justify-between text-xs text-zinc-500 font-mono">
              <span class="truncate flex-1 pr-2">{{ activeCodeFilePath || '暂无选中的代码文件' }}</span>
              <span v-if="activeCodeLine" class="text-sky-600 font-bold">Line: {{ activeCodeLine }}</span>
            </div>
            <div class="flex-1 overflow-auto bg-zinc-50 p-4 font-mono text-xs scrollbar-thin relative min-h-0">
              <div v-if="codeLines.length === 0" class="h-full flex items-center justify-center text-zinc-400 text-xs">
                请选择左侧漏洞以查看相关受污染代码片段
              </div>
              <div v-else>
                <div 
                  v-for="(line, idx) in codeLines" 
                  :key="idx"
                  :class="['flex items-start py-0.5 px-2 font-mono leading-5 transition-colors', isHighlightedLine(idx) ? 'bg-amber-100 border-l-2 border-amber-600 text-amber-950 font-semibold' : 'text-zinc-800']"
                >
                  <span class="w-12 text-right text-zinc-400 select-none pr-3 border-r border-zinc-200 mr-3">{{ getLineNumber(idx) }}</span>
                  <span class="whitespace-pre break-all flex-1">{{ line }}</span>
                </div>
              </div>
            </div>
          </div>

          <!-- Bottom part: Taint Flow trace steps & AI Audit Result -->
          <div class="h-[280px] border border-zinc-200 rounded-lg bg-white flex flex-col overflow-hidden">
            <a-tabs v-model:activeKey="bottomTabKey" class="flex-1 flex flex-col px-3 pt-1 border-b-none" size="small">
              <a-tab-pane key="taint" tab="污点追踪分析 (Taint Flow Trace)">
                <div class="p-2 overflow-y-auto max-h-[220px] scrollbar-thin">
                  <div v-if="dangerPoints.length === 0" class="h-full py-8 text-center text-zinc-400 text-xs">
                    无追踪链路或该隐患没有发生变量污染传递
                  </div>
                  <div v-else class="flex flex-col gap-2">
                    <div 
                      v-for="(step, index) in dangerPoints" 
                      :key="step.key"
                      :class="['p-2.5 rounded border transition-colors cursor-pointer flex items-center justify-between text-xs', activeStepIndex === index ? 'border-amber-500 bg-amber-50/50' : 'border-zinc-200 hover:border-zinc-300 bg-zinc-50/50']"
                      @click="selectStep(step, index)"
                    >
                      <div class="flex items-center gap-3">
                        <span class="flex items-center justify-center w-5 h-5 rounded-full bg-zinc-200 text-zinc-600 font-bold font-mono text-[10px]">{{ index + 1 }}</span>
                        <a-tag :color="step.point_type === 'source' ? 'green' : step.point_type === 'sink' ? 'red' : 'blue'" class="font-bold scale-90">
                          {{ step.point_type.toUpperCase() }}
                        </a-tag>
                        <span class="font-mono text-zinc-800 truncate max-w-[400px]">{{ step.file_path }}</span>
                      </div>
                      <span class="font-mono text-sky-600 font-semibold">L{{ step.start_line }}</span>
                    </div>
                  </div>
                </div>
              </a-tab-pane>

              <a-tab-pane key="ai" tab=" AI 分析">
                <div class="p-2 overflow-y-auto max-h-[220px] scrollbar-thin text-xs leading-relaxed select-text">
                  <div v-if="!parsedAiResult" class="h-full py-8 text-center text-zinc-400 text-xs">
                    暂无 AI 验证结果。
                  </div>
                  <div v-else class="flex flex-col gap-3">
                    <div v-if="parsedAiResult.vulnerability_report" class="bg-purple-50/50 p-3 rounded border border-purple-100">
                      <div class="font-bold text-purple-900 mb-1">📋 漏洞成因分析报告：</div>
                      <div class="text-zinc-700 whitespace-pre-wrap">{{ parsedAiResult.vulnerability_report }}</div>
                    </div>

                    <div v-if="parsedAiResult.wsl_docker_script" class="bg-zinc-950 text-zinc-100 p-3 rounded font-mono text-[11px] relative">
                      <div class="flex items-center justify-between border-b border-zinc-800 pb-1 mb-2 text-zinc-400 text-[10px]">
                        <span>🐳 WSL Docker 靶场复现脚本</span>
                        <a-button type="link" size="small" class="!text-xs !p-0 !text-purple-400" @click="copyScript(parsedAiResult.wsl_docker_script)">
                          复制脚本
                        </a-button>
                      </div>
                      <pre class="whitespace-pre-wrap break-all select-all text-emerald-400">{{ parsedAiResult.wsl_docker_script }}</pre>
                    </div>

                    <div v-if="parsedAiResult.reproduce_steps" class="bg-zinc-50 p-3 rounded border border-zinc-200">
                      <div class="font-bold text-zinc-800 mb-1">🛠️ 手动复现步骤 (PoC)：</div>
                      <div class="text-zinc-700 whitespace-pre-wrap font-mono">{{ parsedAiResult.reproduce_steps }}</div>
                    </div>

                    <div v-if="parsedAiResult.verify_steps" class="bg-emerald-50/50 p-3 rounded border border-emerald-100">
                      <div class="font-bold text-emerald-900 mb-1">✅ 安全防御验证逻辑：</div>
                      <div class="text-zinc-700 whitespace-pre-wrap">{{ parsedAiResult.verify_steps }}</div>
                    </div>
                  </div>
                </div>
              </a-tab-pane>
            </a-tabs>
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
    >
      <div class="bg-zinc-950 text-zinc-100 p-4 font-mono text-xs overflow-auto h-[450px] leading-relaxed select-text">
        <div v-if="logLoading" class="h-full flex items-center justify-center text-zinc-400">
          加载日志中...
        </div>
        <div v-else-if="taskLogs.length === 0" class="h-full flex items-center justify-center text-zinc-400">
          无可用日志
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
import { computed, onMounted, reactive, ref } from 'vue';
import { message } from 'ant-design-vue';
import { 
  ArrowLeftOutlined 
} from '@ant-design/icons-vue';
import { 
  getScanTasks, 
  getScanVulnerabilities, 
  deleteScanTask, 
  addRepo, 
  triggerScan,
  getRepoList,
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
const activeVulnId = ref<number | null>(null);
const activeVuln = ref<any | null>(null);
const activeStepIndex = ref<number | null>(null);
const activeStep = ref<DangerPoint | null>(null);
const bottomTabKey = ref('taint');

const parsedAiResult = computed(() => {
  if (!activeVuln.value || !activeVuln.value.ai_result) return null;
  let raw = activeVuln.value.ai_result;
  if (typeof raw === 'string') {
    try {
      raw = JSON.parse(raw);
    } catch {
      return null;
    }
  }
  return raw;
});

const copyScript = (text: string) => {
  if (!text) return;
  navigator.clipboard.writeText(text);
  message.success('已复制 WSL Docker 脚本到剪贴板');
};

// Log Viewer State
const logModalVisible = ref(false);
const logLoading = ref(false);
const taskLogs = ref<string[]>([]);

const handleShowLogs = async (taskId: number) => {
  logModalVisible.value = true;
  logLoading.value = true;
  taskLogs.value = [];
  try {
    const res = await getScanTaskLogs(taskId);
    taskLogs.value = res.data.data.logs || [];
  } catch (err) {
    message.error('获取扫描日志失败');
  } finally {
    logLoading.value = false;
  }
};

// Forms & Filter
const scanForm = reactive({
  url: '',
  branch: 'main',
  language: 'go',
  rules: {
    cwe078: true,
    cwe502: false,
    cwe094: true,
    cwe918: false,
    cwe611: false,
    cwe089: true,
    cwe079: true,
  },
  enableAi: false,
});

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

const submitLoading = ref(false);

const handleStartScan = async () => {
  const url = scanForm.url.trim();
  if (!url) {
    message.error('Repository URL 不能为空');
    return;
  }

  submitLoading.value = true;
  try {
    const reposRes = await getRepoList(1, 100);
    const repos = reposRes.data.data.data || [];
    let repo = repos.find((r: any) => r.url === url);

    let repoId: number;
    if (repo) {
      repoId = repo.id;
    } else {
      const parts = url.split('/');
      let name = parts[parts.length - 1].replace(/\.git$/i, '') || 'manual-repo';
      
      const createRes = await addRepo({
        name: name,
        url: url,
        branch: scanForm.branch.trim() || 'main',
        language: scanForm.language,
        auth_type: 'none',
      });
      repoId = createRes.data.data.id;
    }

    await triggerScan({
      repo_id: repoId,
      branch: scanForm.branch.trim() || 'main',
      language: scanForm.language,
      rule_profile: 'baseline',
    });

    message.success('静态审计扫描任务已提交执行');
    scanForm.url = '';
    loadTasks();
  } catch (err: any) {
    const errMsg = err.response?.data?.error || '启动扫描任务失败';
    message.error(errMsg);
  } finally {
    submitLoading.value = false;
  }
};

const handleDeleteTask = async (id: number) => {
  try {
    await deleteScanTask(id);
    message.success('扫描任务删除成功');
    loadTasks();
  } catch (err) {
    message.error('删除任务失败');
  }
};

// Details view functions
const enterDetailView = (taskId: number) => {
  viewingTaskId.value = taskId;
  activeVulnId.value = null;
  activeVuln.value = null;
  activeStepIndex.value = null;
  activeStep.value = null;
  vulnData.value = [];
  dangerPoints.value = [];
  activeCodeFilePath.value = '';
  activeCodeLine.value = null;
  activeCodeSnippet.value = '';
  loadVulnerabilities();
};

const exitDetailView = () => {
  viewingTaskId.value = null;
  loadTasks();
};

const loadVulnerabilities = async () => {
  if (!viewingTaskId.value) return;
  vulnLoading.value = true;
  try {
    const res = await getScanVulnerabilities(viewingTaskId.value, 1, 100);
    vulnData.value = res.data.data.data || [];
    if (vulnData.value.length > 0) {
      selectVuln(vulnData.value[0]);
    }
  } catch (err) {
    message.error('获取分析漏洞结果失败');
  } finally {
    vulnLoading.value = false;
  }
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
  activeCodeSnippet.value = step.snippet || '';
};

// Code Viewer calculations
const codeLines = computed(() => {
  return (activeCodeSnippet.value || '').split('\n');
});

const snippetStartLine = computed(() => {
  if (activeStep.value) {
    // worker.go 从 stepStart - 15 开始取
    return Math.max(1, activeStep.value.start_line - 15);
  }
  if (activeVuln.value) {
    // worker.go 从 startLine - 15 开始取
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
  width: 4px;
  height: 4px;
}
.scrollbar-thin::-webkit-scrollbar-thumb {
  background: #e4e4e7;
}
</style>
