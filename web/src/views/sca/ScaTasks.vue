<template>
  <div class="space-y-6">
    <!-- Header banner -->
    <div class="flex items-center justify-between pb-4 border-b border-zinc-200">
      <div>
        <h1 class="text-xl font-bold tracking-tight text-zinc-900">SCA 依赖与漏洞分析</h1>
        <p class="text-xs text-zinc-500 mt-1">
          支持多语言组件分析（Go、Python、Java、JavaScript、Rust）与 Google OSV 漏洞情报实时比对
        </p>
      </div>
      <div class="flex items-center gap-3">
        <a-button @click="fetchTasks" :loading="loading">
          <template #icon><RotateCw :size="14" class="inline-block" /></template>
          刷新
        </a-button>
        <a-button type="primary" class="bg-zinc-900 hover:bg-zinc-800" @click="showCreateModal = true">
          <template #icon><Plus :size="14" class="inline-block" /></template>
          新建 SCA 分析
        </a-button>
      </div>
    </div>

    <!-- Tasks Table -->
    <div class="rounded-lg border border-zinc-200 bg-white overflow-hidden shadow-sm">
      <a-table
        :dataSource="tasks"
        :columns="columns"
        :loading="loading"
        rowKey="id"
        :pagination="pagination"
        @change="handleTableChange"
        size="middle"
      >
        <!-- Task ID -->
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'id'">
            <span class="font-mono text-xs font-semibold text-zinc-800">#{{ record.id }}</span>
          </template>

          <!-- Target / Repo -->
          <template v-else-if="column.key === 'target'">
            <div class="flex flex-col">
              <span v-if="record.repo_id" class="text-xs font-medium text-zinc-800">
                仓库 ID: {{ record.repo_id }} (分支: {{ record.branch || 'main' }})
              </span>
              <span v-else class="text-xs font-mono text-zinc-600 truncate max-w-xs">
                {{ record.target_dir || '本地目录' }}
              </span>
            </div>
          </template>

          <!-- Language -->
          <template v-else-if="column.key === 'language'">
            <a-tag :color="getLangColor(record.language)" class="text-xs uppercase font-medium">
              {{ record.language || 'AUTO' }}
            </a-tag>
          </template>

          <!-- Status -->
          <template v-else-if="column.key === 'status'">
            <a-badge
              :status="getStatusBadge(record.status)"
              :text="getStatusText(record.status)"
              class="font-medium text-xs"
            />
          </template>

          <!-- Total Dependencies -->
          <template v-else-if="column.key === 'total_deps'">
            <span class="font-mono text-xs text-zinc-700 font-semibold">{{ record.total_deps }}</span>
          </template>

          <!-- Vulnerabilities Breakdown -->
          <template v-else-if="column.key === 'vulns'">
            <div class="flex items-center gap-1.5 flex-wrap">
              <span v-if="record.vuln_count === 0" class="text-xs text-emerald-600 font-medium">
                无已知漏洞
              </span>
              <template v-else>
                <a-tag v-if="record.critical_count > 0" color="red" class="text-xs font-bold px-1.5">
                  CRIT: {{ record.critical_count }}
                </a-tag>
                <a-tag v-if="record.high_count > 0" color="orange" class="text-xs font-bold px-1.5">
                  HIGH: {{ record.high_count }}
                </a-tag>
                <a-tag v-if="record.medium_count > 0" color="gold" class="text-xs font-medium px-1.5">
                  MED: {{ record.medium_count }}
                </a-tag>
                <a-tag v-if="record.low_count > 0" color="blue" class="text-xs font-medium px-1.5">
                  LOW: {{ record.low_count }}
                </a-tag>
              </template>
            </div>
          </template>

          <!-- Duration -->
          <template v-else-if="column.key === 'duration_ms'">
            <span class="text-xs text-zinc-500 font-mono">
              {{ record.duration_ms ? (record.duration_ms / 1000).toFixed(2) + 's' : '-' }}
            </span>
          </template>

          <!-- Created At -->
          <template v-else-if="column.key === 'created_at'">
            <span class="text-xs text-zinc-500">{{ formatDate(record.created_at) }}</span>
          </template>

          <!-- Actions -->
          <template v-else-if="column.key === 'actions'">
            <div class="flex items-center gap-2">
              <a-button type="link" size="small" class="text-xs px-1" @click="viewDetail(record)">
                查看详情
              </a-button>
            </div>
          </template>
        </template>
      </a-table>
    </div>

    <!-- Create Task Modal -->
    <a-modal
      v-model:visible="showCreateModal"
      title="发起 SCA 依赖成分分析"
      @ok="handleCreateTask"
      :confirmLoading="submitting"
      okText="立即分析"
      cancelText="取消"
    >
      <a-form layout="vertical" class="mt-4">
        <a-form-item label="分析来源模式" required>
          <a-radio-group v-model:value="sourceMode">
            <a-radio value="repo">已注册代码仓库</a-radio>
            <a-radio value="local">本地工程目录路径</a-radio>
          </a-radio-group>
        </a-form-item>

        <a-form-item v-if="sourceMode === 'repo'" label="选择仓库" required>
          <a-select v-model:value="form.repo_id" placeholder="请选择已注册的代码仓库" :loading="reposLoading">
            <a-select-option v-for="r in repos" :key="r.id" :value="r.id">
              {{ r.name }} ({{ r.language || '未知语言' }})
            </a-select-option>
          </a-select>
        </a-form-item>

        <a-form-item v-else label="工程根目录绝对路径" required>
          <a-input v-model:value="form.target" placeholder="如: /mnt/c/Users/project 或 ." />
        </a-form-item>

        <a-form-item v-if="sourceMode === 'repo'" label="Git 分支">
          <a-input v-model:value="form.branch" placeholder="main" />
        </a-form-item>

        <a-form-item label="主开发语言 / 生态">
          <a-select v-model:value="form.language" placeholder="auto (全自动识别)">
            <a-select-option value="auto">自动识别 (Auto Detect)</a-select-option>
            <a-select-option value="go">Go (go.mod / go.sum)</a-select-option>
            <a-select-option value="python">Python (requirements.txt / pyproject.toml)</a-select-option>
            <a-select-option value="java">Java (pom.xml / build.gradle)</a-select-option>
            <a-select-option value="javascript">JavaScript / TypeScript (npm / yarn)</a-select-option>
            <a-select-option value="rust">Rust (Cargo.lock / Cargo.toml)</a-select-option>
          </a-select>
        </a-form-item>
      </a-form>
    </a-modal>

    <!-- Detail Drawer -->
    <a-drawer
      v-model:visible="showDetailDrawer"
      :title="`SCA 任务详情 #${activeTask?.id || ''}`"
      width="820"
      placement="right"
    >
      <div v-if="activeTask" class="space-y-6">
        <!-- Summary Cards -->
        <div class="grid grid-cols-4 gap-3">
          <div class="p-3 rounded-lg border border-zinc-200 bg-zinc-50">
            <div class="text-xs text-zinc-500 font-medium">依赖总数</div>
            <div class="text-lg font-bold text-zinc-900 mt-1 font-mono">{{ activeTask.total_deps }}</div>
          </div>
          <div class="p-3 rounded-lg border border-red-200 bg-red-50/50">
            <div class="text-xs text-red-600 font-medium">严重 / 高危</div>
            <div class="text-lg font-bold text-red-700 mt-1 font-mono">
              {{ (activeTask.critical_count || 0) + (activeTask.high_count || 0) }}
            </div>
          </div>
          <div class="p-3 rounded-lg border border-amber-200 bg-amber-50/50">
            <div class="text-xs text-amber-600 font-medium">中危 / 低危</div>
            <div class="text-lg font-bold text-amber-700 mt-1 font-mono">
              {{ (activeTask.medium_count || 0) + (activeTask.low_count || 0) }}
            </div>
          </div>
          <div class="p-3 rounded-lg border border-zinc-200 bg-zinc-50">
            <div class="text-xs text-zinc-500 font-medium">分析耗时</div>
            <div class="text-lg font-bold text-zinc-800 mt-1 font-mono">
              {{ activeTask.duration_ms ? (activeTask.duration_ms / 1000).toFixed(2) + 's' : '-' }}
            </div>
          </div>
        </div>

        <!-- Detail Tabs -->
        <a-tabs defaultActiveKey="vulns">
          <!-- Vulnerabilities Tab -->
          <a-tab-pane key="vulns" :tab="`漏洞发现 (${taskVulns.length})`">
            <a-table
              :dataSource="taskVulns"
              :columns="vulnColumns"
              :loading="detailLoading"
              rowKey="id"
              size="small"
              :pagination="{ pageSize: 10 }"
            >
              <template #bodyCell="{ column, record }">
                <template v-if="column.key === 'severity'">
                  <a-tag :color="getSeverityColor(record.severity)" class="font-bold text-xs uppercase">
                    {{ record.severity }}
                  </a-tag>
                </template>
                <template v-else-if="column.key === 'vuln_id'">
                  <div class="flex flex-col">
                    <span class="font-mono font-semibold text-xs text-blue-600">{{ record.vuln_id }}</span>
                    <span v-if="record.aliases" class="text-[10px] text-zinc-400 font-mono truncate max-w-[120px]">
                      {{ record.aliases }}
                    </span>
                  </div>
                </template>
                <template v-else-if="column.key === 'component'">
                  <div class="flex flex-col">
                    <span class="text-xs font-medium text-zinc-900">{{ record.dependency_name }}</span>
                    <span class="text-[11px] text-zinc-500 font-mono">v{{ record.current_version }}</span>
                  </div>
                </template>
                <template v-else-if="column.key === 'fixed_version'">
                  <span v-if="record.fixed_version" class="text-xs font-mono font-semibold text-emerald-600">
                    {{ record.fixed_version }}
                  </span>
                  <span v-else class="text-xs text-zinc-400">无已知修复</span>
                </template>
                <template v-else-if="column.key === 'summary'">
                  <p class="text-xs text-zinc-600 line-clamp-2" :title="record.summary">
                    {{ record.summary || record.title || '无摘要信息' }}
                  </p>
                </template>
              </template>
            </a-table>
          </a-tab-pane>

          <!-- Dependencies Tab -->
          <a-tab-pane key="deps" :tab="`依赖列表 (${taskDeps.length})`">
            <a-table
              :dataSource="taskDeps"
              :columns="depColumns"
              :loading="detailLoading"
              rowKey="id"
              size="small"
              :pagination="{ pageSize: 15 }"
            >
              <template #bodyCell="{ column, record }">
                <template v-if="column.key === 'ecosystem'">
                  <a-tag :color="getLangColor(record.ecosystem)" class="text-xs font-mono">
                    {{ record.ecosystem }}
                  </a-tag>
                </template>
                <template v-else-if="column.key === 'direct'">
                  <a-tag :color="record.direct ? 'blue' : 'default'" class="text-xs">
                    {{ record.direct ? '直接依赖' : '间接依赖' }}
                  </a-tag>
                </template>
                <template v-else-if="column.key === 'vuln_count'">
                  <a-badge
                    :count="record.vuln_count"
                    :number-style="{ backgroundColor: record.vuln_count > 0 ? '#ef4444' : '#10b981' }"
                  />
                </template>
              </template>
            </a-table>
          </a-tab-pane>

          <!-- Logs Tab -->
          <a-tab-pane key="logs" tab="执行日志">
            <div class="rounded-lg bg-zinc-900 p-4 font-mono text-xs text-zinc-200 overflow-x-auto max-h-96 whitespace-pre-wrap">
              {{ activeTask.execution_log || '暂无日志' }}
            </div>
          </a-tab-pane>
        </a-tabs>
      </div>
    </a-drawer>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { message } from 'ant-design-vue'
import { RotateCw, Plus } from 'lucide-vue-next'
import {
  getScaTasks,
  createScaTask,
  getScaDependencies,
  getScaVulnerabilities,
  getRepoList
} from '@/api'

const loading = ref(false)
const tasks = ref<any[]>([])
const pagination = reactive({
  current: 1,
  pageSize: 20,
  total: 0,
})

const columns = [
  { title: '任务 ID', key: 'id', width: 90 },
  { title: '分析目标', key: 'target', width: 220 },
  { title: '语言生态', key: 'language', width: 110 },
  { title: '执行状态', key: 'status', width: 110 },
  { title: '依赖数', key: 'total_deps', width: 90 },
  { title: '漏洞概况', key: 'vulns', width: 220 },
  { title: '耗时', key: 'duration_ms', width: 90 },
  { title: '创建时间', key: 'created_at', width: 160 },
  { title: '操作', key: 'actions', width: 150 },
]

// Modal & Form state
const showCreateModal = ref(false)
const submitting = ref(false)
const sourceMode = ref<'repo' | 'local'>('repo')
const repos = ref<any[]>([])
const reposLoading = ref(false)

const form = reactive({
  repo_id: undefined as number | undefined,
  target: '',
  branch: 'main',
  language: 'auto',
})

// Detail drawer state
const showDetailDrawer = ref(false)
const activeTask = ref<any>(null)
const taskDeps = ref<any[]>([])
const taskVulns = ref<any[]>([])
const detailLoading = ref(false)

const depColumns = [
  { title: '组件名称', dataIndex: 'name', key: 'name' },
  { title: '版本', dataIndex: 'version', key: 'version', width: 120 },
  { title: '生态', dataIndex: 'ecosystem', key: 'ecosystem', width: 100 },
  { title: '依赖属性', key: 'direct', width: 100 },
  { title: '关联漏洞', key: 'vuln_count', width: 90 },
]

const vulnColumns = [
  { title: '级别', key: 'severity', width: 95 },
  { title: '漏洞编号', key: 'vuln_id', width: 140 },
  { title: '影响组件', key: 'component', width: 180 },
  { title: '修复版本', key: 'fixed_version', width: 110 },
  { title: '漏洞摘要', key: 'summary' },
]

const fetchTasks = async () => {
  loading.value = true
  try {
    const res = await getScaTasks(pagination.current, pagination.pageSize)
    const data = res.data?.data || {}
    tasks.value = data.items || []
    pagination.total = data.total || 0
  } catch (err: any) {
    message.error('获取 SCA 任务列表失败: ' + (err.message || '网络异常'))
  } finally {
    loading.value = false
  }
}

const fetchRepos = async () => {
  reposLoading.value = true
  try {
    const res = await getRepoList(1, 100)
    repos.value = res.data?.data?.items || []
  } catch (err) {
    console.error('Failed to load repos', err)
  } finally {
    reposLoading.value = false
  }
}

const handleTableChange = (pag: any) => {
  pagination.current = pag.current
  pagination.pageSize = pag.pageSize
  fetchTasks()
}

const handleCreateTask = async () => {
  if (sourceMode.value === 'repo' && !form.repo_id) {
    message.warning('请选择需要分析的代码仓库')
    return
  }
  if (sourceMode.value === 'local' && !form.target.trim()) {
    message.warning('请输入有效的工程目录绝对路径')
    return
  }

  submitting.value = true
  try {
    const payload: any = {
      language: form.language,
      branch: form.branch,
    }
    if (sourceMode.value === 'repo') {
      payload.repo_id = form.repo_id
    } else {
      payload.target = form.target
    }

    await createScaTask(payload)
    message.success('SCA 分析任务已提交！')
    showCreateModal.value = false
    fetchTasks()
  } catch (err: any) {
    message.error('提交失败: ' + (err.response?.data?.error || err.message))
  } finally {
    submitting.value = false
  }
}

const viewDetail = async (record: any) => {
  activeTask.value = record
  showDetailDrawer.value = true
  detailLoading.value = true
  try {
    const [depsRes, vulnsRes] = await Promise.all([
      getScaDependencies(record.id),
      getScaVulnerabilities(record.id),
    ])
    taskDeps.value = depsRes.data?.data || []
    taskVulns.value = vulnsRes.data?.data || []
  } catch (err: any) {
    message.error('获取详情失败: ' + err.message)
  } finally {
    detailLoading.value = false
  }
}

const getStatusBadge = (status: string) => {
  switch (status) {
    case 'success':
      return 'success'
    case 'running':
      return 'processing'
    case 'failed':
      return 'error'
    default:
      return 'default'
  }
}

const getStatusText = (status: string) => {
  switch (status) {
    case 'success':
      return '已完成'
    case 'running':
      return '分析中'
    case 'failed':
      return '失败'
    default:
      return '排队中'
  }
}

const getSeverityColor = (sev: string) => {
  switch (sev?.toUpperCase()) {
    case 'CRITICAL':
      return 'red'
    case 'HIGH':
      return 'orange'
    case 'MEDIUM':
      return 'gold'
    case 'LOW':
      return 'blue'
    default:
      return 'default'
  }
}

const getLangColor = (lang: string) => {
  switch (lang?.toLowerCase()) {
    case 'go':
      return 'cyan'
    case 'python':
      return 'blue'
    case 'java':
    case 'maven':
      return 'orange'
    case 'javascript':
    case 'npm':
      return 'green'
    case 'rust':
    case 'crates.io':
      return 'purple'
    default:
      return 'default'
  }
}

const formatDate = (dateStr: string) => {
  if (!dateStr) return '-'
  const d = new Date(dateStr)
  return d.toLocaleString()
}

onMounted(() => {
  fetchTasks()
  fetchRepos()
})
</script>
