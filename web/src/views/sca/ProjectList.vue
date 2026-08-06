<template>
  <div class="space-y-6">
    <!-- Header Action Bar -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-bold tracking-tight text-zinc-950">SCA 软件成分分析</h1>
        <p class="mt-1 text-sm text-zinc-500">管理代码工程并自动化扫描项目依赖组件的已知安全漏洞 (CVE)</p>
      </div>
      <a-button type="primary" class="flex items-center gap-1.5 font-medium shadow-none" @click="showModal = true">
        <template #icon><PlusOutlined /></template>
        新增 SCA 工程
      </a-button>
    </div>

    <!-- Stats summary Cards -->
    <div class="grid grid-cols-1 gap-4 md:grid-cols-3">
      <div class="rounded-md border border-zinc-200 bg-white p-5">
        <div class="text-xs font-semibold text-zinc-500 uppercase tracking-wider">监测工程总数</div>
        <div class="mt-2 text-2xl font-bold text-zinc-950">{{ totalProjects }}</div>
      </div>
      <div class="rounded-md border border-zinc-200 bg-white p-5">
        <div class="text-xs font-semibold text-zinc-500 uppercase tracking-wider">扫描成功数</div>
        <div class="mt-2 text-2xl font-bold text-zinc-950">{{ successScanCount }}</div>
      </div>
      <div class="rounded-md border border-zinc-200 bg-white p-5">
        <div class="text-xs font-semibold text-zinc-500 uppercase tracking-wider">发现依赖漏洞</div>
        <div class="mt-2 text-2xl font-bold text-zinc-950">{{ totalVulnsCount }}</div>
      </div>
    </div>

    <!-- Main Table Card -->
    <div class="rounded-md border border-zinc-200 bg-white">
      <a-table
        :columns="columns"
        :data-source="projects"
        :loading="loading"
        :row-key="(record: any) => record.id"
        :pagination="pagination"
        :scroll="{ x: 'max-content' }"
        @change="handleTableChange"
      >
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'name'">
            <div class="font-semibold text-zinc-900">{{ record.name }}</div>
            <div class="text-xs text-zinc-500">{{ record.git_url }}</div>
          </template>

          <template v-if="column.key === 'language'">
            <a-tag class="border-zinc-200 bg-zinc-50 font-mono text-zinc-800">
              {{ record.language || 'go' }}
            </a-tag>
          </template>

          <template v-if="column.key === 'last_scan_status'">
            <span
              v-if="record.last_scan_status === 'success'"
              class="inline-flex items-center gap-1.5 rounded-full bg-emerald-50 px-2.5 py-0.5 text-xs font-medium text-emerald-700 border border-emerald-200"
            >
              <CheckCircleOutlined /> 扫描成功
            </span>
            <span
              v-else-if="record.last_scan_status === 'running'"
              class="inline-flex items-center gap-1.5 rounded-full bg-amber-50 px-2.5 py-0.5 text-xs font-medium text-amber-700 border border-amber-200"
            >
              <SyncOutlined spin /> 扫描中
            </span>
            <span
              v-else
              class="inline-flex items-center gap-1.5 rounded-full bg-zinc-100 px-2.5 py-0.5 text-xs font-medium text-zinc-600 border border-zinc-200"
            >
              未扫描
            </span>
          </template>

          <template v-if="column.key === 'vulnerability_count'">
            <span class="font-bold text-zinc-950">
              {{ record.vulnerability_count || 0 }}
            </span>
          </template>

          <template v-if="column.key === 'action'">
            <div class="flex items-center gap-2">
              <a-button type="link" size="small" class="p-0 text-zinc-950 font-medium" @click="handleScan(record.id)">
                发起扫描
              </a-button>

              <a-popconfirm title="确定删除该工程吗？" @confirm="handleDelete(record.id)">
                <a-button type="link" danger size="small" class="p-0">
                  删除
                </a-button>
              </a-popconfirm>
            </div>
          </template>
        </template>
      </a-table>
    </div>

    <!-- Create Project Modal -->
    <a-modal
      v-model:open="showModal"
      title="新增 SCA 软件工程"
      :confirm-loading="submitLoading"
      @ok="handleCreateProject"
    >
      <a-form layout="vertical" class="mt-4">
        <a-form-item label="工程名称" required>
          <a-input v-model:value="form.name" placeholder="例如: backend-service" />
        </a-form-item>
        <a-form-item label="Git 仓库地址" required>
          <a-input v-model:value="form.git_url" placeholder="https://github.com/org/repo.git" />
        </a-form-item>
        <a-form-item label="默认分支">
          <a-input v-model:value="form.branch" placeholder="main" />
        </a-form-item>
        <a-form-item label="主要语言">
          <a-select v-model:value="form.language">
            <a-select-option value="go">Go (go.mod)</a-select-option>
            <a-select-option value="python">Python (requirements.txt)</a-select-option>
            <a-select-option value="javascript">JavaScript/Node.js (package.json)</a-select-option>
          </a-select>
        </a-form-item>
        <a-form-item label="工程描述">
          <a-textarea v-model:value="form.description" :rows="3" placeholder="描述工程主要依赖及业务用途" />
        </a-form-item>
      </a-form>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { message } from 'ant-design-vue'
import { CheckCircleOutlined, PlusOutlined, SyncOutlined } from '@ant-design/icons-vue'
import { createScaProject, deleteScaProject, getScaProjects, triggerScaScan } from '../../api/sca'

const loading = ref(false)
const submitLoading = ref(false)
const showModal = ref(false)
const projects = ref<any[]>([])
const totalProjects = ref(0)
const successScanCount = ref(0)
const totalVulnsCount = ref(0)

const form = reactive({
  name: '',
  git_url: '',
  branch: 'main',
  language: 'go',
  description: '',
})

const pagination = reactive({
  current: 1,
  pageSize: 10,
  total: 0,
  showSizeChanger: true,
})

const columns = [
  { title: '工程名称 / 仓库', key: 'name', width: 260 },
  { title: '语言', key: 'language', width: 120 },
  { title: '扫描状态', key: 'last_scan_status', width: 140 },
  { title: '漏洞发现数', key: 'vulnerability_count', width: 120 },
  { title: '创建时间', dataIndex: 'created_at', key: 'created_at', width: 180 },
  { title: '操作', key: 'action', width: 160, fixed: 'right' },
]

const fetchProjects = async () => {
  loading.value = true
  try {
    const res: any = await getScaProjects(pagination.current, pagination.pageSize)
    if (res.code === 0 && res.data) {
      projects.value = res.data.items || []
      pagination.total = res.data.total || 0
      totalProjects.value = res.data.total || 0
      successScanCount.value = projects.value.filter((p: any) => p.last_scan_status === 'success').length
    }
  } catch (err: any) {
    message.error('加载 SCA 工程列表失败: ' + (err.message || '未知错误'))
  } finally {
    loading.value = false
  }
}

const handleTableChange = (pag: any) => {
  pagination.current = pag.current
  pagination.pageSize = pag.pageSize
  fetchProjects()
}

const handleCreateProject = async () => {
  if (!form.name || !form.git_url) {
    message.warning('请补充工程名称和 Git 地址')
    return
  }
  submitLoading.value = true
  try {
    const res: any = await createScaProject(form)
    if (res.code === 0) {
      message.success('创建 SCA 工程成功')
      showModal.value = false
      form.name = ''
      form.git_url = ''
      form.description = ''
      fetchProjects()
    }
  } catch (err: any) {
    message.error('创建失败: ' + err.message)
  } finally {
    submitLoading.value = false
  }
}

const handleScan = async (projectId: number) => {
  try {
    const res: any = await triggerScaScan(projectId)
    if (res.code === 0) {
      message.success('已成功发起 SCA 依赖扫描')
      fetchProjects()
    }
  } catch (err: any) {
    message.error('发起扫描失败: ' + err.message)
  }
}

const handleDelete = async (id: number) => {
  try {
    const res: any = await deleteScaProject(id)
    if (res.code === 0) {
      message.success('工程已删除')
      fetchProjects()
    }
  } catch (err: any) {
    message.error('删除失败: ' + err.message)
  }
}

onMounted(() => {
  fetchProjects()
})
</script>
