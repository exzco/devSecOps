<template>
  <div class="space-y-6">
    <!-- Header with PoC/EXP Statistics -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-bold tracking-tight text-zinc-950">CVE 数据列表</h1>
        <p class="mt-1 text-sm text-zinc-500">默认从本地数据库及 Redis 极速读取，点击“网络全量同步入库”触发在线更新</p>
      </div>

      <!-- Real-time Statistics Badges -->
      <div class="flex items-center gap-3">
        <div class="flex items-center gap-2 rounded-lg border border-zinc-200 bg-white px-3 py-1.5 shadow-sm">
          <span class="text-xs font-medium text-zinc-500">CVE 总数</span>
          <span class="font-mono text-base font-bold text-zinc-950">{{ totalCount }}</span>
        </div>

        <div class="flex items-center gap-2 rounded-lg border border-emerald-200 bg-emerald-50/70 px-3 py-1.5 shadow-sm">
          <span class="text-xs font-medium text-emerald-700">有 PoC/EXP 数</span>
          <span class="font-mono text-base font-bold text-emerald-800">{{ pocCount }}</span>
        </div>

        <div class="flex items-center gap-2 rounded-lg border border-blue-200 bg-blue-50/70 px-3 py-1.5 shadow-sm">
          <span class="text-xs font-medium text-blue-700">PoC 覆盖率</span>
          <span class="font-mono text-base font-bold text-blue-800">{{ pocRatio }}</span>
        </div>
      </div>
    </div>

    <!-- Search & Filter Card -->
    <div class="flex items-center gap-3 rounded-md border border-zinc-200 bg-white p-4 shadow-sm">
      <a-input
        v-model:value="keyword"
        placeholder="搜索 CVE 编号、组件名称或漏洞关键词 (例如: nginx, php, spring)"
        size="large"
        class="max-w-md flex-1 !rounded-md"
        @pressEnter="loadLocalCveList"
      />
      <a-select v-model:value="year" size="large" style="width: 130px" class="custom-aligned-select" @change="loadLocalCveList">
        <a-select-option :value="2026">2026 年</a-select-option>
        <a-select-option :value="2025">2025 年</a-select-option>
        <a-select-option :value="2024">2024 年</a-select-option>
      </a-select>
      <a-button
        type="primary"
        size="large"
        class="!bg-zinc-950 !border-zinc-950 px-5 font-medium !rounded-md flex items-center justify-center gap-1.5"
        :loading="loading"
        @click="loadLocalCveList"
      >
        <template #icon><SearchOutlined /></template>
        查询 CVE (本地库)
      </a-button>
      <a-button
        type="default"
        size="large"
        class="border-zinc-300 font-medium hover:border-zinc-950 !rounded-md flex items-center justify-center gap-1.5"
        :loading="syncLoading"
        @click="syncOnlineCveList"
      >
        <template #icon><CloudSyncOutlined /></template>
        网络全量同步入库
      </a-button>
    </div>

    <!-- CVE Intelligence Table -->
    <div class="rounded-md border border-zinc-200 bg-white">
      <a-table
        :columns="columns"
        :data-source="cveData"
        :loading="loading || syncLoading"
        :pagination="paginationConfig"
        :row-key="(record: any) => record.cve_id"
        :scroll="{ x: 'max-content' }"
      >
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'cve_id'">
            <div class="font-mono font-bold text-zinc-950">{{ record.cve_id }}</div>
            <div class="text-xs text-zinc-500 font-medium">{{ record.component }}</div>
          </template>

          <template v-if="column.key === 'severity'">
            <span
              :class="[
                'inline-flex items-center rounded-md px-2 py-0.5 text-xs font-bold border',
                record.severity === 'CRITICAL' ? 'bg-red-50 text-red-700 border-red-200' :
                record.severity === 'HIGH' ? 'bg-amber-50 text-amber-700 border-amber-200' :
                record.severity === 'MEDIUM' ? 'bg-yellow-50 text-yellow-700 border-yellow-200' :
                'bg-zinc-50 text-zinc-600 border-zinc-200'
              ]"
            >
              {{ record.severity }} ({{ record.cvss_score }})
            </span>
          </template>

          <template v-if="column.key === 'has_exp'">
            <div v-if="record.has_exp" class="flex flex-col gap-1">
              <span class="inline-flex items-center gap-1 rounded-md bg-emerald-50 px-2 py-0.5 text-xs font-medium text-emerald-700 border border-emerald-200 w-fit">
                <CheckCircleOutlined class="text-xs text-emerald-600" />
                GitHub EXP 确认
              </span>
              <a
                v-if="record.exp_url"
                :href="record.exp_url"
                target="_blank"
                class="text-xs text-blue-600 hover:text-blue-800 underline truncate max-w-[160px] font-mono"
                title="点击直接前往 GitHub EXP 仓库"
              >
                repo
              </a>
            </div>
            <span v-else class="text-xs text-zinc-400">暂无公开 EXP</span>
          </template>

          <template v-if="column.key === 'tags'">
            <div class="flex flex-wrap gap-1">
              <span
                v-for="tag in (record.tags || [])"
                :key="tag"
                class="rounded bg-zinc-100 px-1.5 py-0.5 font-mono text-[11px] font-medium text-zinc-600 border border-zinc-200"
              >
                {{ tag }}
              </span>
            </div>
          </template>

          <template v-if="column.key === 'action'">
            <div class="flex items-center gap-2">
              <a-button type="link" size="small" class="!px-0 font-medium" @click="showDetail(record)">
                详情 / EXP
              </a-button>
              <a-button
                type="primary"
                size="small"
                class="!bg-zinc-950 !border-zinc-950 font-medium"
                :loading="genLoadingMap[record.cve_id]"
                @click="handleGeneratePoc(record)"
              >
                生成 Nuclei PoC
              </a-button>
            </div>
          </template>
        </template>
      </a-table>
    </div>

    <!-- CVE Detail Modal -->
    <a-modal
      v-model:open="detailVisible"
      :title="`CVE 详细情报与 EXP 验证 - ${selectedCve?.cve_id || ''}`"
      width="720px"
      :footer="null"
    >
      <div v-if="selectedCve" class="space-y-4 pt-2">
        <div class="grid grid-cols-2 gap-4 text-xs bg-zinc-50 border border-zinc-200 rounded-md p-3">
          <div><span class="text-zinc-500">CVE 编号:</span> <span class="font-mono font-bold">{{ selectedCve.cve_id }}</span></div>
          <div><span class="text-zinc-500">发布/更新时间:</span> {{ selectedCve.published_at }}</div>
          <div><span class="text-zinc-500">CVSS 评分:</span> <span class="font-bold text-red-600">{{ selectedCve.cvss_score }}</span> ({{ selectedCve.severity }})</div>
          <div><span class="text-zinc-500">受影响组件:</span> {{ selectedCve.component }}</div>
          <div class="col-span-2" v-if="selectedCve.exp_url">
            <span class="text-zinc-500">GitHub EXP 验证:</span> 
            <a :href="selectedCve.exp_url" target="_blank" class="text-blue-600 underline ml-1">{{ selectedCve.exp_url }}</a>
          </div>
        </div>

        <div>
          <h4 class="text-xs font-bold text-zinc-500 uppercase tracking-wider mb-1">漏洞摘要 Summary</h4>
          <p class="text-sm text-zinc-800 bg-white border border-zinc-200 rounded-md p-3">{{ selectedCve.summary }}</p>
        </div>

        <div v-if="selectedCve.details">
          <h4 class="text-xs font-bold text-zinc-500 uppercase tracking-wider mb-1">漏洞利用 (EXP) / 技术细节</h4>
          <pre class="text-xs font-mono bg-zinc-900 rounded-md p-4 overflow-x-auto whitespace-pre-wrap border border-zinc-800" style="color: #e4e4e7 !important; background-color: #18181b !important; line-height: 1.6;">{{ selectedCve.details }}</pre>
        </div>
      </div>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { message } from 'ant-design-vue'
import { CheckCircleOutlined, SearchOutlined, CloudSyncOutlined } from '@ant-design/icons-vue'
import { getDastCveList, fetchDastCves, generateAiPoc } from '../../api/dast'

const router = useRouter()
const loading = ref(false)
const syncLoading = ref(false)
const keyword = ref('')
const year = ref(2025)
const cveData = ref<any[]>([])
const genLoadingMap = reactive<Record<string, boolean>>({})

// Computed statistics - 物理核验真实 EXP 链接与 PoC 生成状态
const totalCount = computed(() => cveData.value.length)
const pocCount = computed(() => cveData.value.filter((item) => (item.has_exp === true && !!item.exp_url) || item.has_poc === true).length)
const pocRatio = computed(() => {
  if (totalCount.value === 0) return '0.0%'
  return ((pocCount.value / totalCount.value) * 100).toFixed(1) + '%'
})

const paginationConfig = reactive({
  pageSize: 20,
  showSizeChanger: true,
  pageSizeOptions: ['10', '20', '50', '100', '200'],
  showTotal: (total: number) => `共 ${total} 条 CVE 情报`,
})

const detailVisible = ref(false)
const selectedCve = ref<any>(null)

const formatExpRepoName = (url?: string) => {
  if (!url) return ''
  try {
    const clean = url.replace(/\/$/, '')
    const parts = clean.split('/')
    if (parts.length >= 2) {
      return parts.slice(-2).join('/')
    }
  } catch {
    return 'EXP 仓库'
  }
  return 'EXP 仓库'
}

const columns = [
  { title: 'CVE 编号 / 组件', key: 'cve_id', width: 220 },
  { title: '危害级别', key: 'severity', width: 140 },
  { title: 'EXP / PoC 状态', key: 'has_exp', width: 140 },
  { title: '漏洞描述', dataIndex: 'summary', key: 'summary', ellipsis: true },
  { title: '标签', key: 'tags', width: 180 },
  { title: '操作', key: 'action', width: 240, fixed: 'right' as const },
]

// 读取本地数据库 / Redis (零在线网络请求，毫秒级响应)
const loadLocalCveList = async () => {
  loading.value = true
  try {
    const res: any = await getDastCveList(keyword.value, year.value)
    if (res.data && res.data.code === 0) {
      cveData.value = res.data.data || []
    }
  } catch (err: any) {
    message.error('加载本地 CVE 列表失败: ' + (err.message || '系统错误'))
  } finally {
    loading.value = false
  }
}

// 在线全量同步 (显示触发 GitHub 在线聚合与入库)
const syncOnlineCveList = async () => {
  syncLoading.value = true
  try {
    const res: any = await fetchDastCves(keyword.value, year.value)
    if (res.data && res.data.code === 0) {
      cveData.value = res.data.data || []
      message.success(`网络全量同步成功！已聚合落盘 ${cveData.value.length} 条 CVE 情报`)
    }
  } catch (err: any) {
    message.error('网络全量同步失败: ' + (err.message || '网络连接异常'))
  } finally {
    syncLoading.value = false
  }
}

const showDetail = (record: any) => {
  selectedCve.value = record
  detailVisible.value = true
}

const handleGeneratePoc = async (record: any) => {
  genLoadingMap[record.cve_id] = true
  try {
    let targetTag = 'web'
    if (record.tags && record.tags.length > 0) {
      targetTag = record.tags[0]
    }

    const res: any = await generateAiPoc({
      cve_id: record.cve_id,
      target_tag: targetTag,
      description: record.summary,
    })
    if (res.data && res.data.code === 0) {
      message.success(`已拉取官方真实 Nuclei PoC 探针并写入 MinIO！`)
      router.push({ name: 'DastPocs' })
    }
  } catch (err: any) {
    message.error('生成真实 Nuclei PoC 失败: ' + err.message)
  } finally {
    genLoadingMap[record.cve_id] = false
  }
}

onMounted(() => {
  loadLocalCveList()
})
</script>

<style scoped>
:deep(.custom-aligned-select .ant-select-selector) {
  height: 40px !important;
  display: flex !important;
  align-items: center !important;
  border-radius: 0.375rem !important;
}
</style>
