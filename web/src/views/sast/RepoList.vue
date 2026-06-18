<template>
  <div class="h-full w-full mx-auto max-w-screen-2xl flex flex-col gap-5 overflow-hidden">
    <a-card title="代码仓库管理" :bordered="false" class="rounded-lg flex flex-col w-full h-full flex-shrink-0">
      <template #extra>
        <a-space>
          <a-popconfirm
            title="将删除选中的仓库及其扫描任务和漏洞记录，确认继续吗？"
            ok-text="确认"
            cancel-text="取消"
            @confirm="handleBatchDelete"
          >
            <a-button type="primary" danger :disabled="selectedRowKeys.length === 0">
              <template #icon><DeleteOutlined /></template>
              批量删除
            </a-button>
          </a-popconfirm>
          <a-button type="primary" @click="handleOpenAdd">
            <template #icon><PlusOutlined /></template>
            添加仓库
          </a-button>
        </a-space>
      </template>

      <div class="flex-1 overflow-hidden h-full mt-4">
        <a-table
          row-key="id"
          :columns="columns"
          :data-source="data"
          :row-selection="{ selectedRowKeys: selectedRowKeys, onChange: onSelectChange }"
          :scroll="{ x: '100%', y: '100%' }"
          size="middle"
          :loading="loading"
          :pagination="pagination"
          @change="handleTableChange"
          class="h-full w-full"
        >
          <template #bodyCell="{ text, record, column }">
            <template v-if="column.dataIndex === 'language'">
              <a-tag :color="record.language === 'go' ? 'blue' : record.language === 'java' ? 'orange' : 'green'">
                {{ record.language }}
              </a-tag>
            </template>

            <template v-if="column.key === 'actions'">
              <a-space :size="12">
                <a-button type="link" size="small" @click="handleScan(record)">
                  <template #icon><PlayCircleOutlined /></template>
                  开始扫描
                </a-button>
                <a-button type="link" class="!text-amber-400 hover:!text-amber-300" size="small" @click="handleOpenEdit(record)">
                  <template #icon><EditOutlined /></template>
                  修改
                </a-button>
                <a-popconfirm title="确定要删除这个仓库吗？" ok-text="确认" cancel-text="取消" @confirm="handleDelete(record.id)">
                  <a-button type="link" danger size="small">
                    <template #icon><DeleteOutlined /></template>
                    删除
                  </a-button>
                </a-popconfirm>
              </a-space>
            </template>
          </template>
        </a-table>
      </div>
    </a-card>

    <!-- Add/Edit Modal -->
    <a-modal
      v-model:open="visible"
      :title="editingId ? '更新仓库' : '新增仓库'"
      ok-text="确定"
      cancel-text="取消"
      @ok="handleConfirm"
      @cancel="handleCancel"
    >
      <div class="pt-4">
        <a-form :model="form" layout="vertical">
          <a-form-item label="仓库名称" required>
            <a-input v-model:value="form.name" :maxlength="128" placeholder="例如：my-go-project" />
          </a-form-item>
          <a-form-item label="Git 地址" required>
            <a-input v-model:value="form.url" :maxlength="300" placeholder="https://github.com/user/repo.git" />
          </a-form-item>
          <a-form-item label="主要语言" required>
            <a-select v-model:value="form.language" placeholder="请选择语言">
              <a-select-option value="go">Go</a-select-option>
              <a-select-option value="java">Java</a-select-option>
              <a-select-option value="javascript">JavaScript</a-select-option>
              <a-select-option value="python">Python</a-select-option>
            </a-select>
          </a-form-item>
          <a-form-item label="扫描分支">
            <a-input v-model:value="form.branch" :maxlength="128" placeholder="默认为 main" />
          </a-form-item>
          <a-form-item label="Stars">
            <a-input-number v-model:value="form.stars" :min="0" class="w-full" />
          </a-form-item>
          <a-form-item label="认证类型">
            <a-select v-model:value="form.auth_type" placeholder="请选择认证类型">
              <a-select-option value="none">无</a-select-option>
              <a-select-option value="token">Token</a-select-option>
              <a-select-option value="ssh_key">SSH Key</a-select-option>
            </a-select>
          </a-form-item>
          <a-form-item
            v-if="form.auth_type !== 'none'"
            :label="form.auth_type === 'token' ? 'Access Token' : 'SSH Key'"
            required
          >
            <a-input-password
              v-model:value="form.auth_secret"
              :placeholder="form.auth_type === 'token' ? '请输入 Personal Access Token' : '请输入 SSH 私钥内容'"
            />
          </a-form-item>
        </a-form>
      </div>
    </a-modal>

    <!-- Trigger Scan Modal -->
    <a-modal 
      v-model:open="scanVisible" 
      title="触发扫描" 
      ok-text="开始扫描"
      cancel-text="取消"
      @ok="handleConfirmScan"
    >
      <div class="pt-4">
        <a-form :model="scanForm" layout="vertical">
          <a-form-item label="规则策略">
            <a-select v-model:value="scanForm.rule_profile" placeholder="baseline / cve_hot / zero_day_only">
              <a-select-option value="baseline">baseline</a-select-option>
              <a-select-option value="cve_hot">cve_hot</a-select-option>
              <a-select-option value="zero_day_only">zero_day_only</a-select-option>
            </a-select>
          </a-form-item>
          <a-form-item label="额外规则">
            <a-input v-model:value="scanForm.query_suite" :maxlength="512" placeholder="支持逗号分隔多个 .ql/.qls" />
          </a-form-item>
        </a-form>
      </div>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue';
import { message } from 'ant-design-vue';
import { 
  PlusOutlined, 
  DeleteOutlined, 
  PlayCircleOutlined, 
  EditOutlined 
} from '@ant-design/icons-vue';
import { 
  addRepo, 
  batchDeleteRepos, 
  deleteRepo, 
  getRepoList, 
  triggerScan, 
  updateRepo 
} from '../../api';

type RepoLanguage = 'go' | 'java' | 'javascript' | 'python';
type AuthType = 'none' | 'token' | 'ssh_key';
type RuleProfile = 'baseline' | 'cve_hot' | 'zero_day_only';

interface RepoRecord {
  id: number;
  name: string;
  url: string;
  language: RepoLanguage;
  branch: string;
  stars?: number;
  auto_scan_enabled?: boolean;
  auth_type: AuthType;
}

interface RepoForm {
  name: string;
  url: string;
  language: RepoLanguage;
  branch: string;
  stars: number;
  auth_type: AuthType;
  auth_secret: string;
}

interface ScanForm {
  rule_profile: RuleProfile;
  query_suite: string;
}

const BRANCH_REGEX = /^[A-Za-z0-9._/-]{1,128}$/;
const QUERY_FILE_REGEX = /^[A-Za-z0-9._/-]+\.qls?$/;

const normalizeString = (value: string) => (value || '').trim();

const isValidGitUrl = (url: string) => {
  const normalized = normalizeString(url);
  const httpGitRegex = /^https?:\/\/[\w.-]+\/[\w.-]+\/[\w.-]+(?:\.git)?$/;
  const sshGitRegex = /^git@[\w.-]+:[\w.-]+\/[\w.-]+(?:\.git)?$/;
  return httpGitRegex.test(normalized) || sshGitRegex.test(normalized);
};

const isValidBranch = (branch: string) => {
  const normalized = normalizeString(branch);
  return BRANCH_REGEX.test(normalized) && !normalized.includes('..') && !normalized.startsWith('/');
};

const normalizeQuerySuite = (querySuite: string) => {
  const files = querySuite
    .split(',')
    .map((item) => normalizeString(item))
    .filter(Boolean);

  if (files.length === 0) {
    return '';
  }

  const valid = files.every((file) => QUERY_FILE_REGEX.test(file) && !file.includes('..'));
  if (!valid) {
    return null;
  }

  return files.join(',');
};

const loading = ref(false);
const visible = ref(false);
const editingId = ref<number | null>(null);
const data = ref<RepoRecord[]>([]);
const selectedRowKeys = ref<number[]>([]);

const pagination = reactive({
  current: 1,
  pageSize: 10,
  total: 0,
  showSizeChanger: true,
  showQuickJumper: true,
});

const initialForm: RepoForm = {
  name: '',
  url: '',
  language: 'go',
  branch: 'main',
  stars: 0,
  auth_type: 'none',
  auth_secret: '',
};

const form = reactive({ ...initialForm });

const columns = [
  { title: '名称', dataIndex: 'name', key: 'name', width: 150, ellipsis: true },
  { title: 'Git 地址', dataIndex: 'url', key: 'url', width: 280, ellipsis: true },
  { title: '语言', dataIndex: 'language', key: 'language', width: 90 },
  { title: 'Stars', dataIndex: 'stars', key: 'stars', width: 80 },
  { title: '分支', dataIndex: 'branch', key: 'branch', width: 100 },
  { title: '认证方式', dataIndex: 'auth_type', key: 'auth_type', width: 100 },
  { title: '操作', key: 'actions', width: 220, fixed: 'right', align: 'center' as const },
];

const onSelectChange = (keys: any[]) => {
  selectedRowKeys.value = keys.map((k) => Number(k));
};

const scanVisible = ref(false);
const scanTarget = ref<RepoRecord | null>(null);
const scanForm = reactive<ScanForm>({
  rule_profile: 'baseline',
  query_suite: '',
});

const loadData = async () => {
  loading.value = true;
  try {
    const res = await getRepoList(pagination.current, pagination.pageSize);
    data.value = res.data.data.data || [];
    pagination.total = res.data.data.total || 0;
  } catch (err) {
    message.error('获取列表失败');
  } finally {
    loading.value = false;
  }
};

const handleTableChange = (pag: any) => {
  pagination.current = pag.current;
  pagination.pageSize = pag.pageSize;
  loadData();
};

const handleOpenAdd = () => {
  editingId.value = null;
  Object.assign(form, initialForm);
  visible.value = true;
};

const handleOpenEdit = (record: RepoRecord) => {
  editingId.value = record.id;
  Object.assign(form, {
    name: record.name,
    url: record.url,
    language: record.language,
    branch: record.branch,
    stars: record.stars ?? 0,
    auth_type: record.auth_type,
    auth_secret: '',
  });
  visible.value = true;
};

const validateRepoForm = () => {
  form.name = normalizeString(form.name);
  form.url = normalizeString(form.url);
  form.branch = normalizeString(form.branch) || 'main';
  form.auth_secret = (form.auth_secret || '').trim();

  if (!form.name) {
    message.error('仓库名称不能为空');
    return false;
  }
  if (!isValidGitUrl(form.url)) {
    message.error('Git 地址格式非法，仅支持标准 HTTP(S)/SSH 仓库地址');
    return false;
  }
  if (!isValidBranch(form.branch)) {
    message.error('分支名非法：仅允许字母、数字、._/-，且禁止路径穿越片段');
    return false;
  }
  if (form.auth_type !== 'none' && !form.auth_secret && !editingId.value) {
    message.error('已选择认证类型，必须输入凭证');
    return false;
  }
  return true;
};

const handleConfirm = async () => {
  if (!validateRepoForm()) return;

  const payload = {
    name: form.name,
    url: form.url,
    language: form.language,
    branch: form.branch,
    stars: Number(form.stars) || 0,
    auth_type: form.auth_type,
    ...(form.auth_type !== 'none' && form.auth_secret ? { auth_secret: form.auth_secret } : {}),
  };

  try {
    if (editingId.value) {
      await updateRepo(editingId.value, payload);
      message.success('更新成功');
    } else {
      await addRepo(payload);
      message.success('添加成功');
    }
    visible.value = false;
    loadData();
  } catch (err) {
    message.error(editingId.value ? '更新失败' : '添加失败');
  }
};

const handleCancel = () => {
  visible.value = false;
};

const handleDelete = async (id: number) => {
  try {
    await deleteRepo(id);
    selectedRowKeys.value = selectedRowKeys.value.filter((v) => v !== id);
    message.success('删除成功');
    loadData();
  } catch (err) {
    message.error('删除失败');
  }
};

const handleBatchDelete = async () => {
  if (selectedRowKeys.value.length === 0) return;
  try {
    await batchDeleteRepos(selectedRowKeys.value);
    message.success(`批量删除成功：${selectedRowKeys.value.length} 个仓库`);
    selectedRowKeys.value = [];
    loadData();
  } catch (err) {
    message.error('批量删除失败');
  }
};

const handleScan = (record: RepoRecord) => {
  scanTarget.value = record;
  scanForm.query_suite = '';
  scanForm.rule_profile = 'baseline';
  scanVisible.value = true;
};

const handleConfirmScan = async () => {
  if (!scanTarget.value) return;

  const normalizedQuerySuite = normalizeQuerySuite(scanForm.query_suite);
  if (normalizedQuerySuite === null) {
    message.error('额外规则格式非法，仅允许逗号分隔 .ql/.qls 且禁止路径穿越');
    return;
  }

  try {
    await triggerScan({
      repo_id: scanTarget.value.id,
      language: scanTarget.value.language,
      branch: scanTarget.value.branch,
      rule_profile: scanForm.rule_profile || undefined,
      query_suite: normalizedQuerySuite || undefined,
    });
    scanVisible.value = false;
    message.success(`已触发扫描：${scanTarget.value.name}`);
  } catch (err) {
    message.error(`触发扫描失败：${scanTarget.value.name}`);
  }
};

onMounted(() => {
  loadData();
});
</script>
