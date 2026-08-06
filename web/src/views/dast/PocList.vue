<template>
  <div class="w-full mx-auto max-w-screen-2xl flex flex-col gap-6 bg-white p-2">
    <a-card title="PoC 模板列表" :bordered="false" class="rounded-lg border border-zinc-200 bg-white">
      <template #extra>
        <div class="flex items-center gap-3">
          <a-button
            type="primary"
            class="!bg-zinc-950 !border-zinc-950 !text-white hover:!bg-zinc-800"
            @click="showCreateModal"
          >
            <template #icon><PlusOutlined /></template>
            新增 PoC 模板
          </a-button>
        </div>
      </template>

      <a-table
        row-key="id"
        :columns="columns"
        :data-source="pocData"
        :loading="loading"
        size="middle"
        :scroll="{ x: 'max-content' }"
        :pagination="{ pageSize: 15 }"
        class="bg-white"
      >
        <template #bodyCell="{ record, column }">
          <template v-if="column.dataIndex === 'severity'">
            <a-tag :color="severityColor(record.severity)" class="font-semibold px-2 py-0.5 uppercase">
              {{ record.severity || 'info' }}
            </a-tag>
          </template>

          <template v-if="column.dataIndex === 'tags'">
            <a-space :size="4" wrap>
              <a-tag v-for="t in (record.tags || [])" :key="t" color="default" class="font-mono text-xs">
                {{ t }}
              </a-tag>
            </a-space>
          </template>

          <template v-if="column.dataIndex === 'updated_at'">
            {{ record.updated_at ? new Date(record.updated_at).toLocaleString() : '-' }}
          </template>

          <template v-if="column.key === 'actions'">
            <a-space :size="8">
              <a-button type="link" size="small" class="!p-0" @click="showEditModal(record)">
                编辑
              </a-button>
              <a-popconfirm
                title="确认删除该 PoC 模板？"
                ok-text="确认"
                cancel-text="取消"
                @confirm="handleDelete(record.id)"
              >
                <a-button type="link" danger size="small" class="!p-0">删除</a-button>
              </a-popconfirm>
            </a-space>
          </template>
        </template>
      </a-table>
    </a-card>

    <!-- 新增 / 编辑 Modal -->
    <a-modal
      v-model:open="modalVisible"
      :title="editingId ? '编辑 PoC 模板' : '新增 PoC 模板'"
      ok-text="保存"
      cancel-text="取消"
      width="720px"
      :confirm-loading="saveLoading"
      @ok="handleSave"
      @cancel="modalVisible = false"
    >
      <a-form :model="formState" layout="vertical" class="pt-4">
        <div class="grid grid-cols-2 gap-4">
          <a-form-item label="模板名称" required>
            <a-input v-model:value="formState.name" placeholder="例如: nginx-version-detect" :disabled="!!editingId" />
          </a-form-item>
          <a-form-item label="危害等级" required>
            <a-select v-model:value="formState.severity">
              <a-select-option value="critical">Critical</a-select-option>
              <a-select-option value="high">High</a-select-option>
              <a-select-option value="medium">Medium</a-select-option>
              <a-select-option value="low">Low</a-select-option>
              <a-select-option value="info">Info</a-select-option>
            </a-select>
          </a-form-item>
        </div>

        <a-form-item label="标签 (英文逗号分隔)">
          <a-input v-model:value="formState.tagsInput" placeholder="例如: web, nginx, rce" />
        </a-form-item>

        <a-form-item label="描述说明">
          <a-textarea v-model:value="formState.description" :rows="2" placeholder="模板检测说明" />
        </a-form-item>

        <a-form-item label="Nuclei YAML 内容" required>
          <a-textarea
            v-model:value="formState.content"
            :rows="12"
            class="font-mono text-xs"
            placeholder="粘贴 Nuclei 声明式 YAML 规则..."
          />
        </a-form-item>
      </a-form>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue';
import { message } from 'ant-design-vue';
import {
  PlusOutlined,
} from '@ant-design/icons-vue';
import {
  getDastPocList,
  getDastPoc,
  createDastPoc,
  updateDastPoc,
  deleteDastPoc,
} from '@/api/dast';

type PocItem = any;

const loading = ref(false);
const pocData = ref<PocItem[]>([]);

const columns = [
  { title: '模板名称', dataIndex: 'name', key: 'name' },
  { title: '危害等级', dataIndex: 'severity', key: 'severity', width: 120 },
  { title: '标签', dataIndex: 'tags', key: 'tags' },
  { title: '描述', dataIndex: 'description', key: 'description', ellipsis: true },
  { title: '最后修改', dataIndex: 'updated_at', key: 'updated_at', width: 180 },
  { title: '操作', key: 'actions', width: 120, fixed: 'right' as const },
];

const severityColor = (sev?: string) => {
  switch ((sev || '').toLowerCase()) {
    case 'critical':
      return 'red';
    case 'high':
      return 'orange';
    case 'medium':
      return 'gold';
    case 'low':
      return 'blue';
    default:
      return 'default';
  }
};

const loadPocs = async () => {
  loading.value = true;
  try {
    const res: any = await getDastPocList();
    if (res.data) {
      if (Array.isArray(res.data.data)) {
        pocData.value = res.data.data;
      } else if (Array.isArray(res.data)) {
        pocData.value = res.data;
      }
    }
  } catch {
    message.error('加载 PoC 模板列表失败');
  } finally {
    loading.value = false;
  }
};

// Form state
const modalVisible = ref(false);
const saveLoading = ref(false);
const editingId = ref<string | null>(null);

const formState = reactive({
  name: '',
  description: '',
  severity: 'high',
  tagsInput: '',
  content: '',
});

const showCreateModal = () => {
  editingId.value = null;
  formState.name = '';
  formState.description = '';
  formState.severity = 'high';
  formState.tagsInput = 'web';
  formState.content = `id: custom-poc-template

info:
  name: Custom Detection Rule
  author: devsecops
  severity: high
  tags: web

http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: status
        status:
          - 200`;
  modalVisible.value = true;
};

const showEditModal = async (record: PocItem) => {
  editingId.value = record.id || record.name;
  formState.name = record.name;
  formState.description = record.description || '';
  formState.severity = record.severity || 'high';
  formState.tagsInput = (record.tags || []).join(', ');
  formState.content = '加载中...';
  modalVisible.value = true;

  try {
    const res: any = await getDastPoc(record.name);
    const pocMeta = res.data?.data || res.data;
    if (typeof pocMeta === 'string') {
      formState.content = pocMeta;
    } else if (pocMeta?.content) {
      formState.content = pocMeta.content;
    } else {
      formState.content = JSON.stringify(res.data, null, 2);
    }
  } catch {
    formState.content = '# 提取内容失败';
  }
};

const handleSave = async () => {
  if (!formState.name || !formState.content) {
    message.warning('请填写模板名称与 YAML 内容');
    return;
  }

  saveLoading.value = true;
  try {
    const tags = formState.tagsInput
      .split(',')
      .map((t) => t.trim())
      .filter(Boolean);

    if (editingId.value) {
      await updateDastPoc(formState.name, {
        description: formState.description,
        severity: formState.severity,
        tags,
        content: formState.content,
      });
      message.success('模板更新成功');
    } else {
      await createDastPoc({
        name: formState.name,
        description: formState.description,
        severity: formState.severity,
        tags,
        content: formState.content,
      });
      message.success('模板创建成功');
    }
    modalVisible.value = false;
    loadPocs();
  } catch (err: any) {
    message.error('保存失败: ' + (err.message || '系统错误'));
  } finally {
    saveLoading.value = false;
  }
};

const handleDelete = async (id: string) => {
  try {
    await deleteDastPoc(id);
    message.success('模板已删除');
    loadPocs();
  } catch {
    message.error('删除失败');
  }
};

onMounted(() => {
  loadPocs();
});
</script>
