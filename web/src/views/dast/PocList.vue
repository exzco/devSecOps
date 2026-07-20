<template>
  <div class="w-full mx-auto max-w-screen-2xl flex flex-col gap-6 bg-white p-2">
    <a-card title="DAST PoC 模板管理" :bordered="false" class="rounded-lg border border-zinc-200 bg-white">
      <template #extra>
        <a-button
          type="primary"
          class="!bg-zinc-950 !border-zinc-950 !text-white hover:!bg-zinc-800"
          @click="showCreateModal"
        >
          新增 PoC 模板
        </a-button>
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

    <!-- 新增 Modal -->
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

        <a-form-item label="标签 Tags（空格或逗号分隔）">
          <a-input v-model:value="formState.tagsRaw" placeholder="例如: nginx http web" />
        </a-form-item>

        <a-form-item label="描述">
          <a-input v-model:value="formState.description" placeholder="对该模板漏洞原理的简要描述" />
        </a-form-item>

        <a-form-item label="PoC 内容 (Nuclei YAML)" required>
          <a-spin :spinning="contentLoading">
            <a-textarea
              v-model:value="formState.content"
              :rows="14"
              class="font-mono text-xs bg-zinc-50"
              placeholder="id: my-poc&#10;info:&#10;  name: My PoC&#10;  severity: info&#10;http:&#10;  - method: GET&#10;    path:&#10;      - '{{BaseURL}}/'&#10;    matchers:&#10;      - type: word&#10;        words:&#10;          - 'example'"
            />
          </a-spin>
        </a-form-item>
      </a-form>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, reactive } from 'vue';
import { message } from 'ant-design-vue';
import { getDastPocList, getDastPoc, createDastPoc, updateDastPoc, deleteDastPoc } from '../../api';

interface PocRecord {
  id: string;
  name: string;
  description: string;
  severity: string;
  tags: string[];
  file_path: string;
  created_at: string;
  updated_at: string;
}

const loading = ref(false);
const saveLoading = ref(false);
const pocData = ref<PocRecord[]>([]);
const modalVisible = ref(false);
const editingId = ref('');
const contentLoading = ref(false);

const formState = reactive({
  name: '',
  description: '',
  severity: 'info',
  tagsRaw: '',
  content: '',
});

const columns = [
  { title: '模板 ID', dataIndex: 'id', key: 'id', width: 220, ellipsis: true },
  { title: '名称', dataIndex: 'name', key: 'name', width: 180 },
  { title: '等级', dataIndex: 'severity', key: 'severity', width: 100 },
  { title: 'Tags', dataIndex: 'tags', key: 'tags', width: 240 },
  { title: '描述', dataIndex: 'description', key: 'description', ellipsis: true },
  { title: '更新时间', dataIndex: 'updated_at', key: 'updated_at', width: 180 },
  { title: '操作', key: 'actions', width: 120, fixed: 'right' as const },
];

const severityColor = (s: string) => {
  const map: Record<string, string> = {
    critical: 'red', high: 'orange', medium: 'gold', low: 'blue', info: 'green',
  };
  return map[(s || '').toLowerCase()] || 'default';
};

const parseTags = (raw: string) =>
  raw.split(/[\s,]+/).map((t: string) => t.trim()).filter(Boolean);

const loadPocs = async () => {
  loading.value = true;
  try {
    const res = await getDastPocList();
    pocData.value = res.data.data || [];
  } catch {
    message.error('获取 PoC 模板列表失败');
  } finally {
    loading.value = false;
  }
};

const showCreateModal = () => {
  editingId.value = '';
  Object.assign(formState, { name: '', description: '', severity: 'info', tagsRaw: '', content: '' });
  modalVisible.value = true;
};

const showEditModal = async (record: PocRecord) => {
  editingId.value = record.id;
  Object.assign(formState, {
    name: record.name,
    description: record.description,
    severity: record.severity,
    tagsRaw: (record.tags || []).join(' '),
    content: '',
  });
  modalVisible.value = true;
  contentLoading.value = true;
  try {
    const res = await getDastPoc(record.id);
    if (editingId.value === record.id) {
      formState.content = res.data.data.content || '';
    }
  } catch {
    message.error('获取 PoC 详细内容失败');
  } finally {
    contentLoading.value = false;
  }
};

const handleSave = async () => {
  if (!formState.name.trim()) { message.error('模板名称不能为空'); return; }
  if (!formState.content.trim()) { message.error('模板内容不能为空'); return; }
  saveLoading.value = true;
  try {
    if (editingId.value) {
      await updateDastPoc(editingId.value, {
        name: formState.name.trim(),
        description: formState.description.trim(),
        severity: formState.severity,
        tags: parseTags(formState.tagsRaw),
        content: formState.content,
      });
      message.success('模板已更新');
    } else {
      await createDastPoc({
        name: formState.name.trim(),
        description: formState.description.trim(),
        severity: formState.severity,
        tags: parseTags(formState.tagsRaw),
        content: formState.content,
      });
      message.success('PoC 模板创建成功');
    }
    modalVisible.value = false;
    loadPocs();
  } catch (err: any) {
    message.error(err.response?.data?.error || '保存失败');
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

onMounted(loadPocs);
</script>
