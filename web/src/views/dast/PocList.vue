<template>
  <div class="w-full mx-auto max-w-screen-2xl flex flex-col gap-6 bg-white p-2">
    <!-- Main Card -->
    <a-card title="DAST PoC 模版管理" :bordered="false" class="rounded-lg shadow-sm border border-zinc-200 bg-white">
      <template #extra>
        <a-button type="primary" class="!bg-zinc-950 !border-zinc-950 !text-white hover:!bg-zinc-800" @click="showCreateModal">
          新增 PoC 模版
        </a-button>
      </template>

      <a-table
        row-key="ID"
        :columns="columns"
        :data-source="pocData"
        :loading="loading"
        size="middle"
        :pagination="{ pageSize: 10 }"
        class="bg-white"
      >
        <template #bodyCell="{ text, record, column }">
          <template v-if="column.dataIndex === 'severity'">
            <a-tag :color="severityColor(record.severity)" class="font-semibold px-2 py-0.5 uppercase">
              {{ record.severity }}
            </a-tag>
          </template>

          <template v-if="column.dataIndex === 'UpdatedAt'">
            {{ new Date(record.UpdatedAt).toLocaleString() }}
          </template>

          <template v-if="column.key === 'actions'">
            <a-space :size="8">
              <a-button type="link" size="small" @click="showEditModal(record)">
                编辑
              </a-button>
              <a-popconfirm
                title="确认删除该 PoC 模板吗？"
                ok-text="确认"
                cancel-text="取消"
                @confirm="handleDelete(record.ID)"
              >
                <a-button type="link" danger size="small">
                  删除
                </a-button>
              </a-popconfirm>
            </a-space>
          </template>
        </template>
      </a-table>
    </a-card>

    <!-- Create/Edit Modal -->
    <a-modal
      v-model:visible="modalVisible"
      :title="editingId ? '编辑 PoC 模版' : '新增 PoC 模版'"
      @ok="handleSave"
      ok-text="保存"
      cancel-text="取消"
      width="720px"
      :confirm-loading="saveLoading"
    >
      <a-form :model="formState" layout="vertical" class="pt-4 space-y-4">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <a-form-item label="模版名称 (Name)" required>
            <a-input v-model:value="formState.name" placeholder="例如：cve-2026-xxxx-rce" />
          </a-form-item>
          <a-form-item label="危害等级 (Severity)" required>
            <a-select v-model:value="formState.severity" placeholder="请选择危害等级">
              <a-select-option value="critical">Critical</a-select-option>
              <a-select-option value="high">High</a-select-option>
              <a-select-option value="medium">Medium</a-select-option>
              <a-select-option value="low">Low</a-select-option>
              <a-select-option value="info">Info</a-select-option>
            </a-select>
          </a-form-item>
        </div>

        <a-form-item label="描述 (Description)">
          <a-input v-model:value="formState.description" placeholder="请输入对该 PoC 漏洞原理的简要描述" />
        </a-form-item>

        <a-form-item label="PoC 规则详情 (YAML 格式)" required>
          <a-textarea
            v-model:value="formState.content"
            :rows="12"
            class="font-mono text-xs p-3 bg-zinc-50 border-zinc-200 focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400"
            placeholder="id: cve-xxxx-xxxx&#10;info:&#10;  name: Target Vulnerability&#10;  severity: high&#10;requests:&#10;  - method: GET&#10;    path:&#10;      - &quot;{{BaseURL}}/check-leak&quot;&#10;    matchers:&#10;      - type: word&#10;        words:&#10;          - &quot;root:x:&quot;"
          />
        </a-form-item>
      </a-form>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, reactive } from 'vue';
import { message } from 'ant-design-vue';
import {
  getDastPocList,
  createDastPoc,
  updateDastPoc,
  deleteDastPoc
} from '../../api';

interface PocRecord {
  ID: number;
  name: string;
  description: string;
  severity: string;
  content: string;
  UpdatedAt: string;
}

const loading = ref(false);
const pocData = ref<PocRecord[]>([]);
const modalVisible = ref(false);
const editingId = ref<number | null>(null);
const saveLoading = ref(false);

const formState = reactive({
  name: '',
  severity: 'high',
  description: '',
  content: ''
});

const columns = [
  { title: '模版名称', dataIndex: 'name', key: 'name', width: 220 },
  { title: '危险等级', dataIndex: 'severity', key: 'severity', width: 120 },
  { title: '简要描述', dataIndex: 'description', key: 'description', ellipsis: true },
  { title: '修改时间', dataIndex: 'UpdatedAt', key: 'UpdatedAt', width: 180 },
  { title: '操作', key: 'actions', width: 140 }
];

const severityColor = (severity: string) => {
  const s = (severity || '').toLowerCase();
  const map: Record<string, string> = {
    critical: 'red',
    high: 'orange',
    medium: 'gold',
    low: 'blue',
    info: 'green'
  };
  return map[s] || 'default';
};

const loadPocs = async () => {
  loading.value = true;
  try {
    const res = await getDastPocList();
    pocData.value = res.data.data || [];
  } catch (err) {
    message.error('获取 PoC 模板列表失败');
  } finally {
    loading.value = false;
  }
};

const showCreateModal = () => {
  editingId.value = null;
  formState.name = '';
  formState.severity = 'high';
  formState.description = '';
  formState.content = '';
  modalVisible.value = true;
};

const showEditModal = (record: PocRecord) => {
  editingId.value = record.ID;
  formState.name = record.name;
  formState.severity = record.severity;
  formState.description = record.description;
  formState.content = record.content;
  modalVisible.value = true;
};

const handleSave = async () => {
  if (!formState.name.trim()) {
    message.error('模版名称不能为空');
    return;
  }
  if (!formState.content.trim()) {
    message.error('PoC YAML 内容不能为空');
    return;
  }

  saveLoading.value = true;
  try {
    const payload = {
      name: formState.name.trim(),
      severity: formState.severity,
      description: formState.description.trim(),
      content: formState.content
    };

    if (editingId.value) {
      await updateDastPoc(editingId.value, payload);
      message.success('PoC 模板更新成功');
    } else {
      await createDastPoc(payload);
      message.success('PoC 模板创建成功');
    }
    modalVisible.value = false;
    loadPocs();
  } catch (err: any) {
    const errMsg = err.response?.data?.error || '保存 PoC 模板失败';
    message.error(errMsg);
  } finally {
    saveLoading.value = false;
  }
};

const handleDelete = async (id: number) => {
  try {
    await deleteDastPoc(id);
    message.success('PoC 模板删除成功');
    loadPocs();
  } catch (err) {
    message.error('删除 PoC 模板失败');
  }
};

onMounted(() => {
  loadPocs();
});
</script>
