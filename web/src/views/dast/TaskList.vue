<template>
  <div class="w-full mx-auto max-w-screen-2xl flex flex-col gap-5 bg-white">
    <a-card title="DAST 扫描任务配置" :bordered="false" class="rounded-lg w-full border border-zinc-200 bg-white">
      <template #extra>
        <a-space :size="8">
          <a-button type="primary" class="premium-gradient border-none hover:opacity-90" @click="handleOpenAdd">
            新增任务
          </a-button>
          <a-button type="default" @click="loadConfigs">
            刷新
          </a-button>
        </a-space>
      </template>

      <div class="mt-2 bg-white">
        <a-table
          row-key="config_id"
          :columns="columns"
          :data-source="data"
          :scroll="{ x: 'max-content' }"
          size="middle"
          :loading="loading"
          class="w-full bg-white"
        >
          <template #bodyCell="{ record, column }">
            <template v-if="column.dataIndex === 'task_name'">
              <span class="font-medium text-zinc-800">{{ record.task_name }}</span>
            </template>

            <template v-if="column.dataIndex === 'config_id'">
              <span class="text-zinc-500 font-mono text-xs">{{ record.config_id }}</span>
            </template>

            <template v-if="column.dataIndex === 'ips'">
              <span class="font-mono text-xs text-zinc-700 break-all">{{ record.ips }}</span>
            </template>

            <template v-if="column.dataIndex === 'ports'">
              <span class="font-mono text-xs">{{ record.ports || 'top1000' }}</span>
            </template>

            <template v-if="column.dataIndex === 'created_at'">
              {{ record.created_at ? new Date(record.created_at).toLocaleString() : '-' }}
            </template>

            <template v-if="column.key === 'actions'">
              <a-space :size="12">
                <a-button
                  type="link"
                  size="small"
                  class="!p-0"
                  :loading="runningIds.has(record.config_id)"
                  @click="handleRerun(record)"
                >
                  开始
                </a-button>
                <a-button
                  type="link"
                  size="small"
                  class="!p-0 !text-amber-500 hover:!text-amber-400"
                  @click="handleOpenEdit(record)"
                >
                  编辑
                </a-button>
                <a-popconfirm
                  title="确认删除该扫描配置吗？（历史扫描记录不受影响）"
                  ok-text="确认"
                  cancel-text="取消"
                  @confirm="handleDeleteConfig(record.config_id)"
                >
                  <a-button type="link" danger size="small" class="!p-0">
                    删除
                  </a-button>
                </a-popconfirm>
              </a-space>
            </template>
          </template>
        </a-table>
      </div>
    </a-card>

    <!-- Create/Edit Config Modal -->
    <a-modal
      v-model:open="visible"
      :title="editingConfigId ? '编辑扫描任务配置' : '新增扫描任务配置'"
      :ok-text="editingConfigId ? '确定' : '保存并启动扫描'"
      cancel-text="取消"
      @ok="handleConfirm"
      @cancel="handleCancel"
    >
      <div class="pt-4">
        <a-form :model="form" layout="vertical">
          <a-form-item label="任务名称" required>
            <a-input v-model:value="form.task_name" placeholder="请输入任务描述名称，例如: 主机漏洞扫描" />
          </a-form-item>
          <a-form-item label="目标 IP / 主机域名" required extra="多个主机用空格分隔。例如：192.168.1.1 192.168.1.5">
            <a-textarea
              v-model:value="form.ips"
              :rows="4"
              placeholder="请输入要进行动态资产扫描的目标主机 IP"
            />
          </a-form-item>
          <a-form-item label="端口范围 (Ports)" extra="留空则默认扫描 Top 1000 端口">
            <a-input v-model:value="form.ports" placeholder="例如: 80,443,8080" />
          </a-form-item>
        </a-form>
      </div>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue';
import { message } from 'ant-design-vue';
import { getDastConfigs, createDastConfig, deleteDastConfig, updateDastConfig, createDastTask } from '../../api';

// 扫描任务配置模板（持久化，与扫描执行记录完全独立）
interface DastConfig {
  config_id: string;
  task_name: string;
  ips: string;
  ports: string;
  created_at: string;
}

const loading = ref(false);
const visible = ref(false);
const editingConfigId = ref<string | null>(null);
const data = ref<DastConfig[]>([]);
// 正在触发扫描的配置 ID（乐观 UI）
const runningIds = ref<Set<string>>(new Set());

const form = reactive({
  task_name: '',
  ips: '',
  ports: '',
});

const columns = [
  { title: '任务名称', dataIndex: 'task_name', key: 'task_name', width: 160 },
  { title: '配置 ID', dataIndex: 'config_id', key: 'config_id', width: 220, ellipsis: true },
  { title: '目标 IP', dataIndex: 'ips', key: 'ips', ellipsis: true },
  { title: '端口范围', dataIndex: 'ports', key: 'ports', width: 150 },
  { title: '创建时间', dataIndex: 'created_at', key: 'created_at', width: 180 },
  { title: '操作', key: 'actions', width: 180, fixed: 'right' as const },
];

const loadConfigs = async () => {
  loading.value = true;
  try {
    const res = await getDastConfigs();
    data.value = (res.data.data || []) as DastConfig[];
  } catch (err) {
    message.error('获取扫描任务配置失败');
  } finally {
    loading.value = false;
  }
};

const handleOpenAdd = () => {
  editingConfigId.value = null;
  form.task_name = '';
  form.ips = '';
  form.ports = '';
  visible.value = true;
};

const handleOpenEdit = (record: DastConfig) => {
  editingConfigId.value = record.config_id;
  form.task_name = record.task_name;
  form.ips = record.ips;
  form.ports = record.ports;
  visible.value = true;
};

const handleCancel = () => {
  visible.value = false;
  editingConfigId.value = null;
};

const handleConfirm = async () => {
  const name = form.task_name.trim();
  const ips = form.ips.trim();
  if (!name) {
    message.error('任务名称不能为空');
    return;
  }
  if (!ips) {
    message.error('目标 IP 不能为空');
    return;
  }

  try {
    const ports = form.ports.trim();
    if (editingConfigId.value) {
      // 编辑模式下更新配置，但不重新触发扫描
      await updateDastConfig(editingConfigId.value, {
        task_name: name,
        ips,
        ports: ports || undefined,
      });
      message.success('配置更新成功');
    } else {
      // 新建模式下保存并启动扫描
      // 1. 创建持久化配置模板
      await createDastConfig({
        task_name: name,
        ips,
        ports: ports || undefined,
      });
      // 2. 同时触发一次扫描任务（在「任务列表」中可见）
      const runId = `${name}-${Date.now()}`;
      await createDastTask({
        task_id: runId,
        task_name: name,
        ips,
        ports: ports || undefined,
      });
      message.success('配置已保存，扫描已启动，可在「任务列表」查看进度');
    }
    visible.value = false;
    editingConfigId.value = null;
    loadConfigs();
  } catch (err: any) {
    const errMsg = err.response?.data?.error || '创建配置失败';
    message.error(errMsg);
  }
};

/** 使用已有配置重新触发一次扫描 */
const handleRerun = async (record: DastConfig) => {
  if (!record.ips) {
    message.warning('配置中无目标 IP，请重新创建配置。');
    return;
  }
  runningIds.value = new Set(runningIds.value).add(record.config_id);
  try {
    const runId = `${record.task_name}-${Date.now()}`;
    await createDastTask({
      task_id: runId,
      task_name: record.task_name,
      ips: record.ips,
      ports: record.ports || '',
    });
    message.success(`任务 [${record.task_name}] 已启动扫描，可在「任务列表」查看进度`);
  } catch (err) {
    message.error('重新启动扫描失败');
  } finally {
    runningIds.value.delete(record.config_id);
  }
};

/** 删除配置模板（仅删配置，历史扫描记录不受影响） */
const handleDeleteConfig = async (configId: string) => {
  try {
    await deleteDastConfig(configId);
    message.success('配置已删除（历史扫描记录不受影响）');
    loadConfigs();
  } catch (err) {
    message.error('删除配置失败');
  }
};

onMounted(() => {
  loadConfigs();
});
</script>
