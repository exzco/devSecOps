<template>
  <div class="w-full mx-auto max-w-screen-2xl flex flex-col gap-5 bg-white">
    <a-card title="DAST 扫描任务" :bordered="false" class="rounded-lg w-full border border-zinc-200 bg-white">
      <template #extra>
        <a-space :size="8">
          <a-button type="primary" class="premium-gradient border-none hover:opacity-90" @click="handleOpenAdd">
            新增任务
          </a-button>
          <a-button type="default" @click="loadTasks">
            刷新
          </a-button>
          <a-button type="primary" danger :disabled="selectedRowKeys.length === 0" @click="handleBatchDelete">
            删除任务
          </a-button>
        </a-space>
      </template>

      <div class="mt-2 bg-white">
        <a-table
          row-key="task_id"
          :columns="columns"
          :data-source="data"
          :row-selection="{ selectedRowKeys: selectedRowKeys, onChange: onSelectChange }"
          :scroll="{ x: '100%' }"
          size="middle"
          :loading="loading"
          class="w-full bg-white"
        >
          <template #bodyCell="{ text, record, column }">
            <template v-if="column.dataIndex === 'task_name'">
              <span class="font-medium text-zinc-800">{{ record.task_name || '主机漏洞扫描' }}</span>
            </template>

            <template v-if="column.dataIndex === 'task_id'">
              <router-link :to="`/dast/tasks/${record.task_id}`" class="text-sky-400 hover:text-sky-300 font-mono font-semibold">
                {{ record.task_id }}
              </router-link>
            </template>

            <template v-if="column.dataIndex === 'status'">
              <a-tag :color="statusColor(record.status)" class="font-semibold px-2 py-0.5">
                {{ statusLabel(record.status) }}
              </a-tag>
            </template>

            <template v-if="column.dataIndex === 'created_at'">
              {{ record.started_at ? new Date(record.started_at).toLocaleString() : '-' }}
            </template>

            <template v-if="column.dataIndex === 'updated_at'">
              {{ record.updated_at ? new Date(record.updated_at).toLocaleString() : '-' }}
            </template>

            <template v-if="column.dataIndex === 'total_ips'">
              <span class="font-mono">{{ record.total_ips }}</span>
            </template>

            <template v-if="column.key === 'actions'">
              <a-space :size="12">
                <a-button
                  v-if="record.status !== 'running' && record.status !== 'stopping'"
                  type="link"
                  size="small"
                  class="!p-0"
                  @click="handleRerun(record)"
                >
                  开始
                </a-button>
                <a-button
                  v-if="record.status === 'running'"
                  type="link"
                  danger
                  size="small"
                  class="!p-0"
                  :loading="stoppingIds.has(record.task_id)"
                  @click="handleForceStop(record.task_id)"
                >
                  强制停止
                </a-button>
              </a-space>
            </template>
          </template>
        </a-table>
      </div>
    </a-card>

    <!-- Create Dast Task Modal -->
    <a-modal
      v-model:open="visible"
      title="新增 DAST 动态扫描任务"
      ok-text="确定"
      cancel-text="取消"
      @ok="handleConfirm"
      @cancel="handleCancel"
    >
      <div class="pt-4">
        <a-form :model="form" layout="vertical">
          <a-form-item label="任务名称" required>
            <a-input v-model:value="form.task_name" placeholder="请输入任务描述名称，例如: dedecms" />
          </a-form-item>
          <a-form-item label="任务标识 ID (可选)">
            <a-input v-model:value="form.task_id" placeholder="如果不填，系统将随机生成" />
          </a-form-item>
          <a-form-item label="目标 IP / 主机域名" required extra="多个主机用空格分隔。例如：192.168.1.1 192.168.1.5">
            <a-textarea
              v-model:value="form.ips"
              :rows="4"
              placeholder="请输入要进行动态资产扫描的目标主机 IP"
            />
          </a-form-item>
          <a-form-item label="端口范围 (Ports)">
            <a-input v-model:value="form.ports" placeholder="例如: 80,443,8080 (默认扫描 Top 1000 端口)" />
          </a-form-item>
        </a-form>
      </div>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref } from 'vue';
import { message } from 'ant-design-vue';
import { getDastTasks, createDastTask, deleteDastTask, stopDastTask } from '../../api';

interface DastTaskSummary {
  task_id: string;
  status: string;
  total_ips: number;
  scanned_ips: number;
  open_ports: number;
  findings: number;
  started_at: string;
  updated_at?: string;
  task_name?: string;
}

const loading = ref(false);
const visible = ref(false);
const data = ref<DastTaskSummary[]>([]);
const selectedRowKeys = ref<string[]>([]);
// 正在发出停止指令的任务 ID 集合（乐观 UI）
const stoppingIds = ref<Set<string>>(new Set());

let pollTimer: ReturnType<typeof setInterval> | null = null;

const form = reactive({
  task_name: '',
  task_id: '',
  ips: '',
  ports: '',
});

const columns = [
  { title: '任务名称', dataIndex: 'task_name', key: 'task_name', width: 140 },
  { title: '任务 ID', dataIndex: 'task_id', key: 'task_id', width: 180, ellipsis: true },
  { title: '目标主机数', dataIndex: 'total_ips', key: 'total_ips', width: 110 },
  { title: '状态', dataIndex: 'status', key: 'status', width: 120 },
  { title: '创建时间', dataIndex: 'created_at', key: 'created_at', width: 180 },
  { title: '更新时间', dataIndex: 'updated_at', key: 'updated_at', width: 180 },
  { title: '操作', key: 'actions', width: 140, fixed: 'right' as const },
];

/** 状态 → Ant Design Tag color */
const statusColor = (status: string) => {
  switch (status) {
    case 'running':  return 'processing';
    case 'stopping': return 'warning';
    case 'stopped':  return 'default';
    case 'done':
    case 'completed':
    case 'success':  return 'success';
    default:         return 'default';
  }
};

/** 状态 → 中文文本 */
const statusLabel = (status: string) => {
  switch (status) {
    case 'running':  return '进行中';
    case 'stopping': return '正在停止';
    case 'stopped':  return '已停止';
    case 'done':
    case 'completed':
    case 'success':  return '已完成';
    default:         return status || '未知';
  }
};

const onSelectChange = (keys: any[]) => {
  selectedRowKeys.value = keys.map((k) => String(k));
};

/** 是否有进行中或正在停止的任务 */
const hasActiveTask = computed(() =>
  data.value.some((t) => t.status === 'running' || t.status === 'stopping')
);

const loadTasks = async () => {
  loading.value = true;
  try {
    const res = await getDastTasks();
    const tasks = res.data.data || [];

    data.value = tasks.map((t: any) => {
      let name = '主机漏洞扫描';
      if (t.task_id.includes('dedecms')) {
        name = 'dedecms';
      } else if (t.task_id.startsWith('dast-')) {
        name = '主机扫描';
      }
      return { ...t, task_name: t.task_name || name };
    });
  } catch (err) {
    message.error('获取 DAST 扫描任务失败');
  } finally {
    loading.value = false;
  }
};

/** 自动轮询：当有活跃任务时，每 3s 自动刷新状态 */
const startPolling = () => {
  if (pollTimer) return;
  pollTimer = setInterval(async () => {
    if (!hasActiveTask.value) return;
    try {
      const res = await getDastTasks();
      const tasks = res.data.data || [];
      data.value = tasks.map((t: any) => {
        let name = '主机漏洞扫描';
        if (t.task_id.includes('dedecms')) name = 'dedecms';
        else if (t.task_id.startsWith('dast-')) name = '主机扫描';
        return { ...t, task_name: t.task_name || name };
      });
    } catch (_) {
      // silent
    }
  }, 3000);
};

const stopPolling = () => {
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
};

const handleOpenAdd = () => {
  form.task_name = '';
  form.task_id = '';
  form.ips = '';
  form.ports = '';
  visible.value = true;
};

const handleCancel = () => {
  visible.value = false;
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
    let finalTaskId = form.task_id.trim();
    if (finalTaskId) {
      if (!finalTaskId.includes(name)) {
        finalTaskId = `${name}-${finalTaskId}`;
      }
    } else {
      finalTaskId = `${name}-${Date.now()}`;
    }

    await createDastTask({
      task_id: finalTaskId,
      ips: ips,
      ports: form.ports.trim() || undefined,
    });

    message.success('DAST 扫描任务启动成功');
    visible.value = false;
    loadTasks();
  } catch (err: any) {
    const errMsg = err.response?.data?.error || '启动 DAST 任务失败';
    message.error(errMsg);
  }
};

const handleRerun = async (record: DastTaskSummary) => {
  try {
    const parts = record.task_id.split('-');
    let prefix = parts[0] || 'rerun';
    let newId = `${prefix}-${Date.now()}`;

    await createDastTask({
      task_id: newId,
      ips: '127.0.0.1',
      ports: '80,443',
    });
    message.success(`任务 ${prefix} 已重新开始扫描`);
    loadTasks();
  } catch (err) {
    message.error('重新启动扫描失败');
  }
};

/** 强制停止：立即乐观更新本地状态为"正在停止"，后台轮询会同步最终状态 */
const handleForceStop = async (taskId: string) => {
  // 乐观更新
  stoppingIds.value = new Set(stoppingIds.value).add(taskId);
  const idx = data.value.findIndex((t) => t.task_id === taskId);
  if (idx !== -1) {
    data.value[idx] = { ...data.value[idx], status: 'stopping' };
  }

  try {
    await stopDastTask(taskId);
    message.success('停止指令已下发，任务正在停止中…');
  } catch (err) {
    message.error('停止任务失败');
    // 回滚本地状态
    if (idx !== -1) {
      data.value[idx] = { ...data.value[idx], status: 'running' };
    }
  } finally {
    stoppingIds.value.delete(taskId);
  }
};

/** 删除单个任务：若任务正在运行/停止中，先调用 stop 接口，再删除 */
const handleDelete = async (taskId: string) => {
  const task = data.value.find((t) => t.task_id === taskId);
  try {
    if (task && (task.status === 'running' || task.status === 'stopping')) {
      // 后端 deleteDastTask 内部已处理取消信号，但同步调用 stop 确保状态刷新
      await stopDastTask(taskId).catch(() => {});
    }
    await deleteDastTask(taskId);
  } catch (err) {
    // Fail silently for batch
  }
};

const handleBatchDelete = async () => {
  if (selectedRowKeys.value.length === 0) return;
  try {
    for (const id of selectedRowKeys.value) {
      await handleDelete(id);
    }
    message.success('选中的任务已成功删除');
    selectedRowKeys.value = [];
    loadTasks();
  } catch (err) {
    message.error('批量删除任务失败');
  }
};

onMounted(() => {
  loadTasks();
  startPolling();
});

onUnmounted(() => {
  stopPolling();
});
</script>
