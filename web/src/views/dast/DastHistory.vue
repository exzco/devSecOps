<template>
  <div class="w-full mx-auto max-w-screen-2xl flex flex-col gap-5 bg-white p-2">
    <!-- Main Card container -->
    <a-card title="动态扫描任务列表" :bordered="false" class="rounded-lg w-full border border-zinc-200 bg-white">
      <template #extra>
        <a-button type="default" @click="loadTasks" :loading="loading">
          刷新列表
        </a-button>
      </template>

      <div class="mt-2 bg-white">
        <a-table
          row-key="task_id"
          :columns="columns"
          :data-source="data"
          :scroll="{ x: 'max-content' }"
          size="middle"
          :loading="loading"
          class="w-full bg-white"
        >
          <template #bodyCell="{ text, record, column }">
            <template v-if="column.dataIndex === 'task_name'">
              <span class="font-medium text-zinc-800">{{ record.task_name || '主机漏洞扫描' }}</span>
            </template>

            <template v-if="column.dataIndex === 'task_id'">
              <router-link :to="`/dast/tasks/${record.task_id}`" class="text-sky-600 hover:text-sky-500 font-mono font-semibold">
                {{ record.task_id }}
              </router-link>
            </template>

            <template v-if="column.dataIndex === 'status'">
              <a-space :size="8">
                <a-tag :color="statusColor(record.status)" class="font-semibold px-2 py-0.5">
                  {{ statusLabel(record.status) }}
                </a-tag>
                <span v-if="record.status === 'running'" class="text-zinc-400 text-xs font-mono">
                  ({{ record.scanned_ips }}/{{ record.total_ips }})
                </span>
              </a-space>
            </template>

            <template v-if="column.dataIndex === 'created_at'">
              {{ record.started_at ? new Date(record.started_at).toLocaleString() : '-' }}
            </template>

            <template v-if="column.dataIndex === 'updated_at'">
              {{ record.updated_at ? new Date(record.updated_at).toLocaleString() : '-' }}
            </template>

            <template v-if="column.dataIndex === 'findings'">
              <span :class="record.findings > 0 ? 'text-rose-600 font-bold font-mono' : 'text-zinc-600 font-mono'">
                {{ record.findings }}
              </span>
            </template>

            <template v-if="column.key === 'actions'">
              <a-space :size="8">
                <router-link :to="`/dast/tasks/${record.task_id}`">
                  <a-button type="link" size="small" class="!p-0">
                    查看结果
                  </a-button>
                </router-link>
                <a-button
                  v-if="record.status === 'running'"
                  type="link"
                  danger
                  size="small"
                  class="!p-0"
                  :loading="stoppingIds.has(record.task_id)"
                  @click="handleForceStop(record.task_id)"
                >
                  取消扫描
                </a-button>
                <a-popconfirm
                  title="确认删除该扫描任务结果吗？"
                  ok-text="确认"
                  cancel-text="取消"
                  @confirm="handleDelete(record.task_id)"
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
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue';
import { message } from 'ant-design-vue';
import { getDastTasks, deleteDastTask, stopDastTask } from '../../api';

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
const data = ref<DastTaskSummary[]>([]);
// 正在发出停止指令的任务 ID 集合（乐观 UI）
const stoppingIds = ref<Set<string>>(new Set());

let pollTimer: ReturnType<typeof setInterval> | null = null;

const columns = [
  { title: '任务名称', dataIndex: 'task_name', key: 'task_name', width: 140 },
  { title: '任务 ID', dataIndex: 'task_id', key: 'task_id', width: 220, ellipsis: true },
  { title: '状态', dataIndex: 'status', key: 'status', width: 180 },
  { title: '开放端口数', dataIndex: 'open_ports', key: 'open_ports', width: 110 },
  { title: '漏洞发现数', dataIndex: 'findings', key: 'findings', width: 110 },
  { title: '扫描开始时间', dataIndex: 'created_at', key: 'created_at', width: 180 },
  { title: '更新时间', dataIndex: 'updated_at', key: 'updated_at', width: 180 },
  { title: '操作', key: 'actions', width: 200 },
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
    message.error('获取 DAST 历史任务失败');
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
    message.error('取消扫描失败');
    // 回滚本地状态
    if (idx !== -1) {
      data.value[idx] = { ...data.value[idx], status: 'running' };
    }
  } finally {
    stoppingIds.value.delete(taskId);
  }
};

/** 删除任务：若正在运行/停止中，后端 deleteDastTask 内部已处理取消信号 */
const handleDelete = async (taskId: string) => {
  try {
    await deleteDastTask(taskId);
    message.success('扫描任务已删除');
    loadTasks();
  } catch (err) {
    message.error('删除任务失败');
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
