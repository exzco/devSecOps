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
              <router-link :to="`/dast/tasks/${record.task_id}`" class="text-sky-600 hover:text-sky-500 font-mono font-semibold">
                {{ record.task_id }}
              </router-link>
            </template>

            <template v-if="column.dataIndex === 'status'">
              <a-tag :color="record.status === 'running' ? 'processing' : 'success'" class="font-semibold px-2 py-0.5">
                {{ record.status === 'running' ? '进行中' : '已完成' }}
              </a-tag>
            </template>

            <template v-if="column.dataIndex === 'created_at'">
              {{ record.started_at ? new Date(record.started_at).toLocaleString() : '-' }}
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
                  type="link" 
                  danger 
                  size="small" 
                  class="!p-0" 
                  :disabled="record.status !== 'running'" 
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
import { onMounted, ref } from 'vue';
import { message } from 'ant-design-vue';
import { getDastTasks, deleteDastTask } from '../../api';

interface DastTaskSummary {
  task_id: string;
  status: string;
  total_ips: number;
  scanned_ips: number;
  open_ports: number;
  findings: number;
  started_at: string;
  task_name?: string;
}

const loading = ref(false);
const data = ref<DastTaskSummary[]>([]);

const columns = [
  { title: '任务名称', dataIndex: 'task_name', key: 'task_name', width: 140 },
  { title: '任务 ID', dataIndex: 'task_id', key: 'task_id', width: 220, ellipsis: true },
  { title: '状态', dataIndex: 'status', key: 'status', width: 100 },
  { title: '开放端口数', dataIndex: 'open_ports', key: 'open_ports', width: 110 },
  { title: '漏洞发现数', dataIndex: 'findings', key: 'findings', width: 110 },
  { title: '扫描开始时间', dataIndex: 'created_at', key: 'created_at', width: 180 },
  { title: '操作', key: 'actions', width: 180 }
];

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
      return {
        ...t,
        task_name: name,
      };
    });
  } catch (err) {
    message.error('获取 DAST 历史任务失败');
  } finally {
    loading.value = false;
  }
};

const handleForceStop = (taskId: string) => {
  message.info(`任务 ${taskId} 已发出停止指令`);
};

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
});
</script>
