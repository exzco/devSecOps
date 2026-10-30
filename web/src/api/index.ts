import axios from 'axios';

const api = axios.create({
  baseURL: '/api/v1',
});

// ==================== SAST API ====================

export const getRepoList = (page = 1, perPage = 20) =>
  api.get(`/repos?page=${page}&per_page=${perPage}`);

export const addRepo = (data: any) =>
  api.post('/repos', data);

export const updateRepo = (id: number, data: any) =>
  api.put(`/repos/${id}`, data);

export const deleteRepo = (id: number) =>
  api.delete(`/repos/${id}`);

export const batchDeleteRepos = (ids: number[]) =>
  api.post('/repos/batch-delete', { ids });

export interface TriggerScanPayload {
  repo_id: number;
  language: string;
  branch: string;
  query_suite?: string;
  rule_profile?: string;
  rules?: string[];
}

export const triggerScan = (payload: TriggerScanPayload) =>
  api.post('/scans', { ...payload, type: 'sast' });

export const deleteScanTask = (taskId: number) =>
  api.delete(`/scan/tasks/${taskId}`);

export const getScanTasks = (page = 1, perPage = 20, repoId?: number, status?: string) => {
  const params = new URLSearchParams({
    page: String(page),
    per_page: String(perPage),
  });

  if (repoId) params.append('repo_id', String(repoId));
  if (status) params.append('status', status);

  return api.get(`/scan/tasks?${params.toString()}`);
};

export const getScanVulnerabilities = (taskId: number, page = 1, perPage = 20) =>
  api.get(`/scan/vulnerabilities?task_id=${taskId}&page=${page}&per_page=${perPage}`);

export const getScanTaskLogs = (taskId: number) =>
  api.get(`/scan/tasks/${taskId}/logs`);

// ==================== DAST APIs ====================

export interface CreateDastPayload {
  task_name?: string;
  ips: string;
  ports?: string;
}

export const createDastTask = (payload: CreateDastPayload) =>
  api.post('/scans', {
    type: 'dast',
    task_name: payload.task_name,
    target: payload.ips,
    ports: payload.ports,
  });

export const getDastTasks = () =>
  api.get('/dast/scan/tasks');

export const getDastTaskStatus = (taskId: string) =>
  api.get(`/dast/scan/tasks/${taskId}/status`);

export const getDastTaskResults = (taskId: string) =>
  api.get(`/dast/scan/tasks/${taskId}/results`);

export const deleteDastTask = (taskId: string) =>
  api.delete(`/dast/scan/tasks/${taskId}`);

export const getDastTaskAssets = (taskId: string) =>
  api.get(`/dast/scan/tasks/${taskId}/assets`);

// ==================== DAST 扫描配置模板 APIs ====================

export interface CreateConfigPayload {
  config_id?: string;
  task_name: string;
  ips: string;
  ports?: string;
}

export const getDastConfigs = () =>
  api.get('/dast/scan/configs');

export const createDastConfig = (payload: CreateConfigPayload) =>
  api.post('/dast/scan/configs', payload);

export const deleteDastConfig = (configId: string) =>
  api.delete(`/dast/scan/configs/${configId}`);

export const updateDastConfig = (configId: string, payload: CreateConfigPayload) =>
  api.post(`/dast/scan/configs/update/${configId}`, payload);

// ==================== SCA 依赖与漏洞分析 APIs ====================

export interface CreateScaPayload {
  repo_id?: number;
  branch?: string;
  language?: string;
  target?: string;
}

export const createScaTask = (payload: CreateScaPayload) =>
  api.post('/scans', { ...payload, type: 'sca' });

export const getScaTasks = (page = 1, pageSize = 20) =>
  api.get(`/sca/tasks?page=${page}&page_size=${pageSize}`);

export const getScaTaskDetail = (id: number) =>
  api.get(`/sca/tasks/${id}`);

export const getScaDependencies = (id: number) =>
  api.get(`/sca/tasks/${id}/dependencies`);

export const getScaVulnerabilities = (id: number) =>
  api.get(`/sca/tasks/${id}/vulnerabilities`);

export default api;
