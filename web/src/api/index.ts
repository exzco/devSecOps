import axios from 'axios';

const api = axios.create({
  baseURL: '/api/v1',
});

// ==================== SAST API ====================

export const getRepoList = (page = 1, perPage = 20) =>
  api.get(`/repos/list?page=${page}&per_page=${perPage}`);

export const addRepo = (data: any) =>
  api.post('/repos', data);

export const updateRepo = (id: number, data: any) =>
  api.post(`/repos/update/${id}`, data);

export const deleteRepo = (id: number) =>
  api.post(`/repos/delete/${id}`);

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
  api.post('/scan/tasks', payload);

export const deleteScanTask = (taskId: number) =>
  api.post(`/scan/tasks/delete/${taskId}`);

export const getScanTasks = (page = 1, perPage = 20, repoId?: number, status?: string) => {
  const params = new URLSearchParams({
    page: String(page),
    per_page: String(perPage),
  });

  if (repoId) params.append('repo_id', String(repoId));
  if (status) params.append('status', status);

  return api.get(`/scan/ListTasks?${params.toString()}`);
};

export const getScanVulnerabilities = (taskId: number, page = 1, perPage = 20) =>
  api.get(`/scan/vulnerabilities?task_id=${taskId}&page=${page}&per_page=${perPage}`);

export const getScanTaskLogs = (taskId: number) =>
  api.get(`/scan/tasks/${taskId}/logs`);

// ==================== DAST APIs ====================

export interface CreateDastPayload {
  task_id?: string;
  ips: string;
  ports?: string;
}

export const createDastTask = (payload: CreateDastPayload) =>
  api.post('/dast/scan/tasks', payload);

export const getDastTasks = () =>
  api.get('/dast/scan/tasks');

export const getDastTaskStatus = (taskId: string) =>
  api.get(`/dast/scan/tasks/${taskId}/status`);

export const getDastTaskResults = (taskId: string) =>
  api.get(`/dast/scan/tasks/${taskId}/results`);

export const deleteDastTask = (taskId: string) =>
  api.post(`/dast/scan/tasks/delete/${taskId}`);

// ==================== DAST PoC APIs ====================
export const getDastPocList = () =>
  api.get('/dast/pocs');

export const createDastPoc = (data: any) =>
  api.post('/dast/pocs', data);

export const updateDastPoc = (id: number, data: any) =>
  api.post(`/dast/pocs/update/${id}`, data);

export const deleteDastPoc = (id: number) =>
  api.post(`/dast/pocs/delete/${id}`);

export default api;
