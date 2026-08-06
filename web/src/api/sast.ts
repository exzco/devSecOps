import api from './client';

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
  use_ai_verification?: boolean;
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
