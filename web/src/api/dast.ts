import api from './client';

export interface CreateDastPayload {
  task_id?: string;
  task_name?: string;
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

export const stopDastTask = (taskId: string) =>
  api.post(`/dast/scan/tasks/stop/${taskId}`);

export const getDastTaskAssets = (taskId: string) =>
  api.get(`/dast/scan/tasks/${taskId}/assets`);

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
  api.post(`/dast/scan/configs/delete/${configId}`);

export const updateDastConfig = (configId: string, payload: CreateConfigPayload) =>
  api.post(`/dast/scan/configs/update/${configId}`, payload);

export const getDastPocList = () =>
  api.get('/dast/pocs');

export const getDastPoc = (id: string) =>
  api.get(`/dast/pocs/${id}`);

export const createDastPoc = (data: any) =>
  api.post('/dast/pocs', data);

export const updateDastPoc = (id: string, data: any) =>
  api.post(`/dast/pocs/update/${id}`, data);

export const deleteDastPoc = (id: string) =>
  api.post(`/dast/pocs/delete/${id}`);

export const getDastCveList = (keyword = '', year = 2025) =>
  api.get(`/dast/cve/fetch?keyword=${encodeURIComponent(keyword)}&year=${year}&local=true`);

export const fetchDastCves = (keyword = '', year = 2025) =>
  api.get(`/dast/cve/fetch?keyword=${encodeURIComponent(keyword)}&year=${year}`);

export const generateAiPoc = (data: { cve_id: string; target_tag: string; description?: string }) =>
  api.post('/dast/pocs/generate-ai', data);

