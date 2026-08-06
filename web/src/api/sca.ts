import api from './client';

export interface CreateScaProjectPayload {
  name: string;
  git_url: string;
  branch?: string;
  language?: string;
  description?: string;
}

export const getScaProjects = (page = 1, perPage = 20) =>
  api.get(`/sca/projects?page=${page}&per_page=${perPage}`);

export const createScaProject = (payload: CreateScaProjectPayload) =>
  api.post('/sca/projects', payload);

export const deleteScaProject = (id: number) =>
  api.post(`/sca/projects/delete/${id}`);

export const triggerScaScan = (projectId: number) =>
  api.post('/sca/tasks', { project_id: projectId });

export const getScaTasks = (page = 1, perPage = 20, projectId?: number) => {
  const params = new URLSearchParams({
    page: String(page),
    per_page: String(perPage),
  });
  if (projectId) params.append('project_id', String(projectId));
  return api.get(`/sca/tasks?${params.toString()}`);
};

export const getScaDependencies = (projectId?: number) => {
  const url = projectId ? `/sca/dependencies?project_id=${projectId}` : '/sca/dependencies';
  return api.get(url);
};

export const getScaVulnerabilities = (page = 1, perPage = 20, projectId?: number) => {
  const params = new URLSearchParams({
    page: String(page),
    per_page: String(perPage),
  });
  if (projectId) params.append('project_id', String(projectId));
  return api.get(`/sca/vulnerabilities?${params.toString()}`);
};
