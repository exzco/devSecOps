<template>
  <div class="w-full mx-auto max-w-screen-xl flex flex-col gap-6 bg-white p-2">
    <!-- Git Repo Scan Form Card -->
    <a-card title="CodeQL SAST 扫描配置" :bordered="false" class="rounded-lg shadow-sm border border-zinc-200 bg-white">
      <div class="p-2">
        <div class="text-sm font-semibold text-zinc-800 border-b border-zinc-200 pb-2.5 mb-5 w-full">
          仓库配置与规则指定
        </div>
        <a-form :model="scanForm" layout="vertical" class="space-y-4">
          <a-form-item label="Repository URL" required>
            <a-input 
              v-model:value="scanForm.url" 
              placeholder="https://github.com/owner/repo.git" 
            />
          </a-form-item>
          
          <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <a-form-item label="Branch" required>
              <a-input 
                v-model:value="scanForm.branch" 
                placeholder="main" 
              />
            </a-form-item>
            
            <a-form-item label="扫描语言 (Language)" required>
              <a-select v-model:value="scanForm.language" placeholder="请选择审计语言">
                <a-select-option value="go">Go</a-select-option>
                <a-select-option value="java">Java</a-select-option>
                <a-select-option value="javascript">JavaScript</a-select-option>
                <a-select-option value="python">Python</a-select-option>
              </a-select>
            </a-form-item>
          </div>

          <a-form-item label="Rules*" required>
            <div class="grid grid-cols-1 md:grid-cols-3 gap-3 p-4 bg-zinc-50 border border-zinc-200 rounded-lg">
              <a-checkbox v-model:checked="scanForm.rules.cwe078">CWE-078 (Command Injection)</a-checkbox>
              <a-checkbox v-model:checked="scanForm.rules.cwe502">CWE-502 (Deserialization)</a-checkbox>
              <a-checkbox v-model:checked="scanForm.rules.cwe094">CWE-094 (Code Injection)</a-checkbox>
              <a-checkbox v-model:checked="scanForm.rules.cwe918">CWE-918 (SSRF)</a-checkbox>
              <a-checkbox v-model:checked="scanForm.rules.cwe611">CWE-611 (XXE)</a-checkbox>
              <a-checkbox v-model:checked="scanForm.rules.cwe089">CWE-089 (SQL Injection)</a-checkbox>
              <a-checkbox v-model:checked="scanForm.rules.cwe079">CWE-079 (XSS)</a-checkbox>
            </div>
          </a-form-item>

          <a-form-item label="测试选项">
            <div class="flex items-center">
              <a-switch v-model:checked="scanForm.enableAi" />
              <span class="ml-3 text-sm text-zinc-600">AI 验证</span>
            </div>
          </a-form-item>

          <div class="pt-4 border-t border-zinc-100 flex items-center justify-between">
            <span class="text-xs text-zinc-400 font-medium">提示：配置完成后点击 Start Scan 将提交并跳转至扫描任务列表</span>
            <a-button type="primary" :loading="submitLoading" class="!bg-zinc-950 !border-zinc-950 !text-white hover:!bg-zinc-800" @click="handleStartScan">
              Start Scan
            </a-button>
          </div>
        </a-form>
      </div>
    </a-card>
  </div>
</template>

<script setup lang="ts">
import { reactive, ref } from 'vue';
import { useRouter } from 'vue-router';
import { message } from 'ant-design-vue';
import { 
  addRepo, 
  triggerScan,
  getRepoList 
} from '../../api';

const router = useRouter();
const submitLoading = ref(false);

const scanForm = reactive({
  url: '',
  branch: 'main',
  language: 'go',
  rules: {
    cwe078: true,
    cwe502: false,
    cwe094: true,
    cwe918: false,
    cwe611: false,
    cwe089: true,
    cwe079: true,
  },
  enableAi: false,
});

const handleStartScan = async () => {
  const url = scanForm.url.trim();
  if (!url) {
    message.error('Repository URL 不能为空');
    return;
  }

  submitLoading.value = true;
  try {
    const reposRes = await getRepoList(1, 100);
    const repos = reposRes.data.data.data || [];
    let repo = repos.find((r: any) => r.url === url);

    let repoId: number;
    if (repo) {
      repoId = repo.id;
    } else {
      const parts = url.split('/');
      let name = parts[parts.length - 1].replace(/\.git$/i, '') || 'manual-repo';
      
      const createRes = await addRepo({
        name: name,
        url: url,
        branch: scanForm.branch.trim() || 'main',
        language: scanForm.language,
        auth_type: 'none',
      });
      repoId = createRes.data.data.id;
    }

    const selectedRules: string[] = [];
    Object.entries(scanForm.rules).forEach(([key, checked]) => {
      if (checked) {
        const num = key.replace('cwe', '');
        selectedRules.push(`cwe-${num}`);
      }
    });

    await triggerScan({
      repo_id: repoId,
      branch: scanForm.branch.trim() || 'main',
      language: scanForm.language,
      rule_profile: 'baseline',
      rules: selectedRules,
      use_ai_verification: scanForm.enableAi,
    });

    message.success('静态审计扫描任务已提交执行');
    router.push({ name: 'SastTasks' });
  } catch (err: any) {
    const errMsg = err.response?.data?.error || '启动扫描任务失败';
    message.error(errMsg);
  } finally {
    submitLoading.value = false;
  }
};
</script>
