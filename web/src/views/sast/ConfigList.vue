<template>
  <div class="space-y-6">
    <div class="rounded-md border border-zinc-200 bg-white p-6 shadow-sm">
      <h1 class="text-xl font-bold tracking-tight text-zinc-950 mb-6">CodeQL SAST 扫描</h1>

      <!-- Tab Header -->
      <div class="border-b border-zinc-200 mb-6">
        <button class="pb-2.5 border-b-2 border-blue-600 font-semibold text-blue-600 text-sm tracking-wide">
          Git仓库扫描
        </button>
      </div>

      <!-- Form Content -->
      <a-form layout="vertical" class="max-w-4xl space-y-4">
        <!-- Repository URL -->
        <a-form-item required>
          <template #label>
            <span class="font-medium text-zinc-900">Repository URL</span>
          </template>
          <a-input
            v-model:value="form.repo_url"
            placeholder="https://github.com/owner/repo.git"
            class="h-10 rounded-md border-zinc-200 text-sm"
          />
        </a-form-item>

        <!-- Branch -->
        <a-form-item>
          <template #label>
            <span class="font-medium text-zinc-900">Branch</span>
          </template>
          <a-input
            v-model:value="form.branch"
            placeholder="main"
            class="h-10 rounded-md border-zinc-200 text-sm"
          />
        </a-form-item>

        <!-- Rules (CWE) -->
        <a-form-item required>
          <template #label>
            <span class="font-medium text-zinc-900">Rules (CWE)</span>
          </template>
          <div class="grid grid-cols-1 md:grid-cols-3 gap-y-3.5 gap-x-6 pt-1">
            <a-checkbox v-model:checked="rulesMap['CWE-078']">
              <span class="text-sm text-zinc-800">CWE-078 (Command Injection)</span>
            </a-checkbox>
            <a-checkbox v-model:checked="rulesMap['CWE-502']">
              <span class="text-sm text-zinc-800">CWE-502 (Deserialization)</span>
            </a-checkbox>
            <a-checkbox v-model:checked="rulesMap['CWE-094']">
              <span class="text-sm text-zinc-800">CWE-094 (Code Injection)</span>
            </a-checkbox>
            <a-checkbox v-model:checked="rulesMap['CWE-918']">
              <span class="text-sm text-zinc-800">CWE-918 (SSRF)</span>
            </a-checkbox>
            <a-checkbox v-model:checked="rulesMap['CWE-611']">
              <span class="text-sm text-zinc-800">CWE-611 (XXE)</span>
            </a-checkbox>
            <a-checkbox v-model:checked="rulesMap['CWE-089']">
              <span class="text-sm text-zinc-800">CWE-089 (SQL Injection)</span>
            </a-checkbox>
            <a-checkbox v-model:checked="rulesMap['CWE-079']">
              <span class="text-sm text-zinc-800">CWE-079 (XSS)</span>
            </a-checkbox>
          </div>
        </a-form-item>

        <!-- Enable AI Audit -->
        <a-form-item>
          <template #label>
            <div class="flex items-center gap-1.5">
              <span class="font-medium text-zinc-900">AI 验证</span>
              <a-tooltip title="开启后，大语言模型将自动对 CodeQL 产生的 SARIF 结果进行上下文污染链鉴别，过滤误报。">
                <QuestionCircleOutlined class="text-zinc-400 hover:text-zinc-600 text-xs cursor-pointer" />
              </a-tooltip>
            </div>
          </template>
          <a-switch v-model:checked="form.enable_ai" />
        </a-form-item>

        <!-- Submit Button -->
        <div class="pt-4">
          <a-button
            type="primary"
            class="h-10 px-6 font-medium bg-blue-600 hover:bg-blue-700 border-blue-600 rounded-md shadow-sm"
            :loading="scanning"
            @click="handleStartScan"
          >
            Start Scan
          </a-button>
        </div>
      </a-form>
    </div>
  </div>
</template>

<script setup lang="ts">
import { reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { message } from 'ant-design-vue'
import { QuestionCircleOutlined } from '@ant-design/icons-vue'
import { addRepo, triggerScan } from '../../api/sast'

const router = useRouter()
const scanning = ref(false)

const form = reactive({
  repo_url: '',
  branch: 'main',
  enable_ai: false,
})

const rulesMap = reactive<Record<string, boolean>>({
  'CWE-078': true,
  'CWE-502': true,
  'CWE-094': true,
  'CWE-918': true,
  'CWE-611': true,
  'CWE-089': true,
  'CWE-079': true,
})

const handleStartScan = async () => {
  if (!form.repo_url.trim()) {
    message.warning('请输入 Repository URL')
    return
  }

  const selectedRules = Object.keys(rulesMap).filter(k => rulesMap[k])
  if (selectedRules.length === 0) {
    message.warning('请至少选择一项 CWE 检查规则')
    return
  }

  scanning.value = true
  try {
    // 1. Add repo metadata
    const repoName = form.repo_url.split('/').pop()?.replace('.git', '') || 'repo-' + Date.now()
    const addRes: any = await addRepo({
      name: repoName,
      url: form.repo_url.trim(),
      language: 'go',
      branch: form.branch.trim() || 'main',
      stars: 0,
      auth_type: 'none',
    })

    const repoId = addRes.data?.data?.id || addRes.data?.id || 1

    // 2. Trigger scan task
    const scanRes: any = await triggerScan({
      repo_id: repoId,
      language: 'go',
      branch: form.branch.trim() || 'main',
      query_suite: 'security-extended',
      rules: selectedRules,
      use_ai_verification: form.enable_ai,
    })

    if (scanRes.data.code === 0 || scanRes.data.status === 'success') {
      message.success('已成功发起 SAST 静态代码扫描任务！')
      router.push({ name: 'SastTasks' })
    } else {
      message.success('扫描任务已提交')
      router.push({ name: 'SastTasks' })
    }
  } catch (err: any) {
    message.error('提交扫描任务失败: ' + (err.response?.data?.error || err.message))
  } finally {
    scanning.value = false
  }
}
</script>
