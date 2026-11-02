<template>
  <div class="w-full mx-auto max-w-screen-2xl h-[calc(100vh-112px)] flex flex-col overflow-hidden">
    <!-- Header banner -->
    <div class="flex items-center justify-between pb-4 border-b border-zinc-200 shrink-0">
      <div>
        <h1 class="text-xl font-bold tracking-tight text-zinc-900">SAST 静态扫描配置</h1>
        <p class="text-xs text-zinc-500 mt-1">
          配置目标代码仓库、选择或合并自建扫描规则套件，按需定制静态审计范围
        </p>
      </div>
      <div class="flex items-center gap-3">
        <a-button @click="loadRepos" :loading="reposLoading">
          <template #icon><RotateCw :size="14" class="inline-block" /></template>
          刷新仓库
        </a-button>
        <a-button type="primary" class="bg-zinc-900 hover:bg-zinc-800" :loading="submitting" @click="handleSubmitScan">
          <template #icon><Play :size="14" class="inline-block" /></template>
          启动静态扫描 (已选 {{ selectedRulesCount }} 项规则)
        </a-button>
      </div>
    </div>

    <!-- Main Content Area: Fixed Left & Scrollable Right -->
    <div class="flex-1 min-h-0 grid grid-cols-1 lg:grid-cols-3 gap-6 pt-4 overflow-hidden">
      <!-- Left Column: Repository & Target Selection (1 col, fixed layout) -->
      <div class="h-full flex flex-col overflow-hidden">
        <a-card title="扫描目标配置" :bordered="false" class="rounded-lg shadow-sm border border-zinc-200 bg-white h-full flex flex-col">
          <a-form layout="vertical" class="space-y-4">
            <a-form-item label="代码来源模式" class="!mb-3">
              <a-radio-group v-model:value="repoMode" button-style="solid" size="small" class="w-full flex">
                <a-radio-button value="select" class="flex-1 text-center">已有仓库</a-radio-button>
                <a-radio-button value="quick" class="flex-1 text-center">快捷导入</a-radio-button>
              </a-radio-group>
            </a-form-item>

            <!-- Mode 1: Select registered repo -->
            <template v-if="repoMode === 'select'">
              <a-form-item label="目标代码仓库" required class="!mb-3">
                <a-select
                  v-model:value="selectedRepoId"
                  placeholder="请选择已注册的代码仓库"
                  :loading="reposLoading"
                  @change="handleRepoChange"
                >
                  <a-select-option v-for="r in repos" :key="r.id" :value="r.id">
                    {{ r.name }} ({{ r.language || '未知语言' }})
                  </a-select-option>
                </a-select>

                <!-- Compact repo info summary -->
                <div v-if="currentRepo" class="mt-2 px-2.5 py-1.5 bg-zinc-50 border border-zinc-200/80 rounded-md text-xs text-zinc-600 flex items-center justify-between gap-2">
                  <div class="flex items-center gap-1.5 truncate">
                    <GitBranch :size="12" class="text-zinc-400 shrink-0" />
                    <span class="font-mono text-[11px] text-zinc-600 truncate" :title="currentRepo.url">{{ currentRepo.url }}</span>
                  </div>
                  <a-tag :color="getLangColor(currentRepo.language)" class="text-[10px] uppercase font-mono m-0 shrink-0">
                    {{ currentRepo.language }}
                  </a-tag>
                </div>
              </a-form-item>
            </template>

            <!-- Mode 2: Quick import repo -->
            <template v-else>
              <a-form-item label="仓库名称" required class="!mb-3">
                <a-input v-model:value="quickForm.name" placeholder="例如: web-backend" size="small" />
              </a-form-item>

              <a-form-item label="Git 仓库 URL" required class="!mb-3">
                <a-input v-model:value="quickForm.url" placeholder="https://github.com/owner/repo.git" size="small" />
              </a-form-item>

              <a-form-item label="开发语言" required class="!mb-3">
                <a-select v-model:value="quickForm.language" placeholder="请选择编程语言" size="small">
                  <a-select-option value="go">Go</a-select-option>
                  <a-select-option value="java">Java</a-select-option>
                  <a-select-option value="javascript">JavaScript / TypeScript</a-select-option>
                  <a-select-option value="python">Python</a-select-option>
                </a-select>
              </a-form-item>
            </template>

            <a-form-item label="扫描分支 (Branch)" class="!mb-3">
              <a-input v-model:value="form.branch" placeholder="main" size="small" />
            </a-form-item>

            <!-- 扫描规则套件选择 -->
            <a-form-item label="扫描规则套件 (Rule Suite)" class="!mb-0">
              <a-select v-model:value="selectedSuiteId" @change="handleSuiteChange">
                <a-select-opt-group label="内置预设套件">
                  <a-select-option v-for="s in defaultSuites" :key="s.id" :value="s.id">
                    <span class="font-medium">{{ s.name }}</span> ({{ s.ruleIds.length }} 项)
                  </a-select-option>
                </a-select-opt-group>
                <a-select-opt-group v-if="customSuites.length > 0" label="我合并保存的套件">
                  <a-select-option v-for="s in customSuites" :key="s.id" :value="s.id">
                    <span class="font-medium">{{ s.name }}</span> ({{ s.ruleIds.length }} 项)
                  </a-select-option>
                </a-select-opt-group>
                <a-select-option v-if="isCustomSelection" value="_custom_" disabled>
                  <span class="italic text-zinc-500">当前：自定义勾选组合 (未保存)</span>
                </a-select-option>
              </a-select>
              <div v-if="activeSuiteDescription" class="mt-2 text-xs text-zinc-500 leading-normal flex items-start gap-1.5 px-0.5">
                <Info :size="12" class="text-zinc-400 mt-0.5 shrink-0" />
                <span>{{ activeSuiteDescription }}</span>
              </div>
            </a-form-item>
          </a-form>
        </a-card>
      </div>

      <!-- Right Column: Rule Selection Matrix (2 cols, independent scrolling) -->
      <div class="lg:col-span-2 h-full flex flex-col overflow-hidden">
        <a-card :bordered="false" class="rounded-lg shadow-sm border border-zinc-200 bg-white h-full flex flex-col overflow-hidden" :bodyStyle="{ flex: '1', display: 'flex', flexDirection: 'column', minHeight: 0, padding: '16px' }">
          <template #title>
            <div class="flex items-center gap-2.5">
              <span class="font-semibold text-sm text-zinc-900">安全规则矩阵</span>
              <a-tag :bordered="false" class="bg-zinc-100 text-zinc-600 text-[11px] font-mono font-medium m-0">
                已选 {{ selectedRulesCount }} / {{ allRules.length }}
              </a-tag>
            </div>
          </template>
          <template #extra>
            <div class="flex items-center gap-2">
              <a-space :size="4">
                <a-button size="small" type="text" class="text-xs text-zinc-600 hover:text-zinc-900 !px-2" @click="handleSelectAll">全选</a-button>
                <span class="text-zinc-300">|</span>
                <a-button size="small" type="text" class="text-xs text-zinc-600 hover:text-zinc-900 !px-2" @click="handleClearAll">清空</a-button>
              </a-space>
              <div class="h-3 w-px bg-zinc-200 mx-1"></div>
              <a-button size="small" @click="showSaveSuiteModal = true" :disabled="selectedRulesCount === 0" class="text-xs">
                <template #icon><Save :size="12" class="inline-block" /></template>
                保存为套件
              </a-button>
              <a-button size="small" type="primary" class="bg-zinc-900 text-xs" @click="handleOpenCreateRule">
                <template #icon><Plus :size="12" class="inline-block" /></template>
                新建规则
              </a-button>
            </div>
          </template>

          <!-- Scrollable Rule Items Grid -->
          <div class="flex-1 overflow-y-auto pr-1 custom-scrollbar">
            <div class="grid grid-cols-1 md:grid-cols-2 gap-2.5">
              <div
                v-for="rule in allRules"
                :key="rule.id"
                class="group relative flex items-start gap-2.5 p-3 rounded-lg border transition-all cursor-pointer select-none"
                :class="selectedRules[rule.id] ? 'border-zinc-900 bg-zinc-50/70 shadow-xs' : 'border-zinc-200 hover:border-zinc-300 bg-white'"
                @click="toggleRule(rule.id)"
              >
                <a-checkbox
                  :checked="selectedRules[rule.id]"
                  class="mt-0.5 shrink-0"
                  @click.stop="toggleRule(rule.id)"
                />
                <div class="flex-1 min-w-0">
                  <div class="flex items-center justify-between gap-1.5">
                    <div class="flex items-center gap-1.5 truncate">
                      <span class="font-mono font-bold text-xs text-zinc-900 shrink-0">{{ rule.tag }}</span>
                      <a-tag :color="getSeverityColor(rule.severity)" class="text-[9px] font-semibold px-1 py-0 m-0 shrink-0">
                        {{ rule.severity }}
                      </a-tag>
                      <a-tag v-if="rule.isCustom" color="purple" class="text-[9px] px-1 py-0 m-0 shrink-0">
                        自定义
                      </a-tag>
                    </div>
                    <!-- Hover-revealed edit button, keeping cards sleek and uncluttered -->
                    <button
                      type="button"
                      class="opacity-0 group-hover:opacity-100 text-zinc-400 hover:text-zinc-900 p-0.5 rounded transition-all shrink-0 hover:bg-zinc-100"
                      title="编辑规则配置"
                      @click.stop="handleOpenEditRule(rule)"
                    >
                      <Pencil :size="11" />
                    </button>
                  </div>
                  <div class="text-xs font-medium text-zinc-800 mt-1 truncate" :title="rule.name">
                    {{ rule.name }}
                  </div>
                  <div class="text-[11px] text-zinc-400 mt-0.5 truncate" :title="rule.desc">
                    {{ rule.desc }}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </a-card>
      </div>
    </div>

    <!-- Modal: Save Current Selection as New Rule Suite -->
    <a-modal
      v-model:open="showSaveSuiteModal"
      title="将当前选中的规则合并为新套件"
      ok-text="确认保存"
      cancel-text="取消"
      @ok="handleSaveNewSuite"
    >
      <div class="pt-2">
        <a-form layout="vertical">
          <a-form-item label="套件名称" required>
            <a-input v-model:value="newSuiteForm.name" placeholder="例如: Web项目核心安全套件" />
          </a-form-item>
          <a-form-item label="套件说明">
            <a-textarea v-model:value="newSuiteForm.description" :rows="2" placeholder="简要说明该规则套件的用途或针对的应用场景" />
          </a-form-item>
          <div class="p-3 bg-zinc-50 border border-zinc-200 rounded text-xs text-zinc-600">
            已包含以下 <span class="font-bold text-zinc-900">{{ selectedRulesCount }}</span> 项规则：
            <div class="flex flex-wrap gap-1 mt-2">
              <a-tag v-for="tag in currentSelectedTags" :key="tag" class="font-mono text-[10px]">
                {{ tag }}
              </a-tag>
            </div>
          </div>
        </a-form>
      </div>
    </a-modal>

    <!-- Modal: Edit Rule Config & File Content -->
    <a-modal
      v-model:open="showEditRuleModal"
      :title="`编辑规则配置: ${editingRuleForm.tag || ''} - ${editingRuleForm.name || ''}`"
      ok-text="保存配置"
      cancel-text="取消"
      width="780px"
      @ok="handleSaveRuleEdit"
    >
      <div class="pt-2">
        <a-form layout="vertical">
          <div class="grid grid-cols-1 md:grid-cols-3 gap-3">
            <a-form-item label="规则编号 (Tag)" required class="md:col-span-1">
              <a-input v-model:value="editingRuleForm.tag" placeholder="如: CWE-078" />
            </a-form-item>
            <a-form-item label="危险等级" required class="md:col-span-1">
              <a-select v-model:value="editingRuleForm.severity">
                <a-select-option value="CRITICAL">CRITICAL (严重)</a-select-option>
                <a-select-option value="HIGH">HIGH (高危)</a-select-option>
                <a-select-option value="MEDIUM">MEDIUM (中危)</a-select-option>
              </a-select>
            </a-form-item>
            <a-form-item label="规则文件路径" class="md:col-span-1">
              <a-input v-model:value="editingRuleForm.filePath" placeholder="如: codeql/cwe-078.ql" />
            </a-form-item>
          </div>

          <a-form-item label="规则名称" required>
            <a-input v-model:value="editingRuleForm.name" placeholder="规则名称描述" />
          </a-form-item>

          <a-form-item label="规则说明">
            <a-input v-model:value="editingRuleForm.desc" placeholder="简要说明检测逻辑及危害场景" />
          </a-form-item>

          <a-form-item required>
            <template #label>
              <div class="flex items-center justify-between w-full">
                <span>规则文件内容 (CodeQL / YAML 定义)</span>
                <span class="text-xs text-zinc-400 font-normal">支持在线更新并保存</span>
              </div>
            </template>
            <a-textarea
              v-model:value="editingRuleForm.fileContent"
              :rows="12"
              class="font-mono text-xs bg-zinc-900 text-zinc-100 p-3 rounded border-zinc-700"
              placeholder="请输入规则文件内容（如 CodeQL .ql 查询或 .qls 套件语法）"
            />
          </a-form-item>
        </a-form>
      </div>
    </a-modal>

    <!-- Modal: Create New Rule Config -->
    <a-modal
      v-model:open="showCreateRuleModal"
      title="新建扫描规则配置"
      ok-text="确认创建"
      cancel-text="取消"
      width="780px"
      @ok="handleConfirmCreateRule"
    >
      <div class="pt-2">
        <a-form layout="vertical">
          <div class="grid grid-cols-1 md:grid-cols-3 gap-3">
            <a-form-item label="规则编号 (Tag)" required class="md:col-span-1">
              <a-input v-model:value="createRuleForm.tag" placeholder="如: CWE-899 或 CUSTOM-01" />
            </a-form-item>
            <a-form-item label="危险等级" required class="md:col-span-1">
              <a-select v-model:value="createRuleForm.severity">
                <a-select-option value="CRITICAL">CRITICAL (严重)</a-select-option>
                <a-select-option value="HIGH">HIGH (高危)</a-select-option>
                <a-select-option value="MEDIUM">MEDIUM (中危)</a-select-option>
              </a-select>
            </a-form-item>
            <a-form-item label="规则文件路径" class="md:col-span-1">
              <a-input v-model:value="createRuleForm.filePath" placeholder="如: custom/rules/my-rule.ql" />
            </a-form-item>
          </div>

          <a-form-item label="规则名称" required>
            <a-input v-model:value="createRuleForm.name" placeholder="例如: 自定义敏感凭据与泄露检测" />
          </a-form-item>

          <a-form-item label="规则说明">
            <a-input v-model:value="createRuleForm.desc" placeholder="简要说明检测逻辑及防护场景" />
          </a-form-item>

          <a-form-item required>
            <template #label>
              <div class="flex items-center justify-between w-full">
                <span>规则文件内容 (CodeQL / YAML 定义)</span>
                <span class="text-xs text-zinc-400 font-normal">基于标准 CodeQL / 污点分析模板</span>
              </div>
            </template>
            <a-textarea
              v-model:value="createRuleForm.fileContent"
              :rows="12"
              class="font-mono text-xs bg-zinc-900 text-zinc-100 p-3 rounded border-zinc-700"
              placeholder="请输入规则文件定义内容"
            />
          </a-form-item>
        </a-form>
      </div>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { message } from 'ant-design-vue'
import { RotateCw, Play, Save, Plus, Pencil, GitBranch, Info } from 'lucide-vue-next'
import {
  getRepoList,
  addRepo,
  triggerScan
} from '@/api'

const router = useRouter()

// Repo selection state
const repoMode = ref<'select' | 'quick'>('select')
const repos = ref<any[]>([])
const reposLoading = ref(false)
const selectedRepoId = ref<number | undefined>(undefined)

const quickForm = reactive({
  name: '',
  url: '',
  language: 'go',
})

const form = reactive({
  branch: 'main',
})

const submitting = ref(false)

const currentRepo = computed(() => {
  return repos.value.find((r) => r.id === selectedRepoId.value)
})

// Rules definitions
interface RuleItem {
  id: string
  tag: string
  name: string
  desc: string
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM'
  filePath?: string
  fileContent?: string
  isCustom?: boolean
}

const generateDefaultRuleContent = (tag: string, name: string): string => {
  const normTag = tag.toUpperCase()
  const lowerTag = normTag.toLowerCase()
  return `/**
 * @name ${name}
 * @description Security query rule targeting ${normTag} vulnerability patterns.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.5
 * @precision high
 * @id go/${lowerTag.replace(/[^a-z0-9]/g, '-')}
 * @tags security
 *       external/cwe/${lowerTag}
 */

import go
import DataFlow::PathGraph

class VulnerabilityConfiguration extends DataFlow::Configuration {
  VulnerabilityConfiguration() { this = "${normTag}Config" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof UntrustedFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof UntrustedFlowSink
  }
}

from VulnerabilityConfiguration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Vulnerable data flow to sink detected from $@.", source.getNode(), "user input"`
}

const builtinRules: RuleItem[] = [
  {
    id: 'cwe078',
    tag: 'CWE-078',
    name: '操作系统命令注入 (OS Command Injection)',
    desc: '检测外部不可信输入未清洗直接传入系统命令调用（如 exec.Command, Runtime.exec）',
    severity: 'CRITICAL',
    filePath: 'codeql/queries/cwe-078.ql',
    fileContent: `/**
 * @name OS Command Injection
 * @description Using untrusted user input directly in command execution functions is vulnerable to RCE.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id go/command-injection
 * @tags security
 *       external/cwe/cwe-078
 */

import go
import semmle.go.security.CommandInjection
import DataFlow::PathGraph

from CommandInjection::Configuration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Command execution sink depends on untrusted input $@.", source.getNode(), "user input"`,
  },
  {
    id: 'cwe094',
    tag: 'CWE-094',
    name: '动态代码注入 (Code Injection / Eval)',
    desc: '检测模板引擎未转义、eval 执行、脚本引擎动态解析外部构造恶意代码漏洞',
    severity: 'CRITICAL',
    filePath: 'codeql/queries/cwe-094.ql',
    fileContent: `/**
 * @name Code Injection
 * @description Evaluating untrusted user input directly leads to remote code execution.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @id go/code-injection
 * @tags security
 *       external/cwe/cwe-094
 */

import go
import semmle.go.security.CodeInjection
import DataFlow::PathGraph

from CodeInjection::Configuration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Code execution depends on untrusted input $@.", source.getNode(), "user input"`,
  },
  {
    id: 'cwe502',
    tag: 'CWE-502',
    name: '不安全反序列化 (Insecure Deserialization)',
    desc: '检测 Java ObjectInputStream、Python pickle/yaml、PHP unserialize 导致的反序列化执行',
    severity: 'CRITICAL',
    filePath: 'codeql/queries/cwe-502.ql',
    fileContent: `/**
 * @name Insecure Deserialization
 * @description Deserializing untrusted input can lead to arbitrary object instantiation or RCE.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @id go/unsafe-deserialization
 * @tags security
 *       external/cwe/cwe-502
 */

import go
import semmle.go.security.UnsafeDeserialization
import DataFlow::PathGraph

from UnsafeDeserialization::Configuration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Deserialization sink depends on untrusted input $@.", source.getNode(), "user input"`,
  },
  {
    id: 'cwe089',
    tag: 'CWE-089',
    name: 'SQL 注入 (SQL Injection)',
    desc: '检测未采用参数化绑定的 SQL 字符串拼接，可能导致数据库脱库或越权篡改',
    severity: 'HIGH',
    filePath: 'codeql/queries/cwe-089.ql',
    fileContent: `/**
 * @name SQL Injection
 * @description Building SQL queries from user-controlled input allows attackers to execute arbitrary database statements.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @id go/sql-injection
 * @tags security
 *       external/cwe/cwe-089
 */

import go
import semmle.go.security.SqlInjection
import DataFlow::PathGraph

from SqlInjection::Configuration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "SQL query depends on untrusted input $@.", source.getNode(), "user input"`,
  },
  {
    id: 'cwe079',
    tag: 'CWE-079',
    name: '跨站脚本攻击 (Cross-site Scripting - XSS)',
    desc: '检测反射型与存储型输入直接渲染至 HTML/DOM 导致客户端脚本执行风险',
    severity: 'HIGH',
    filePath: 'codeql/queries/cwe-079.ql',
    fileContent: `/**
 * @name Cross-site Scripting
 * @description Writing user input directly to a web page allows cross-site scripting attacks.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.0
 * @id go/reflected-xss
 * @tags security
 *       external/cwe/cwe-079
 */

import go
import semmle.go.security.ReflectedXss
import DataFlow::PathGraph

from ReflectedXss::Configuration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "XSS vulnerability due to untrusted input $@.", source.getNode(), "user input"`,
  },
  {
    id: 'cwe611',
    tag: 'CWE-611',
    name: 'XML 外部实体注入 (XXE Injection)',
    desc: '检测 XML 解析器未禁用 DTD 外部实体加载，导致内网探测或任意敏感文件读取',
    severity: 'HIGH',
    filePath: 'codeql/queries/cwe-611.ql',
    fileContent: `/**
 * @name XML External Entity (XXE) Injection
 * @description Parsing XML with external entity resolution enabled allows reading local files or SSRF.
 * @kind problem
 * @problem.severity error
 * @security-severity 8.2
 * @id go/xxe-injection
 * @tags security
 *       external/cwe/cwe-611
 */

import go

from CallExpr call
where call.getTarget().hasQualifiedName("encoding/xml", "NewDecoder")
select call, "XML parser without disabling external entities can be vulnerable to XXE."`,
  },
  {
    id: 'cwe918',
    tag: 'CWE-918',
    name: '服务端请求伪造 (SSRF)',
    desc: '检测 HTTP Client 发送请求的目标 URL 受客户端输入影响，可能被利用探测内网',
    severity: 'HIGH',
    filePath: 'codeql/queries/cwe-918.ql',
    fileContent: `/**
 * @name Server-Side Request Forgery
 * @description Requesting URLs derived from untrusted input allows an attacker to access internal servers.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.5
 * @id go/ssrf
 * @tags security
 *       external/cwe/cwe-918
 */

import go
import semmle.go.security.RequestForgery
import DataFlow::PathGraph

from RequestForgery::Configuration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "SSRF depends on untrusted input $@.", source.getNode(), "user input"`,
  },
  {
    id: 'cwe022',
    tag: 'CWE-022',
    name: '路径穿越与任意文件读取 (Path Traversal)',
    desc: '检测文件读写路径中未过滤 ../ 相对路径符号，导致越权读取服务器系统文件',
    severity: 'HIGH',
    filePath: 'codeql/queries/cwe-022.ql',
    fileContent: `/**
 * @name Path Traversal
 * @description Accessing files with paths constructed from untrusted inputs allows arbitrary file access.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @id go/path-traversal
 * @tags security
 *       external/cwe/cwe-022
 */

import go
import semmle.go.security.PathTraversal
import DataFlow::PathGraph

from PathTraversal::Configuration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Path traversal depends on untrusted input $@.", source.getNode(), "user input"`,
  },
  {
    id: 'cwe798',
    tag: 'CWE-798',
    name: '硬编码敏感凭据 (Hardcoded Credentials)',
    desc: '检测源代码中静态硬编码的 API 密钥、数据库密码、私钥等敏感凭据暴露',
    severity: 'HIGH',
    filePath: 'codeql/queries/cwe-798.ql',
    fileContent: `/**
 * @name Hardcoded Credentials
 * @description Hardcoding credentials in source code exposes secrets to unauthorized users.
 * @kind problem
 * @problem.severity error
 * @security-severity 7.4
 * @id go/hardcoded-credentials
 * @tags security
 *       external/cwe/cwe-798
 */

import go

from StringLit lit
where lit.getValue().regexpMatch("(?i)(password|secret|apikey|token)\\\\s*=\\\\s*['\\"][a-zA-Z0-9+/=]{8,}['\\"]")
select lit, "Hardcoded credential detected in literal string."`,
  },
  {
    id: 'cwe295',
    tag: 'CWE-295',
    name: '不安全的 TLS 证书校验 (Improper Certificate Validation)',
    desc: '检测 InsecureSkipVerify=true 或空 TrustManager，使通信暴露在中间人攻击 (MITM) 威胁下',
    severity: 'MEDIUM',
    filePath: 'codeql/queries/cwe-295.ql',
    fileContent: `/**
 * @name Disabled TLS Verification
 * @description InsecureSkipVerify allows man-in-the-middle attacks.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.5
 * @id go/disabled-tls-verification
 * @tags security
 *       external/cwe/cwe-295
 */

import go

from KeyValueExpr kv
where kv.getKey().(Ident).getName() = "InsecureSkipVerify" and
      kv.getValue().(Ident).getName() = "true"
select kv, "Insecure TLS verification is explicitly enabled."`,
  },
  {
    id: 'cwe327',
    tag: 'CWE-327',
    name: '弱加密/散列算法使用 (Broken / Risky Crypto)',
    desc: '检测 MD5、SHA1 用于密码哈希或 DES、ECB 弱模式加密漏洞',
    severity: 'MEDIUM',
    filePath: 'codeql/queries/cwe-327.ql',
    fileContent: `/**
 * @name Weak Cryptographic Hash
 * @description Use of broken hash algorithms such as MD5 or SHA-1 for security purposes.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.9
 * @id go/weak-cryptographic-hash
 * @tags security
 *       external/cwe/cwe-327
 */

import go

from CallExpr call
where call.getTarget().hasQualifiedName("crypto/md5", "New") or
      call.getTarget().hasQualifiedName("crypto/sha1", "New")
select call, "Weak cryptographic hash function used."`,
  },
  {
    id: 'cwe352',
    tag: 'CWE-352',
    name: '跨站请求伪造防护缺失 (CSRF Missing)',
    desc: '检测状态变更接口未配置 Anti-CSRF Token 或 SameSite Cookie 保护',
    severity: 'MEDIUM',
    filePath: 'codeql/queries/cwe-352.ql',
    fileContent: `/**
 * @name Missing CSRF Protection
 * @description State-changing HTTP handlers without CSRF token protection.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.5
 * @id go/missing-csrf-protection
 * @tags security
 *       external/cwe/cwe-352
 */

import go

from CallExpr call
where call.getTarget().getName().matches("POST|PUT|DELETE")
select call, "State-modifying endpoint should enforce Anti-CSRF validation."`,
  },
]

const allRules = ref<RuleItem[]>([...builtinRules])

// Rule Suites definitions
interface RuleSuite {
  id: string
  name: string
  description: string
  ruleIds: string[]
}

const defaultSuites: RuleSuite[] = [
  {
    id: 'web-core',
    name: 'Web 核心安全套件',
    description: '覆盖 SQL 注入、XSS、SSRF、代码注入、命令注入与 XXE 核心高发漏洞。',
    ruleIds: ['cwe078', 'cwe094', 'cwe089', 'cwe079', 'cwe918', 'cwe611'],
  },
  {
    id: 'rce-high-risk',
    name: 'RCE 与反序列化专项套件',
    description: '专注于命令执行、代码执行与不安全反序列化等系统级严重漏洞。',
    ruleIds: ['cwe078', 'cwe094', 'cwe502'],
  },
  {
    id: 'data-credential',
    name: '数据泄露与凭据安全套件',
    description: '关注敏感数据安全、硬编码凭据、弱加密以及任意路径读取越权风险。',
    ruleIds: ['cwe089', 'cwe798', 'cwe022', 'cwe327'],
  },
  {
    id: 'full-security',
    name: '全量安全规则套件',
    description: '勾选全部 12 项 CodeQL CWE 安全规则，执行全覆盖深度污点审计。',
    ruleIds: builtinRules.map((r) => r.id),
  },
]

const customSuites = ref<RuleSuite[]>([])
const selectedSuiteId = ref<string>('web-core')

// Modal: Edit Rule Config & File Content
const showEditRuleModal = ref(false)
const editingRuleForm = reactive<RuleItem>({
  id: '',
  tag: '',
  name: '',
  desc: '',
  severity: 'HIGH',
  filePath: '',
  fileContent: '',
})

const handleOpenEditRule = (rule: RuleItem) => {
  editingRuleForm.id = rule.id
  editingRuleForm.tag = rule.tag
  editingRuleForm.name = rule.name
  editingRuleForm.desc = rule.desc
  editingRuleForm.severity = rule.severity
  editingRuleForm.filePath = rule.filePath || `codeql/queries/${rule.tag.toLowerCase()}.ql`
  editingRuleForm.fileContent = rule.fileContent || generateDefaultRuleContent(rule.tag, rule.name)
  showEditRuleModal.value = true
}

const handleSaveRuleEdit = () => {
  if (!editingRuleForm.name.trim() || !editingRuleForm.tag.trim()) {
    message.warning('请填写规则编号与规则名称')
    return
  }

  const idx = allRules.value.findIndex((r) => r.id === editingRuleForm.id)
  if (idx !== -1) {
    allRules.value[idx] = {
      ...allRules.value[idx],
      tag: editingRuleForm.tag.trim().toUpperCase(),
      name: editingRuleForm.name.trim(),
      desc: editingRuleForm.desc.trim(),
      severity: editingRuleForm.severity,
      filePath: editingRuleForm.filePath?.trim() || `codeql/queries/${editingRuleForm.tag.toLowerCase()}.ql`,
      fileContent: editingRuleForm.fileContent,
    }
    saveCustomRulesToStorage()
    showEditRuleModal.value = false
    message.success(`规则 [${editingRuleForm.tag}] 配置及文件内容已更新！`)
  }
}

// Modal: Create New Rule Config
const showCreateRuleModal = ref(false)
const createRuleForm = reactive<RuleItem>({
  id: '',
  tag: '',
  name: '',
  desc: '',
  severity: 'HIGH',
  filePath: '',
  fileContent: '',
})

const handleOpenCreateRule = () => {
  const customCount = allRules.value.filter((r) => r.isCustom).length + 1
  createRuleForm.id = `rule_${Date.now()}`
  createRuleForm.tag = `CUSTOM-${String(customCount).padStart(2, '0')}`
  createRuleForm.name = ''
  createRuleForm.desc = ''
  createRuleForm.severity = 'HIGH'
  createRuleForm.filePath = `custom/rules/rule-${customCount}.ql`
  createRuleForm.fileContent = `/**
 * @name Custom Security Rule
 * @description User-defined security inspection rule with CodeQL query pattern.
 * @kind problem
 * @problem.severity warning
 * @id custom/security-check-${customCount}
 * @tags security
 */

import go

from CallExpr call
where call.getTarget().getName().matches("%Secret%")
select call, "Potential sensitive secret access detected in call."`
  showCreateRuleModal.value = true
}

const handleConfirmCreateRule = () => {
  if (!createRuleForm.tag.trim() || !createRuleForm.name.trim()) {
    message.warning('请填写规则编号 (Tag) 与规则名称')
    return
  }

  const newRule: RuleItem = {
    id: createRuleForm.id || `rule_${Date.now()}`,
    tag: createRuleForm.tag.trim().toUpperCase(),
    name: createRuleForm.name.trim(),
    desc: createRuleForm.desc.trim() || '自定义安全检测规则',
    severity: createRuleForm.severity,
    filePath: createRuleForm.filePath?.trim() || `custom/rules/${createRuleForm.tag.toLowerCase()}.ql`,
    fileContent: createRuleForm.fileContent,
    isCustom: true,
  }

  allRules.value.push(newRule)
  selectedRules[newRule.id] = true
  saveCustomRulesToStorage()
  syncSuiteSelectionWithRules()
  showCreateRuleModal.value = false
  message.success(`已成功新建并加入扫描规则「${newRule.tag}」！`)
}

// Load custom rules from localStorage
const loadCustomRules = () => {
  try {
    const raw = localStorage.getItem('sast_custom_rules')
    if (raw) {
      const parsed = JSON.parse(raw) as RuleItem[]
      if (Array.isArray(parsed) && parsed.length > 0) {
        const ruleMap = new Map<string, RuleItem>()
        builtinRules.forEach((r) => ruleMap.set(r.id, { ...r }))
        parsed.forEach((r) => ruleMap.set(r.id, r))
        allRules.value = Array.from(ruleMap.values())
      }
    }
  } catch (e) {
    console.error('Failed to load custom rules from localStorage', e)
  }
}

const saveCustomRulesToStorage = () => {
  try {
    localStorage.setItem('sast_custom_rules', JSON.stringify(allRules.value))
  } catch (e) {
    console.error('Failed to save custom rules to localStorage', e)
  }
}

// Load custom suites from localStorage
const loadCustomSuites = () => {
  try {
    const raw = localStorage.getItem('sast_custom_rule_suites')
    if (raw) {
      customSuites.value = JSON.parse(raw)
    }
  } catch (e) {
    console.error('Failed to parse custom rule suites from localStorage', e)
  }
}

const saveCustomSuitesToStorage = () => {
  try {
    localStorage.setItem('sast_custom_rule_suites', JSON.stringify(customSuites.value))
  } catch (e) {
    console.error('Failed to save custom rule suites to localStorage', e)
  }
}

// Selected rules map: id -> boolean
const selectedRules = reactive<Record<string, boolean>>({})

// Initialize rules based on default suite
defaultSuites[0].ruleIds.forEach((id) => {
  selectedRules[id] = true
})

const selectedRulesCount = computed(() => {
  return Object.values(selectedRules).filter(Boolean).length
})

const currentSelectedTags = computed(() => {
  return allRules.value.filter((r) => selectedRules[r.id]).map((r) => r.tag)
})

const activeSuiteDescription = computed(() => {
  const allSuites = [...defaultSuites, ...customSuites.value]
  const suite = allSuites.find((s) => s.id === selectedSuiteId.value)
  return suite?.description || ''
})

const isCustomSelection = computed(() => {
  return selectedSuiteId.value === '_custom_'
})

// When user changes rule suite dropdown
const handleSuiteChange = (suiteId: string) => {
  if (suiteId === '_custom_') return
  const allSuites = [...defaultSuites, ...customSuites.value]
  const suite = allSuites.find((s) => s.id === suiteId)
  if (suite) {
    allRules.value.forEach((r) => {
      selectedRules[r.id] = suite.ruleIds.includes(r.id)
    })
  }
}

// Check if current rule selection exactly matches any existing suite
const syncSuiteSelectionWithRules = () => {
  const currentActiveIds = allRules.value.filter((r) => selectedRules[r.id]).map((r) => r.id).sort().join(',')
  const allSuites = [...defaultSuites, ...customSuites.value]
  const matched = allSuites.find((s) => [...s.ruleIds].sort().join(',') === currentActiveIds)
  if (matched) {
    selectedSuiteId.value = matched.id
  } else {
    selectedSuiteId.value = '_custom_'
  }
}

const toggleRule = (ruleId: string) => {
  selectedRules[ruleId] = !selectedRules[ruleId]
  syncSuiteSelectionWithRules()
}

const handleSelectAll = () => {
  allRules.value.forEach((r) => {
    selectedRules[r.id] = true
  })
  syncSuiteSelectionWithRules()
}

const handleClearAll = () => {
  allRules.value.forEach((r) => {
    selectedRules[r.id] = false
  })
  syncSuiteSelectionWithRules()
}

// Modal: Save as new suite
const showSaveSuiteModal = ref(false)
const newSuiteForm = reactive({
  name: '',
  description: '',
})

const handleSaveNewSuite = () => {
  const name = newSuiteForm.name.trim()
  if (!name) {
    message.warning('请输入规则套件名称')
    return
  }

  const chosenIds = allRules.value.filter((r) => selectedRules[r.id]).map((r) => r.id)
  if (chosenIds.length === 0) {
    message.warning('请至少勾选一项规则')
    return
  }

  const newSuite: RuleSuite = {
    id: `custom-${Date.now()}`,
    name,
    description: newSuiteForm.description.trim() || `包含 ${chosenIds.length} 项自选安全审计规则的定制套件`,
    ruleIds: chosenIds,
  }

  customSuites.value.push(newSuite)
  saveCustomSuitesToStorage()
  selectedSuiteId.value = newSuite.id
  showSaveSuiteModal.value = false
  newSuiteForm.name = ''
  newSuiteForm.description = ''
  message.success(`已成功合并并创建「${name}」规则套件！`)
}

const handleRepoChange = (id: number) => {
  const repo = repos.value.find((r) => r.id === id)
  if (repo) {
    form.branch = repo.branch || 'main'
  }
}

const loadRepos = async () => {
  reposLoading.value = true
  try {
    const res = await getRepoList(1, 100)
    repos.value = res.data?.data?.data || res.data?.data?.items || []
    if (repos.value.length > 0 && !selectedRepoId.value) {
      selectedRepoId.value = repos.value[0].id
      form.branch = repos.value[0].branch || 'main'
    }
  } catch (err: any) {
    message.error('加载仓库列表失败: ' + (err.message || '网络异常'))
  } finally {
    reposLoading.value = false
  }
}

const handleSubmitScan = async () => {
  let targetRepoId = selectedRepoId.value
  let targetLanguage = currentRepo.value?.language || 'go'
  let targetBranch = form.branch.trim() || 'main'

  if (repoMode.value === 'quick') {
    if (!quickForm.name.trim() || !quickForm.url.trim()) {
      message.warning('请填写快捷导入的仓库名称和 Git URL')
      return
    }
    submitting.value = true
    try {
      const createRes = await addRepo({
        name: quickForm.name.trim(),
        url: quickForm.url.trim(),
        language: quickForm.language,
        branch: targetBranch,
        auth_type: 'none',
      })
      targetRepoId = createRes.data?.data?.id
      targetLanguage = quickForm.language
    } catch (err: any) {
      message.error('创建仓库失败: ' + (err.response?.data?.error || err.message))
      submitting.value = false
      return
    }
  }

  if (!targetRepoId) {
    message.warning('请选择需要执行 SAST 静态分析的目标仓库')
    return
  }

  const chosenRuleTags: string[] = []
  allRules.value.forEach((r) => {
    if (selectedRules[r.id]) {
      chosenRuleTags.push(r.tag.toLowerCase())
    }
  })

  if (chosenRuleTags.length === 0) {
    message.warning('请至少勾选一项待检测的安全规则')
    return
  }

  submitting.value = true
  try {
    await triggerScan({
      repo_id: targetRepoId,
      language: targetLanguage,
      branch: targetBranch,
      rule_profile: selectedSuiteId.value === '_custom_' ? 'custom' : selectedSuiteId.value,
      rules: chosenRuleTags,
    })

    message.success('SAST 静态扫描任务已成功提交！')
    router.push({ name: 'SastTasks' })
  } catch (err: any) {
    message.error('提交扫描任务失败: ' + (err.response?.data?.error || err.message))
  } finally {
    submitting.value = false
  }
}

const getSeverityColor = (sev: string) => {
  switch (sev) {
    case 'CRITICAL':
      return 'red'
    case 'HIGH':
      return 'orange'
    case 'MEDIUM':
      return 'gold'
    default:
      return 'default'
  }
}

const getLangColor = (lang: string) => {
  switch (lang?.toLowerCase()) {
    case 'go':
      return 'blue'
    case 'java':
      return 'orange'
    case 'javascript':
      return 'green'
    case 'python':
      return 'cyan'
    default:
      return 'default'
  }
}

onMounted(() => {
  loadCustomRules()
  loadCustomSuites()
  loadRepos()
})
</script>

<style scoped>
/* Custom sleek scrollbar for rules matrix */
.custom-scrollbar::-webkit-scrollbar {
  width: 6px;
}
.custom-scrollbar::-webkit-scrollbar-track {
  background: #f4f4f5;
  border-radius: 4px;
}
.custom-scrollbar::-webkit-scrollbar-thumb {
  background: #d4d4d8;
  border-radius: 4px;
}
.custom-scrollbar::-webkit-scrollbar-thumb:hover {
  background: #a1a1aa;
}
</style>
