# 前端开发规范 (Frontend Development Specification)

本规范定义了项目前端开发的整体设计准则、色彩系统、系统布局、组件样式覆写以及模块架构解耦标准。全站页面及新增组件在编写 Vue、TypeScript、TailwindCSS 及 Ant Design Vue 样式时必须严格遵守本规范，以确保系统在各种显示分辨率下都能呈现高度一致、精致且稳定的 **Shadcn Light** 界面体验。

---

## 1. 界面设计与色彩系统 (Design & Color Theme)

系统严格基于 **Shadcn UI (Light Mode)** 极简主义设计哲学，去除多余渐变与大面积彩色背景，以极细的单色线条和强烈的文字对比度构建现代界面。

### 1.1 核心色值配置
* **背景基底色**：全站主背景统一为纯白色 `#ffffff`（或 `zinc-50` 极淡灰 `#fafafa` 用于列表/表头等区域的分隔背景）。
* **主要文字色**：统一为 `Zinc-950`（`#09090b`），高对比度的纯黑。
* **次要辅助字色**：统一为 `Zinc-500`（`#71717a`）或 `Zinc-400`（`#a1a1aa`），用于说明文字、水印或非活动状态。
* **边框与分割线**：全站通用边线统一为 `Zinc-200`（`#e4e4e7`），线宽固定为 `1px`。
* **主交互高亮色**：
  * 默认高亮/Primary 按钮：`Zinc-950`（`#09090b`），前景色为 `#ffffff`。
  * 鼠标悬停（Hover）：`Zinc-800`（`#27272a`）或 `Zinc-100`（`#f4f4f5`）。

### 1.2 几何与物理规范
* **圆角大小**：通用卡片、输入框、下拉框、弹窗和按钮的圆角统一设定为 `6px`（对应 Tailwind 的 `rounded-md`）。
* **投影规范**：主视口视图内移除一切深色重阴影。仅在 Modal、Drawer 等悬浮弹出组件上允许使用极淡的扩散阴影（如 `0 10px 15px -3px rgba(0, 0, 0, 0.05)`）。

---

## 2. 系统布局与视口滚动规范 (Viewport & Scrolling)

为了保障系统不发生水平晃动，并且高度超出时能自动生成滚动条，必须采用如下的“固定框架 + 局部滚动”模型：

```
+-----------------------------------------------------------+
|               |  Header: Fixed (64px, border-b)           |
|               +-------------------------------------------+
|               |  a-layout-content: flex-1                 |
|               |                                           |
|               |  +-------------------------------------+  |
| Sidebar       |  |  Sub view (Height: auto)            |  |
| Fixed (240px) |  |                                     |  |
| height: 100vh |  |  Content overflows...               |  |
| border-r      |  |                                     |  |
|               |  |  [Scrollbar y auto triggers here]   |  |
|               |  +-------------------------------------+  |
|               |                                           |
+-----------------------------------------------------------+
```

### 2.1 顶级视口锁定
* `#app` 及顶层 `html, body` 必须设定为 `height: 100vh; width: 100vw; overflow: hidden;`。锁定页面顶级视口，防止全局滚动条引起闪烁或页面整体位移。

### 2.2 固定侧边栏 (Sider)
* 侧边栏采用物理固定定位，`height: 100vh; position: fixed; left: 0; z-index: 100;`。
* 侧边栏宽度在未折叠时固定设定为 `240px`。
* 移除侧边栏底部的切换收折按钮以保持其简洁度，固定展开展示。

### 2.3 右侧内容容器自适应
* 右侧 `a-layout` 容器的 `marginLeft` 固定设定为 `240px`。
* 右侧容器必须显式附加 `min-width: 0;`。这是在 Flex 布局中，防止内部包含的表格等组件因内容过宽强行拉伸父容器，从而将左侧侧边栏挤出屏幕的关键。
* `a-layout-header`（顶部导航栏）高度固定为 `64px`，并设置 `shrink-0` 属性防止在垂直方向上被压缩。

### 2.4 主内容滚动上下文
* 内容容器 `a-layout-content` 为系统内页的**唯一滚动容器**，必须设定类名为 `flex-1 overflow-y-auto overflow-x-hidden p-6`。
* **内页高度规范**：挂载在路由下的常规内页组件（如列表、表单、详情）高度一律设为自适应（高度 `auto`），**坚决禁止在常规内页最外层包裹 `h-full` 或 `overflow-hidden`**。这样当内容增多时，滚动条能够正常在 `a-layout-content` 上生成。
* **特殊情况说明**：类似于 SAST 代码审计等需要双分栏、左侧列表、右侧 timeline 分别独立滚动的复合控制页，才动态把内页容器高度限制为 `h-[calc(100vh-112px)] overflow-hidden`，并在内部的各个组件板块中独立定义 `overflow-y-auto`。

---

## 3. 组件样式覆盖规范 (UI Components Override)

对 Ant Design Vue 组件的样式深度定制应在全局中维护，避免使用内联 `!important` 污染组件。

### 3.1 导航菜单 (Menu)
* **分割线重合去除**：`.ant-menu` 组件自带的右边线必须隐藏：
  ```css
  .ant-menu {
    border-right: none !important;
  }
  ```
  以此确保侧边栏的右边框（`border-r`）是唯一展示的垂线，防止双线重合导致线宽粗细不一。

### 3.2 按钮 (Buttons)
* **Primary 按钮**：设为 Shadcn 标志性的黑底白字：
  ```css
  .ant-btn-primary {
    background-color: #09090b !important;
    border-color: #09090b !important;
    color: #ffffff !important;
  }
  .ant-btn-primary:hover {
    background-color: #27272a !important; /* 悬停变为 Zinc-800 */
    border-color: #27272a !important;
  }
  ```
* **Default 按钮**：白底、细灰边框，Hover 时淡灰背景。

### 3.3 数据表格 (Tables)
* **纯净排版**：移除表格的纵向列分割线，仅保留横向行分割线（`border-bottom`）。
* **表头风格**：表头 `.ant-table-thead > tr > th` 背景统一设为 `#fafafa`，文字统一为 `Zinc-500`。
* **横向自适应**：表格配置横向自适应滚动 `:scroll="{ x: '100%' }"`。**除特殊分栏视口外，绝不允许设置 `:scroll="{ y: ... }"` 等纵向限高属性**，防止表格数据因硬编码高度发生截断。

### 3.4 卡片与表单 (Cards & Forms)
* 所有卡片（`a-card`）及表单输入框（`a-input`、`a-select`、`a-textarea`）边框色统一设为 `Zinc-200`（`#e4e4e7`）。
* 输入框在获取焦点时，高亮边框色改为 `Zinc-400`（`#a1a1aa`），并配置统一的 6px 圆角。

---

