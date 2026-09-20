# AGENTS.md

本文件面向所有在该仓库工作的 AI 代理（Agent），说明仓库结构与工作约定。

## 项目概述

华中科技大学网络空间安全学院《网络空间安全综合实践3》课程的 CTF 题解（writeup）仓库。
仓库仅保存个人解题记录，用于课程作业提交。

## 目录结构

```
├── README.md            # 项目说明（中英双语）
├── AGENTS.md            # 本文件
├── .gitignore
├── .local/              # 本地私有配置（平台地址、账号口令、cookie），不入库
├── 1-1/                 # 题解：第 1 次作业第 1 题
│   ├── writeup.md       # 题解文档
│   └── screenshots/     # 解题过程截图
└── (1-2, 1-3, 2-1, ...) # 按此格式逐题展开
```

**命名规则**：文件夹为 `作业编号-题目编号`（如 `1-1`、`1-2`、`2-1`）。
一个文件夹 = 一道题的完整题解。

## 角色约定

本仓库默认由 Agent **全面负责做题**（角色 B）：从定位题面、启动实例、侦察利用、取 Flag、提交答案，到向教学大模型提问、截图与原始记录，均由 Agent 自主完成，不需要用户逐步授权或口述过程。用户可在会话开始时（或中途）指定其他角色，Agent 不得擅自越界。

### 角色 A：Writeup 撰写者（记录员）

- 只负责记录与整理，**不主动解题**。素材来源：解题 Agent 的原始记录（`.local/process/<目录>-ctf-process.md` 等），或用户口述/粘贴的操作步骤与截图；AI 的主要任务是把它们整理成规范的 writeup 文档。
- 用户会逐步提供操作步骤与截图（图片来自剪贴板临时目录），AI 负责核对截图内容与叙述的一致性，必要时指出矛盾之处（以实测/截图为准）。
- 可以解释漏洞原理、补充总结与修复建议，但默认不作为解题主导方。

### 角色 B（默认）：解题执行者（Assistant）

- **全权解题**：Agent 自主完成一道题的完整链路——定位章节与题面、启动并访问实例、枚举与利用、取得 Flag、在平台提交全部答案（选择题 + Flag 题）并复核判分、向教学问答平台提 3–6 个问题、按约定截图、写原始过程记录（详见《完整复用流程》一节）。
- **必须留下解题记录**：全程把关键命令与输出、失败尝试、Flag、提交与判分结果同步写入 `.local/process/<目录>-ctf-process.md`（体例见《完整复用流程》第 3 步），问答原文另存 `.local/process/<目录>-qa-transcript.json`；该记录是写 writeup 的唯一依据，不允许「做完了但没有可交接的记录」。
- 过程中如实保留失败尝试（截图 + 记录）；关键命令、请求/响应要点、Flag 都要留痕，截图存入 `<目录>/screenshots/`。
- 遇到卡点时自行调整思路或借助教学大模型与工具，不把解题责任推回用户；仅在必须由用户决定的事项上中断询问（如授权范围、是否提交推送）。
- **不负责写 writeup**：即使全程由 Agent 解题，也不主动创建/更新 `writeup.md`，除非用户明确要求（或按三 Agent 流程交由写 writeup 的 Agent）。
- 用户明确要求「只讨论 / 只给思路 / 先别动手」时，退回协作模式：逐步引导而非一次性给出完整解法。

### 角色判定与切换

- **默认角色为 B（解题执行者）**：用户给出题目（如「帮我解决题 N」「接着做下一题」）即按全面解题模式执行全流程，无需逐条操作授权。
- 用户明确说「只讨论」「只给思路」「别动手」时，限制在讨论/提示范围内。
- 用户明确要求写/整理 writeup（或提供解题过程与截图要求整理）时切到角色 A；角色可中途切换，以用户明确指示为准。

## writeup.md 模板

每题必须包含以下章节（中文撰写，命令与代码保留原文）：

| 章节 | 内容 |
| --- | --- |
| 题目信息 | 题目名称、分类、题目描述 |
| 环境信息 | 平台地址、注册方式、账号信息 |
| 解题过程 | 按步骤编号记录，关键处引用截图 |
| Flag | 代码块包裹的最终 Flag |
| 总结与心得 | 漏洞原理、做题方法、修复建议 |

- 解题过程中的每个关键步骤都要保留（尤其是失败尝试，如"大小写变体被拒"），它们是题解完整性的重要部分。
- 截图在 writeup 中以相对路径 `screenshots/xxx.png` 引用。

## 截图约定

- 存放在题目文件夹的 `screenshots/` 子目录中。
- 命名格式：`NN-步骤简述.png`（编号两位递增，如 `01-register-success-f12.png`）。
- 截图从剪贴板临时目录（`/var/folders/.../pi-clipboard-*.png`）拷入仓库时，必须重命名为符合约定的文件名，不得使用原始随机文件名。

### Agent 自动截图方法（无 GUI 权限时）

本机为 macOS，装有 Google Chrome，但 Agent 进程**没有屏幕录制权限**：`screencapture -x out.png` 会报 `could not create image from display`，`open -a "Google Chrome" URL` 能拉起浏览器却也截不到屏。因此不要尝试截取真实桌面/浏览器窗口，改用**无头 Chrome（playwright-core 驱动系统已装的 Chrome）**截取页面。

一次性准备（脚本与输出放仓库外的临时目录，避免入库）：

```bash
mkdir -p /tmp/shot && cd /tmp/shot && npm init -y && npm i playwright-core
```

脚本模板（`/tmp/shot/shots.mjs`，登录 + 截图）：

```js
import { chromium } from 'playwright-core';
const B = 'http://172.17.0.13:12031';                 // 靶机地址
const browser = await chromium.launch({
  channel: 'chrome', headless: true,                  // 用系统 Chrome，无需下载浏览器
  args: ['--no-proxy-server'],                        // 必须：本机代理变量指向未启动的 127.0.0.1:7897
});
const ctx = await browser.newContext({
  viewport: { width: 1280, height: 900 }, deviceScaleFactor: 2,   // 2 倍缩放，截图更清晰
});
const page = await ctx.newPage();
await page.goto(B + '/login', { waitUntil: 'networkidle' });
await page.fill('input[name=username]', 'USER');       // 按实际表单字段名填写
await page.fill('input[name=password]', 'PASS');
await Promise.all([page.waitForURL('**/dev'), page.click('button.btn')]);
await page.goto(B + '/dev', { waitUntil: 'networkidle' });
await page.screenshot({ path: '/tmp/shot/out/03-dev-center.png', fullPage: true });
await browser.close();
```

运行：`cd /tmp/shot && node shots.mjs`（用 `.mjs` 后缀即可在顶层写 await）。

常用场景：

- **需要 `Authorization` 头才能访问的接口**（如 `/api/me`）：新建 context 带上请求头，再导航到接口 URL，Chrome 会把原始 JSON 渲染成页面，截图同时保留真实 URL 与响应体：
  ```js
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 800 }, deviceScaleFactor: 2, extraHTTPHeaders: { Authorization: 'Bearer ' + token } });
  await (await ctx.newPage()).goto(B + '/api/me', { waitUntil: 'networkidle' });
  ```
- **长页面 / 长对话**：整页用 `page.screenshot({ fullPage: true })`；只截局部时先用 `page.evaluate(() => el.scrollIntoView({ block: 'end' }))` 滚到目标区块（教学问答平台的对话在 `#log` 内，可设 `#log.scrollTop = #log.scrollHeight`）。
- **等待流式输出**（教学问答平台）：轮询 `#log` 文本长度，连续数秒不再增长且明显长于提问前再截图；上一条回答还在生成（`#status` 显示「生成中…」）时点击发送会无效。
- **登录态复用**：同一 `context` 内页面共享 cookie；跨 context 需重新登录。

兜底方案（无需登录的页面），直接用 Chrome 自带无头截图：

```bash
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --headless=new \
  --no-proxy-server --window-size=1280,900 --screenshot=/tmp/x.png URL
```

注意事项：

- 无头截图**不含浏览器地址栏/标签页**；writeup 需要展示地址栏时应请用户手动截图。
- 截图后必须核对内容（文件已生成、画面确为期望步骤、登录态正确），再按 `NN-步骤简述.png` 命名拷入题目目录；用户从剪贴板粘贴的图（`/var/folders/.../codex-clipboard-*.png`）同样要重命名为约定格式。
- 后台常驻脚本（`nohup ... &`）在会话结束后可能被回收，需要长时间轮询（如等待靶机 bot）时改用交互式会话持续运行。

## 工作流程

完整的三 Agent 复用流程（启动实例 → 解题提交 → 写 writeup，含向教学大模型提问）见下一节。

### 角色 A（Writeup 撰写者）

1. 取素材：解题 Agent 的原始记录（`.local/process/<目录>-ctf-process.md`、问答原文），或用户口述/粘贴的解题过程与截图路径 → AI 核对图片与叙述
2. AI 整理/更新对应题目的 `writeup.md`
3. 用户确认内容（AI 应主动列出与旧记录不一致或无法核实的信息）
4. 提交推送：`git add -A && git commit -m "Add writeup for challenge X-Y: <一句话主题>" && git push`

### 角色 B（解题执行者，默认）

1. 用户给出题目 → Agent 定位章节与题面并启动实例（见下一节《完整复用流程》），无需逐条操作授权
2. Agent 自主完成完整链路：枚举 → 利用 → 取 Flag → 提交答案并复核判分 → 向教学大模型提问 → 截图 → 写原始过程记录
3. 题目完成后：提醒用户可将过程交给角色 A（或另一个 Agent）整理 writeup；README 进度列表默认提醒用户更新，用户明确要求时由 Agent 更新并入库

## 完整复用流程：启动实例 → 解题提交 → 写 writeup（三 Agent 协作）

本仓库默认按该流程执行（2-3 / 课程第 8 节已跑通）：主 Agent 负责侦察、启动实例与汇总核验，另派两个子 Agent 分别「解题」与「写 writeup」；用户只需发题、确认内容与决定是否入库。

### 0. 准备

```bash
set -a; . .local/qa-platform.env; . .local/vmc-platform.env; set +a
# VMC cookie 过期（约 2 天）时重新登录
curl -sS -k --noproxy '*' -m 25 -c .local/vmc-cookies.txt -X POST "$VMC_BASE/api/login" \
  -H 'Content-Type: application/json' \
  --data "{\"username\":\"$PLATFORM_USER\",\"password\":\"$PLATFORM_PASS\"}"
```

### 1. 定位章节与题面

- `GET $VMC_BASE/api/course?ID=1639&pwd=&isMulEnv=0` → `course.sections[]`，按 `title` 找章节，记录 `id`（sectionID）、`number` 与 `questionGroups[].questionIDs`（各题 questionID）。
- 课程 `number` 与仓库目录对应：`6→2-1`、`7→2-2`、`8→2-3`、`9→2-4`（同系列 G1–G4 依次类推）。
- `GET $VMC_BASE/api/student/newTestPaper?sectionID=<sid>&contestMode=0` → `answers[]`：`questionType` 1 填空、2 单选、3 多选、4 代码/Flag；`questionContent` 是 JSON 字符串（含 `content` / `options`）。

### 2. 启动靶机实例

```bash
# a) 查章节实验环境，记录 environment.id（envID，如 C080-G3-F → 1399）
curl -sS -k --noproxy '*' -m 25 -b .local/vmc-cookies.txt \
  "$VMC_BASE/api/student/lab/vm?ID=<sectionID>&questionID=<flagQuestionID>&constMode=0&isMulEnv=0"
# b) 创建/启动实例：labNumber 必须填 0（填 1 会报 "labNumber is greater than or equal to the length of the configs"）
curl -sS -k --noproxy '*' -m 90 -b .local/vmc-cookies.txt -X POST "$VMC_BASE/api/student/lab/vm" \
  -H 'Content-Type: application/json' \
  --data '{"sectionID":<sid>,"labNumber":0,"constMode":0,"isMulEnv":0,"envID":<envID>}'
# c) 轮询实例，直到 state=Running，记录 podID 与 portInfos 端口映射
curl -sS -k --noproxy '*' -m 25 -b .local/vmc-cookies.txt \
  "$VMC_BASE/api/student/instances?offset=0&limit=10&ID=<envID>"
```

- 访问地址 `http://172.17.0.13:<publishedPort>`：80 → ttyd Web 终端（打开即已登录的低权限 shell），22 → SSH（密码常未知，一般不用）。
- 实例有保存时限（`saveTime` 约 3 小时）会自动回收；交付前要确保 Flag、截图、判分都已核对完成。
- 终端驱动：`python3 .local/process/ttyd_drive.py <host>:<port> "<命令>"`（WebSocket）；截图时用无头浏览器直接在该页面键入命令，保证截图与过程一致（见「Agent 自动截图方法」）。

### 3. 派 Agent 1：解题 + 提交 + 问大模型 + 截图记录

任务书需写清：

- 题面 / 题型 / flag 题要求、靶机地址与终端驱动方式；
- 先枚举后利用（`id` → `sudo -n -l` → SUID / capabilities → cron / 进程 / 可写目录），**失败尝试也必须截图与记录**；
- 向教学问答平台提 3–6 个问题：漏洞原理、机制细节、加固与应急排查各有覆盖；截图命名 `NN-AI问答-<主题>.png`；
- 提交答案（见下方「答案提交与判分」）并用 `answerHistory` 复核；
- 产出：`<目录>/screenshots/NN-步骤简述.png`、原始记录 `.local/process/<目录>-ctf-process.md`、问答原文 `.local/process/<目录>-qa-transcript.json`（后两者不入库）。
- **必须留下解题记录**（写 writeup 的唯一依据，Agent 1 交付前不得删除）——`.local/process/<目录>-ctf-process.md` 至少包含：
  1. 环境信息表：平台 / 章节 / sectionID / envID / podID / 终端与 SSH 地址 / 题型清单；
  2. 完整时间线：每条命令 + 关键输出原文，关键节点标注对应截图文件名；
  3. 失败尝试清单：现象、原因、如何调整；
  4. 答案与判分：各题提交格式与 `answerHistory` 复核结果（`isCorrect`）；
  5. AI 问答：问题列表与回答要点，问答原文另存 `-qa-transcript.json`；
  6. 截图清单与靶机遗留物（未清理的文件，便于复现与善后）。
- 常见坑：ttyd 的 bash 会做历史展开（`!` 触发，必要时先 `set +H`）；无头浏览器键入长命令偶发吞引号/字符，命令尽量简单 ASCII，截图前核对回显。

### 4. 派 Agent 2：写 writeup

- 输入（只读）：Agent 1 的原始记录、问答原文与截图；
- 输出 `<目录>/writeup.md`，按本文件模板章节撰写；**默认不写选择题解析**（用户另有要求除外），选择题只在「环境信息」备注提交与判分结果；
- 失败尝试如实保留；逐步核对命令/输出与截图的对应关系，发现矛盾以截图/实测为准并在交付说明中指出。

### 5. 主 Agent 汇总核验与入库

- 核验：截图引用是否全部存在且无多余文件、`answerHistory` 是否全部判对、Flag 在原始记录与 writeup 中是否一致；
- README 进度列表默认提醒用户更新；用户明确要求时可由 Agent 更新（目录结构区块同步补一行）；
- 用户确认后入库：`git add -A && git commit -m "Add writeup for challenge X-Y: <一句话主题>" && git push`。

### 答案提交与判分（实证格式）

`POST $VMC_BASE/api/student/submitAnswers`，multipart 多个 `answers` 字段，值为 **JSON 字符串**：

| 题型 | answer 值 |
| --- | --- |
| 单选（type 2） | `{"answer":["C"],"num":1}` |
| 多选（type 3） | `{"answer":["A","B","D"],"num":3}` |
| 填空（type 1） | `{"num":3,"answer":["","","vmc{...}"]}`（平台会把中间位规范化为 `"true"`） |

- 纯字母/纯文本提交会被判错，填空题的值被丢弃为 `{"num":0,"answer":["",""]}`；
- 判分以 `GET $VMC_BASE/api/student/get/answerHistory?sectionID=<sid>&contestMode=0` 的 `isCorrect` 为准；顶层 `scoreRate` 常显示 0、`testPaper`/`selfJudge` 不返回分数，均属平台正常现象。

## 其他约定

- writeup 与注释使用中文；命令、Flag、代码保持原样。
- 不提交任何未授权测试涉及的真实攻击目标信息（题目标靶场地址仅为课程环境）。
- 不要修改 README.md 的进度列表；有新题完成时提醒用户更新进度。

## 教学问答平台（Qwen2.5）调用方法

课程内的教学问答平台可用脚本直接调用，不必开浏览器。

- **平台地址、账号口令、cookie 一律存放在 `.local/`（已被 `.gitignore` 忽略），禁止写入本文件或任何被跟踪的文件**；配置方法见 README「本地配置」一节。
- 下文以 `$PLATFORM_BASE` 表示平台根地址（形如 `http://<host>`，不含末尾斜杠），需先连 OpenVPN（校园网），仅 HTTP。
- 脚本用法：先 `set -a; . .local/qa-platform.env; set +a` 载入 `PLATFORM_BASE` / `PLATFORM_USER` / `PLATFORM_PASS`。
- 本机注意：shell 的 `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` 指向未启动的 `127.0.0.1:7897`，访问该地址必须加 `--noproxy '*'`。
- 沙箱内网络受限，相关 curl 命令需以非沙箱权限（`require_escalated`）执行。

### 登录

```bash
set -a; . .local/qa-platform.env; set +a
curl -sS -i -m 20 --noproxy '*' -c .local/qa-cookies.txt \
  -X POST "$PLATFORM_BASE/login" \
  --data-urlencode "username=$PLATFORM_USER" --data-urlencode "password=$PLATFORM_PASS"
```

成功返回 `302` + `location: /chat`，并下发 `session` cookie（Flask 签名 cookie，有效期 24 小时）。失败返回 `401`，页面内含 `账号或口令不正确`。

### 提问（chat 入口）

```bash
set -a; . .local/qa-platform.env; set +a
curl -sS -N -m 90 --noproxy '*' -b .local/qa-cookies.txt \
  -X POST "$PLATFORM_BASE/api/chat" \
  -F 'message=你好'
```

- `multipart/form-data`；字段：`message`（正文，≤4000 字）、`conversation_id`（可选，续聊指定会话）；上传文件时另加 `extract`（抽取后的正文）、`filename`、`truncated`（`1` / `0`）。
- 响应为 SSE 流，逐块 `data: {...}`，按需解析：
  - `{"conversation_id": 5123, "context": {"pct": 3}}` — 会话号与上下文占用百分比
  - `{"queue": {"position": 0, "waiting": 0, "busy": 1, "slots": 64}}` — 排队信息
  - `{"delta": "..."}` — 增量文本，需按序拼接
  - `{"done": true}` — 本次生成结束
  - `{"error": "..."}` — 出错信息

### 其他端点

| 端点 | 方法 | 说明 |
| --- | --- | --- |
| `/api/chat/history?conversation_id=<id>` | GET | 读取指定会话的全部消息 |
| `/api/chat/history` | GET | 读取最近一次会话 |
| `/api/chat/conversations?offset=0&limit=50&q=<关键词>` | GET | 历史列表 / 搜索，每次 50 条 |
| `/api/chat/conversations/<id>` | DELETE | 删除会话 |
| `/api/preview` | POST | 上传文件抽取文本（`multipart` 字段 `file`） |
| `/api/chat/export?window=6h\|1d\|7d\|30d\|all` | GET | 导出笔记 Markdown |

### 使用限制

- 同一账号约 **每分钟 10 次** 提问，脚本必须限速。
- 单次回答上限 **1024 token**，被截断时可追加「请继续」。
- 会话变长后模型只保留最近约 **30%** 上下文，长任务应另开 `conversation_id`。
- 上传文件上限 2MB，抽出文本上限约 2400 字（超出只保留开头）。

## 实训平台（VMCourse）题目与实例调用方法

课程题目与靶机实例都在实训平台上，同样可以用脚本直接调用，不必开浏览器。

- **平台根地址存放在 `.local/vmc-platform.env` 的 `VMC_BASE`（实训平台「VMCourse / 国产化教学实训平台」，本机直连地址也在该文件）**，前端是 Vue 单页应用，页面内容全部由 `/api/*` 接口渲染。
- 账号口令与教学问答平台相同（取自 `.local/qa-platform.env` 的 `PLATFORM_USER` / `PLATFORM_PASS`），但**两者不是同一个服务**（地址见 `.local/`），会话互不相通。
- 站点使用自签名证书，curl 需加 `-k`；访问一律加 `--noproxy '*'`；沙箱内网络受限，相关命令需以非沙箱权限（`require_escalated`）执行。
- 登录后的 `SESSIONID` cookie 存到 `.local/vmc-cookies.txt`（有效期 2 天），与账号口令一样**只放 `.local/`，禁止写入任何被跟踪的文件**。

### 登录

```bash
set -a; . .local/qa-platform.env; . .local/vmc-platform.env; set +a
curl -sS -k --noproxy '*' -m 25 -c .local/vmc-cookies.txt \
  -X POST "$VMC_BASE/api/login" \
  -H 'Content-Type: application/json' \
  --data "{\"username\":\"$PLATFORM_USER\",\"password\":\"$PLATFORM_PASS\"}"
```

成功返回 `{"code":0,...}` 并下发 `SESSIONID` cookie（有效期 2 天）；失败返回 `{"code":10105,"msg":"login failed"}`。注意 `POST /api/login/portal` 是门户免登录接口，用账号口令调用同样报 `10105`。

### 查题

| 端点 | 方法 | 说明 |
| --- | --- | --- |
| `/api/course?ID=<courseID>&pwd=&isMulEnv=0` | GET | 课程详情与章节列表（`sections[]`，含 `questionGroups[].questionIDs`、`experimentID`、附件 `sectionFiles`），实测 `ID=1639` |
| `/api/section?ID=<sid>` | GET | 单个章节详情 |
| `/api/student/newTestPaper?sectionID=<sid>&contestMode=0` | GET | 题面。`answers[].questionContent` 是 JSON 字符串（含 `content` / `options`）；`questionType`：1 填空、2 单选、3 多选、4 代码/Flag 题 |
| `/api/student/section/file/<文件名>?ID=<sid>&decryptStr=` | GET | 下载章节附件（题面素材 `.md`、`challenge.elf` 等）；同 URL 用 HEAD 可探测附件是否存在 |

当前课程 `1639` 共 41 个章节（40 道题 + 课程说明），每个题章节 = 3 单选 + 1 多选 + 1 道实战 Flag 题。

### 实例（靶机）

| 端点 | 方法 | 说明 |
| --- | --- | --- |
| `/api/student/environments?offset=0&limit=10&content=` | GET | 我的环境列表（`environments[]`：`id` / `title` / `comment`） |
| `/api/student/instances?offset=0&limit=10&ID=<envID>` | GET | 环境下的实例（`name`、`podID`、`state`、`image`、`portInfos` 端口映射、`timeout`） |
| `/api/vm/action` | POST | 实例操作，body `{"name":"<podID>","labID":<envID>,"action":"start"\|"reboot"\|"state"\|"destroy","vmType":2}` |
| `/api/student/lab/stopContainer` | PUT | 停止容器，body `{"Name":..,"LabID":..,"Action":..,"VmType":..}` |
| `/api/student/lab/vm` | GET | 查询章节实验环境，参数 `ID`（章节 ID）、`questionID`、`constMode`、`isMulEnv`；该章节没有实验环境时 `environment` 为 `null` |
| `/api/student/lab/vm` | POST | 创建/启动章节实验环境，body `{sectionID,labNumber,constMode,isMulEnv,envID}` |

```bash
# 查询实例状态（只读；先用 environments / instances 拿到 podID 与端口映射）
curl -sS -k --noproxy '*' -m 25 -b .local/vmc-cookies.txt \
  -X POST "$VMC_BASE/api/vm/action" -H 'Content-Type: application/json' \
  -d '{"name":"<podID>","labID":<envID>,"action":"state","vmType":2}'
# 启动/重启/销毁：把 action 换成 start / reboot / destroy，其余字段不变
```

- 实例操作用 `podID`（不是页面显示的 `name`），`labID` 填环境 ID（`environments[].id`），`vmType` 目前为 `2`；用 `name` 或 `labID=0` 会返回 `{"code":10000,"msg":"record not found"}`。
- 访问方式：容器端口映射到宿主机 `172.17.0.13`，按 `portInfos` 用 `http://<hostIP>:<publishedPort>` 访问（22 → SSH，80 → HTTP）。环境名通常对应题章节编号，例如 `C077-G3-F` → `http://172.17.0.13:12031/`。
- 课程 `1639` 实测各章节的 `lab/vm` 查询都返回 `environment: null`，靶机实例统一在「我的实例」里按环境管理（账号下现有 `DVWA实验`、`C077-G3-F` 两个环境）。

### 网页入口

- 学生中心 →「我的实例」：`/student/vm`（启动 / 重启 / 停止 / 销毁实例，查看端口映射）
- 课程页：`/student/course/<courseID>`（章节列表，如 `/student/course/1639`）
- 答题页：`/student/course/answer/<sectionID>`
