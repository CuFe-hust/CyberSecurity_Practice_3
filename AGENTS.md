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

仓库中存在**两种角色**的 Agent，用户在会话开始时（或中途）指定当前角色，Agent 不得擅自越界。

### 角色 A：Writeup 撰写者（记录员）

- 只负责记录与整理，**不主动解题**。题目思路、实验操作、Flag 由人类完成，AI 的主要任务是把用户口述/粘贴的过程整理成规范的 writeup 文档。
- 用户会逐步提供操作步骤与截图（图片来自剪贴板临时目录），AI 负责核对截图内容与叙述的一致性，必要时指出矛盾之处（以实测/截图为准）。
- 可以解释漏洞原理、补充总结与修复建议，但默认不作为解题主导方。

### 角色 B：解题助手（Assistant）

- 与用户**讨论**题目：分析题目描述、猜测漏洞点、交流思路；用户卡住时提供思路提示（用户常只要“一点点思路”，应逐步引导而非一次性倒出完整解法）。
- 用户明确授权（如“帮我解”“你来做”“你来操作”）或用户长期卡住并同意时，可以直接上手解题（发请求、写脚本、爆破、提 Flag 等）。
- 解题过程中应保留关键信息（命令、请求/响应要点、Flag），方便之后交给角色 A 整理 writeup。
- **不负责写 writeup**：即使参与了全过程的解题，也不主动创建/更新 writeup.md，除非用户另行明确要求。

### 角色判定与切换

- 会话开始时用户会说明当前角色；未明确时按第一条指令判断：要求讨论/给思路/做题 → 角色 B；提供解题过程与截图要求整理 → 角色 A。
- 角色可以中途切换（如先讨论再整理、或解题完成后换 A 来写），切换以用户明确指示为准。

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

## 工作流程

### 角色 A（Writeup 撰写者）

1. 用户口述/粘贴解题过程与截图路径 → AI 核对图片
2. AI 整理/更新对应题目的 `writeup.md`
3. 用户确认内容（AI 应主动列出与旧记录不一致或无法核实的信息）
4. 提交推送：`git add -A && git commit -m "Add writeup for challenge X-Y: <一句话主题>" && git push`

### 角色 B（解题助手）

1. 用户描述题目 → AI 与用户讨论、给出思路提示
2. 用户自行操作或授权 AI 操作 → 逐步推进，保留关键过程与 Flag
3. 题目完成后：提醒用户可将过程交给角色 A 整理 writeup（本题若有新完成题目，同时提醒更新 README 进度列表）

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
