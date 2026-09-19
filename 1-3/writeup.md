# 1-3 开放平台 · OAuth 2.0（授权码窃取官方私密资料）

## 题目信息

| 项目 | 内容 |
| --- | --- |
| 题目名称 | 开放平台 · OAuth 2.0（社交平台系列） |
| 分类 | Web / OAuth 2.0 授权码流程滥用（静默授权 CSRF + 权限范围提升） |
| 题目描述 | 某社交平台的「开放平台」上线了应用接入能力，开发者可以创建 OAuth 应用，让用户用社区账号一键登录。平台鼓励开发者把应用体验链接私信给官方账号 @official，官方会登录试用并反馈。官方账号持有一份普通用户看不到的私密资料。请注册开发者账号，设法获取官方账号的私密资料。本题需要一定的 OAuth 2.0 基础知识。 |

## 环境信息

| 项目 | 内容 |
| --- | --- |
| 靶机地址 | http://172.17.0.13:12031/ |
| 服务端 | gunicorn（Flask），仅 HTTP |
| 注册方式 | `POST /register`（字段 username / password），注册后自动登录并跳转 `/dev` |
| 演示账号 | 开发者 `devtroy01` / `Passw0rd!23`（本次解题时注册，环境重建后失效） |
| 教学问答平台 | 课程教学问答平台（Qwen2.5），用于 OAuth 2.0 基础概念答疑；入口地址与账号保存在本地 `.local/` 配置中（不入库） |

### 关键端点

| 端点 | 方法 | 说明 |
| --- | --- | --- |
| `/register`、`/login` | POST | 注册/登录，下发 Flask 签名 session cookie（`{"user":"<name>"}`） |
| `/dev` | GET | 开发者中心：创建应用、显示 client_id / client_secret / redirect_uri、已收到的授权码 |
| `/dev/create` | POST | 创建应用（字段 name），成功后 302 → `/dev` |
| `/oauth/authorize` | GET | 授权端点。参数 `client_id`、`redirect_uri`（须与注册值精确相等）、`response_type`、`state`、`scope`。未登录时 302 → `/login`；**已登录时不做任何确认，直接签发 code 并 302 → redirect_uri** |
| `/oauth/cb/<client_id>` | GET | 平台内置的回调页（即应用的 redirect_uri）。显示「授权完成 / 已自动授权」；带 `code` 访问时会把该授权码记录进开发者的 `/dev` 面板 |
| `/oauth/token` | POST | 授权码换令牌。参数 `grant_type=authorization_code`、`client_id`、`client_secret`、`code`、`redirect_uri`，返回 `{"access_token","scope","token_type":"Bearer"}` |
| `/api/me` | GET | 资源接口，需 `Authorization: Bearer <token>`。返回 `{"username","official","scope"}`；**官方账号 + scope=private 时额外返回 `private_note`（flag）** |
| `/dm` | GET/POST | 给 @official 发私信（字段 body）。官方 bot 会打开私信中的链接 |

## 解题过程

### 1. 观察首页动态，确认题目入口

首页「开放平台」动态中，官方账号 @official 公告「开放平台」上线，开发者可在开放平台创建应用；开放平台账号 @open 进一步提示：应用做好后可以把**体验链接私信给官方账号 @official**，官方会尽快登录试用并反馈。据此确认攻击路径：构造授权链接 → 私信诱导官方账号访问。

![首页-开放平台动态](screenshots/01-首页-开放平台动态.png)

### 2. 注册开发者账号

打开注册页注册开发者账号 `devtroy01`（`POST /register`，字段 username / password），注册成功后自动登录并跳转开发者中心 `/dev`。

![注册开发者账号](screenshots/02-注册开发者账号.png)

### 3. 创建应用，拿到 client_id / client_secret / redirect_uri

在开发者中心创建应用 DemoApp（`POST /dev/create`，字段 name），成功后 302 → `/dev`。页面显示本次解题用到的应用凭证：

- client_id：`app_6e58dbd6dfa0`
- client_secret：`0c49c81edd09a8bdb23f5cc8068d3de4`
- redirect_uri：`/oauth/cb/app_6e58dbd6dfa0`

![开发者中心-应用凭证](screenshots/03-开发者中心-应用凭证.png)

### 4. 自测授权码流程，观察回调行为

先用浏览器自测一遍标准授权码流程：访问 `/oauth/authorize?...` → 302 携带 `code` 跳转到 `/oauth/cb/app_6e58dbd6dfa0` → 回调页把授权码记录进开发者中心（截图 03 中「已收到的授权码」第一条 `JB6A2DFK2B2WgWdIvxuDkQ` 即自测所得）。

回调页显示「授权完成 / 应用「DemoApp」已获得授权 / **已自动授权** / 正在返回应用…」，而且**以访客身份（未登录）直接访问该页也会展示同样的内容**（截图 09 左下角为「访客 未登录」），说明回调页本身没有登录要求，也没有向用户呈现任何权限确认信息。

![授权完成回调页-已自动授权](screenshots/09-授权完成回调页-已自动授权.png)

> 自测同时确认：授权端点对已登录用户**没有确认页**，访问即签发授权码——这正是后续攻击成立的前提。

自测和交叉验证阶段还产生了另外几条授权码，完整列表见截图 10，来源都可以对应上：`vRXovuiyRXDV75IinG4nIg` 来自 devtroy01 的第二次自测授权；`wk_QSQ5v7wdwzVXlF37Mog` 由第二个测试账号 `user2test` 走同一条授权链路所得，其令牌调用 `/api/me` 返回 `{"official":false,"scope":"basic","username":"user2test"}`，证明授权码会被记入应用所有者的面板；`ZxDG2gpICFkipFTY2kgWsw` 由第三个测试账号 `user4test` 所得，同样用于验证「无论哪个用户完成回调，授权码都会出现在应用开发者中心」，其 `/api/me` 返回 `{"official":false,"scope":"basic","username":"user4test"}`。即截图 10 的 6 条授权码 = 2 条 devtroy01 自测 + 2 条测试账号交叉验证 + 2 条官方授权。

### 5. 失败/排除尝试一：redirect_uri 篡改全部被拒（400）

尝试对 `redirect_uri` 做各类篡改，想把它引到别处截获授权码：

- 路径穿越：`/oauth/cb/app_6e58dbd6dfa0/../dm`、`/oauth/cb/app_6e58dbd6dfa0/../../dm`、`%2f..%2f`
- 附加参数/片段：加 `?x=1`、加 `#x`
- 绝对 URL：`http://172.17.0.13:12031/...`
- 外部域：`http://evil.example/...`、`//evil.example/...`
- 前缀/后缀变形：`/oauth/cb/app_6e58dbd6dfa0evil`

结果**全部返回 `400 invalid client_id or redirect_uri`**。说明本题授权端点的 `redirect_uri` 做了**精确匹配**（这是平台做对了的地方），无法从回调地址下手。

### 6. 失败/排除尝试二：其它 grant type、令牌传递方式均无效

- `grant_type=client_credentials`、`grant_type=password`、`grant_type=refresh_token`、缺 `grant_type` → 全部返回 `invalid_grant`；用 GET 请求 `/oauth/token` → **405**。
- 用 `/api/me?access_token=...`、不带 token、错误 token 访问 → 均返回 `401 {"error":"invalid_token"}`；资源接口只接受 `Authorization: Bearer` 请求头。

### 7. 失败/排除尝试三：Flask session 弱密钥爆破失败

session cookie 是形如 `{"user":"devtroy01"}` 的 Flask 签名 cookie。尝试用 flask-unsign 爆破 `SECRET_KEY`：先试 31 个常见弱口令，再跑 1 万条常见口令字典，均未命中，未发现弱密钥，放弃该路径。

### 8. 排除尝试：授权码一次性、回调页无 code、其它端点

- 同一个授权码第二次换令牌返回 `invalid_grant`，错误 `client_secret` 同样返回 `invalid_grant`——授权码**一次性使用**且绑定 client_secret（这两点平台做对了）。
- 用测试账号 `user3test` 验证：`/oauth/cb/<client_id>` 不带 `code` 访问时只显示「授权完成 / 已自动授权」，不会签发新授权码——排除「直接让官方访问回调页」的思路。
- `/api/secret`、`/api/official`、`/api/flag`、`/admin` 等端点均返回 404，仅 `/api/me` 有效。

### 9. 构造应用体验链接，私信发给 @official

按标准授权码流程构造授权链接，作为「应用体验链接」发给官方：

```
http://172.17.0.13:12031/oauth/authorize?client_id=app_6e58dbd6dfa0&response_type=code&redirect_uri=/oauth/cb/app_6e58dbd6dfa0&state=sc1&scope=private
```

![构造应用体验链接](screenshots/04-构造应用体验链接.png)

用 `/dm` 私信 @official：第一条以「试用 DemoApp」的口吻附带授权链接（未指定 scope，state=`st8f3k2`，截图 05）；随后又补发一条，把链接单独成行（state=`st8f3k2b`，截图 06）。

![私信官方-发送授权链接](screenshots/05-私信官方-发送授权链接.png)

![私信官方-补充链接](screenshots/06-私信官方-补充链接.png)

### 10. 官方首次授权：只拿到 basic 权限，看不到私密资料

22:12 官方首次授权（访问第一条私信中的链接，未指定 scope），开发者中心收到授权码 `Vkpb891o7t2RX-l3-VAH_w`。用它换到的令牌只带 **basic** 权限，调用 `/api/me` 返回：

```json
{"official":true,"scope":"basic","username":"official"}
```

响应中没有 `private_note`——默认 scope 只有 basic，**要拿私密资料必须申请到更高权限范围**。

![官方令牌-仅basic权限看不到私密资料](screenshots/08-官方令牌-仅basic权限看不到私密资料.png)

### 11. 补发多 scope 授权链接，官方以 scope=private 授权

22:13 第三次私信官方，一次性给出 5 个不同 scope 的授权入口（scope 分别为 `private`、`profile`、`official`、`all`、`private%20profile%20official%20all`，state 对应 `sc1`~`sc5`）：

![私信官方-多权限scope链接](screenshots/07-私信官方-多权限scope链接.png)

22:14:04 官方访问了第一个入口（**scope=private**），开发者中心收到授权码 `dSP6wvr8OCUKJL136lEm2A`（截图 10 中最后一条）。

![开发者中心-收到官方授权码](screenshots/10-开发者中心-收到官方授权码.png)

### 12. 用 client_secret 在后端把授权码换成 access_token

```
curl -sS -i -X POST http://172.17.0.13:12031/oauth/token \
  -d "grant_type=authorization_code&client_id=app_6e58dbd6dfa0 \
     &client_secret=0c49c81edd09a8bdb23f5cc8068d3de4 \
     &code=dSP6wvr8OCUKJL136lEm2A&redirect_uri=/oauth/cb/app_6e58dbd6dfa0"
```

响应：

```json
{"access_token":"serGRKKkDqtl-yEXKyleT6UoQOdXjOND","scope":"private","token_type":"Bearer"}
```

另外做了一次对照验证：换令牌时传入与注册值不一致的 `redirect_uri`，仍然成功换到令牌：

```
curl -sS -X POST http://172.17.0.13:12031/oauth/token \
  -d "grant_type=authorization_code&client_id=app_6e58dbd6dfa0 \
     &client_secret=0c49c81edd09a8bdb23f5cc8068d3de4 \
     &code=SVNjvfVxjtr1skl3r46dPw&redirect_uri=/oauth/cb/other"
# => 200 {"access_token":"l5H6hW9F3ImJig3f70t2epr-H8UooCqO","scope":"basic","token_type":"Bearer"}
```

说明 `/oauth/token` **不校验 `redirect_uri` 是否与注册值一致**——授权端点做对的精确匹配没有延伸到换令牌环节（该授权码已一次性作废，此处仅作证据引用）。

### 13. 读取官方账号私密资料，拿到 Flag

```
curl -sS -H "Authorization: Bearer serGRKKkDqtl-yEXKyleT6UoQOdXjOND" http://172.17.0.13:12031/api/me
```

响应：

```json
{"official":true,"private_note":"官方账号内部凭据：vmc{iW1NFyW1BAIXZJUZ74PoIWfNCcPBXOTp}","scope":"private","username":"official"}
```

![API-me-官方私密资料](screenshots/11-API-me-官方私密资料.png)

### 14. 解题过程中的 AI 助教问答（截图 12–16）

解题过程中围绕 OAuth 2.0 协议细节向课程教学问答平台（Qwen2.5）提了 5 个基础问题，用于确认攻击思路与协议预期行为：

**问题 1：授权码模式的基本流程，为什么授权码要在后端换取访问令牌**（截图 12）——确认标准流程：授权码经浏览器传递、令牌必须由客户端后端用授权码 + 密钥换取。这对应了本题中开发者用 client_secret 在服务端换令牌的步骤。

![AI问答-授权码模式流程](screenshots/12-AI问答-授权码模式流程.png)

**问题 2：`state` 参数的作用与缺失风险**（截图 13）——确认 `state` 是防 CSRF 的不可预测随机值、回调时需校验一致性；请求不带 `state` 时无法判断授权响应是否由自己发起。

![AI问答-state参数作用](screenshots/13-AI问答-state参数作用.png)

**问题 3：`redirect_uri` 应如何校验、宽松校验会导致什么攻击**（截图 14）——确认应做精确匹配，前缀匹配/任意路径会导致授权码被重定向劫持；对照本题实测，平台的精确匹配是协议实现中做对的部分。

![AI问答-redirect_uri校验](screenshots/14-AI问答-redirect_uri校验.png)

**问题 4：授权服务器不展示用户确认页、直接下发授权码的风险**（截图 15）——确认「一访问授权链接就下发授权码」会导致用户不知情、授权码可被攻击者构造的链接套取；这正是本题官方账号被静默授权的根因。

![AI问答-无同意页风险](screenshots/15-AI问答-无同意页风险.png)

**问题 5：拿到 access_token 后能读哪些数据、权限范围由什么决定**（截图 16）——确认可读数据由令牌的权限范围（scope）决定，为申请 `scope=private` 提供了依据。

![AI问答-访问令牌的权限范围](screenshots/16-AI问答-访问令牌的权限范围.png)

### 时间线（北京时间）

- 21:49 注册 devtroy01；创建 DemoApp，拿到 client_id / client_secret / redirect_uri
- 21:50 自测授权码流程：authorize → 302 带 code → 回调页 → 开发者中心出现授权码
- 21:51 第一次私信官方（授权链接，未指定 scope）
- 22:06 第二次私信官方（链接单独成行）
- 22:12 官方首次授权，授权码 `Vkpb891o7t2RX-l3-VAH_w`（scope=basic）→ `/api/me` 只有 basic 资料
- 22:13 第三次私信官方（5 个不同 scope 的授权链接）
- 22:14:04 官方授权 scope=private，授权码 `dSP6wvr8OCUKJL136lEm2A`
- 22:15 换令牌 → `/api/me` 拿到 `private_note` = flag

## Flag

```
vmc{iW1NFyW1BAIXZJUZ74PoIWfNCcPBXOTp}
```

## 总结与心得

### 漏洞原理链

1. **无确认页 + 不校验 state 的静默授权（核心）**：授权端点对已登录用户不做任何确认，访问即签发授权码，且不校验 `state`。任何已登录用户（包括官方 bot）只要打开攻击者构造的 `/oauth/authorize?...` 链接，攻击者就完成了一次「静默授权」，等价于标准 OAuth 2.0 的 CSRF 授权缺陷。
2. **scope 未做白名单校验导致权限提升**：应用可以任意声明 `scope=private` 等敏感范围，平台照单全收并原样写进令牌，低权限应用因此越权取得官方账号的私密资料——这是最后拿到 flag 的关键一步。
3. **授权码投递面过宽**：回调页 `/oauth/cb/<client_id>` 是平台内置、路径可预测的页面，且会把授权码写入开发者中心列表——任何能诱导用户点击授权链接的攻击者，都能在自己的面板里捡到受害者的授权码。
4. **授权感知被弱化**：回调页无需登录即可访问、直接展示「已自动授权」，用户既看不到应用申请了哪些权限，也没有点击同意或拒绝的机会。

### 做题方法与关键点

- 本题把「官方会试用私信里的链接」和「开放平台 OAuth」组合在一起，本质是让攻击者用自己的应用授权链接去钓官方账号的授权码。关键洞察是**授权服务端没有确认页**：官方打开链接的那一刻，攻击就已经完成，剩下的只是把授权码换令牌。
- 先自测跑通标准授权码流程，确认回调页会把 code 记进开发者中心，再发私信。官方第一次授权时未指定 scope，只拿到 basic 权限，`/api/me` 没有 `private_note`；补发带 `scope=private` 的链接后才拿到 flag——**scope 是本题拿 flag 的关键参数**。
- 私信内容要像正常的开发者试用请求（介绍应用、给出体验链接、请求反馈），并利用平台「官方会打开私信链接」的设计完成投递；授权码的获取依赖官方的访问节奏（首次等待约 20 分钟），需要耐心。
- 失败尝试同样有信息量：redirect_uri 各类篡改全部 400、授权码一次性、错误 client_secret 无效、其它 grant type/传令牌方式均被拒，说明平台在协议细节上有部分正确实现，漏洞主要出在**确认页 / state / scope** 三处。

### 修复建议

- **授权端点展示用户可见的确认页**：列明请求方应用名与所申请的权限清单，由用户主动点击同意。
- **对 scope 做服务端白名单**：只允许应用注册时声明的范围，敏感 scope（如 `private`）应单独审批准入。
- **使用并校验 state**：授权请求与回调使用不可预测随机值，回调时比对一致性，防 CSRF。
- **redirect_uri 继续精确匹配**（本题已做到），并建议对公开客户端引入 **PKCE**（`code_verifier` / `code_challenge`），防止授权码被截获后滥用。
- **授权码保持短时效、一次性使用**（本题已做到），并绑定 client_id 与 redirect_uri；**换令牌时也应校验 redirect_uri**（本题未校验，实测证据见步骤 12）。
- 平台侧不建议用「私信链接 + 官方账号自动登录试用」的方式验证第三方应用，应以沙箱账号或人工审核替代。
