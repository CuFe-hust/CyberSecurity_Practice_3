# CyberSecurity Practice 3 — CTF Writeups

华中科技大学网络空间安全学院 **《网络空间安全综合实践3》** 课程题解仓库

CTF writeups for the course **"Cyberspace Security Comprehensive Practice 3"**,
School of Cyberspace Security, Huazhong University of Science and Technology (HUST).

---

## 简介 / Introduction

本仓库按课程作业编号整理个人 CTF 题解（writeup），涵盖 Web、Crypto、Misc、Reverse、Pwn 等方向的实战题目。每个题目文件夹包含完整的解题过程、环境信息、Flag 及关键截图。

This repository collects personal CTF writeups for the course assignments, covering Web, Crypto, Misc, Reverse, Pwn and other directions. Each challenge folder contains the full solving process, environment info, flag and key screenshots.

## 目录结构 / Structure

```
CyberSecurity_3/
├── README.md
├── 1-1/                    # 第 1 次作业第 1 题
│   ├── writeup.md          # 题解文档
│   └── screenshots/        # 解题过程截图
├── 1-2/                    # 第 1 次作业第 2 题
│   ├── writeup.md          # 题解文档
│   └── screenshots/        # 解题过程截图
├── 1-3/                    # 第 1 次作业第 3 题
│   ├── writeup.md          # 题解文档
│   └── screenshots/        # 解题过程截图
├── 1-4/                    # 第 1 次作业第 4 题
│   ├── writeup.md          # 题解文档
│   └── screenshots/        # 解题过程截图
├── 2-1/                    # 第 2 次作业第 1 题
│   ├── writeup.md          # 题解文档
│   └── screenshots/        # 解题过程截图
├── 2-2/                    # 第 2 次作业第 2 题
│   ├── writeup.md          # 题解文档
│   └── screenshots/        # 解题过程截图
├── 2-3/                    # 第 2 次作业第 3 题
│   ├── writeup.md          # 题解文档
│   └── screenshots/        # 解题过程截图
├── 2-4/                    # 第 2 次作业第 4 题
│   ├── writeup.md          # 题解文档
│   └── screenshots/        # 解题过程截图
└── 3-1/                    # 第 3 次作业第 1 题
    ├── writeup.md          # 题解文档
    └── screenshots/        # 解题过程截图
```

- 文件夹按 `作业编号-题目编号`（`1-1`、`1-2` …）展开，一个文件夹对应一道题的完整题解。
- Each folder follows the naming convention `assignment-challenge` (e.g. `1-1`), containing a complete writeup for one challenge.

## Writeup 模板 / Template

每份 writeup 包含以下章节 / Each writeup includes:

| 章节 Section | 内容 Content |
| --- | --- |
| 题目信息 Challenge Info | 题目名称、分类、题目描述 |
| 环境信息 Environment | 平台地址、注册方式、账号信息 |
| 解题过程 Exploitation | 步骤化记录，附截图 |
| Flag | 最终获得的 Flag |
| 总结与心得 Takeaways | 漏洞原理、修复建议、做题方法 |

## 说明 / Notes

- 题解仅供学习交流，请勿用于任何未授权测试。
- 若题目环境基于公开靶机（如 DVWA、在线 CTF 平台），均为课程授权范围。
- Writeups are for learning purposes only. Do not use them for unauthorized testing.

## 本地配置 / Local Configuration

仓库中**不保存任何平台地址与账号凭据**。调用课程教学问答平台所需的连接信息放在本地未跟踪目录 `.local/`（已在 `.gitignore` 中忽略）：

| 文件 | 用途 |
| --- | --- |
| `.local/qa-platform.env` | 连接配置：`PLATFORM_BASE`（平台根地址，不含末尾斜杠）、`PLATFORM_USER`、`PLATFORM_PASS` |
| `.local/qa-platform.md` | 凭据备注，人类阅读（含踩坑记录） |
| `.local/qa-cookies.txt` | 登录后的会话 cookie，由 `curl -c` 自动写入，24 小时过期 |

首次使用：创建 `.local/` 并填入实际信息。

```bash
mkdir -p .local
cat > .local/qa-platform.env <<'EOF'
PLATFORM_BASE='http://<平台地址>'
PLATFORM_USER='<账号>'
PLATFORM_PASS='<口令>'
EOF
```

脚本载入方式：`set -a; . .local/qa-platform.env; set +a`。接口说明与调用示例见 `AGENTS.md` 的「教学问答平台（Qwen2.5）调用方法」一节。

Connection details and credentials for the course Q&A platform live only in the untracked `.local/` directory and are never committed. See `AGENTS.md` for the API usage.

## 进度 / Progress

- [x] 1-1 仿冒官方账号读私信（Unicode 归一化不一致 / 全角字符绕过）
- [x] 1-2 客服中心工单系统（存储型 XSS / 窃取内部工单密钥）
- [x] 1-3 开放平台 OAuth 2.0（无确认页静默授权 / scope 越权窃取官方账号私密资料）
- [x] 1-4 举报中心·社交平台（同源 JSONP callback 注入绕过 CSP / 窃取审核后台内部凭据）
- [x] 2-1 权限提升维持-G1（sudo NOPASSWD 放行 find / GTFOBins 提权读 /flag）
- [x] 2-2 权限提升维持-G2（SUID svcstat 相对路径调用 ps / PATH 劫持提权读 /flag）
- [x] 2-3 权限提升维持-G3（root cron 在可写目录执行 tar 通配符 / 选项注入提权读 /flag）
- [x] 2-4 权限提升维持-G4（root 常驻脚本检查与使用分离 / 符号链接 TOCTOU 竞态 + rename 原子替换提权读 /flag）
- [x] 3-1 免杀 payload 制作-G1（PHP eval + 关键词黑名单 / 字符串拆分、chr 编码与动态调用绕过读 flag）
