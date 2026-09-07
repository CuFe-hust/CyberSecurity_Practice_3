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
└── 1-2/                    # 第 1 次作业第 2 题（即将添加）
    └── ...
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

## 进度 / Progress

- [x] 1-1 仿冒官方账号读私信（Unicode 归一化不一致 / 全角字符绕过）
