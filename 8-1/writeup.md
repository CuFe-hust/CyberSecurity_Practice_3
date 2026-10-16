# 8-1 系统层漏洞利用与逆向分析 · 软件逆向静态分析-G1（静态链接 stripped ELF：`strings` 线索 → 定位校验点 → 42 字节 `^0xAA` 还原）

## 题目信息

| 项目 | 内容 |
| --- | --- |
| 题目名称 | 系统层漏洞利用与逆向分析-软件逆向静态分析-G1（sectionID `6655`，课程内 number 30，题目内部编号 `C036-G1`） |
| 分类 | 逆向分析 / 静态分析（Linux ELF64、**静态链接且 stripped**；单字节 XOR 编码还原；**无靶机实例**） |
| 题目描述 | 题面只给一句提示加一个附件：「有时候，顺着字符串的线索摸过去，真相就藏在最简单的运算里。flag 格式为 `flag{}`。」本题**没有靶机实例**（`experimentID=0`），flag 完全来自对附件 `challenge.elf` 的静态分析；本机 Docker 只用于**动态佐证**。 |

Flag 题（questionID 9443，`questionType=4` 代码/Flag 题）题干原文：

> 有时候，顺着字符串的线索摸过去，真相就藏在最简单的运算里。flag 格式为 `flag{}`。
>
> `{{input}}`

题面附件行（作答页实测，见截图 05）：`challenge.elf`，**690.02K**。

Note：本批 `C036` 系列的两道逆向题都不给靶机 —— **8-1** 是 ELF64 静态链接的 **XOR** 校验器，**8-2** 是 PE32+ 的 **RC4** 校验器；两题的 Flag 题同为 `questionType=4`，提交格式都要实测。本题的分析链条可以概括成一条线：

```text
strings -t x（文件偏移 0x7f00e / 0x7f021 / 0x7f028）
  → 解析程序头换算虚拟地址（VA 0x47f010 / 0x47f021 / 0x47f028）
  → 全量反汇编（124377 行）后 grep 这三个 VA：全二进制只有 4 处引用，全部落在 0x40191e–0x4019bb
  → 读循环语义：strlen(input) == 0x2a 且 ∀i: input[i] ^ 0xAA == target[i]
  → 取 .rodata VA 0x481140 的 42 字节，逐字节 ^0xAA ⇒ flag
```

## 环境信息

| 项目 | 内容 |
| --- | --- |
| 平台 | VMCourse 国产化教学实训平台（自签名证书，`curl` 需 `-k --noproxy '*'`），课程 ID `1639`，本章节 `sectionID` `6655`（课程内 number 30，title「系统层漏洞利用与逆向分析-软件逆向静态分析-G1」）。平台账号与口令只保存在本地未跟踪的 `.local/` 目录（不入库），本文不记录任何凭据、cookie 或个人身份信息 |
| 题型 | 3 道单选（9407 / 9409 / 9411，`questionType=2`）+ 1 道多选（9413，`questionType=3`）+ 1 道 **type-4 代码/Flag 题**（9443，`questionType=4`），共 5 题，`answersTotal=5`、每题 2 分；题目分组 `10011 / 10013 / 10015 / 10017 / 10019` 依次对应 `C036-G1-S1 / S2 / S3 / M / F` |
| 判分机会 | 题面接口返回 `isResubmit=false`、`endOrNot=true` ⇒ 本次为**首次判分**；5 题 `answerTimes` 均为 1，一次通过 |
| 靶机实例 | **无**。章节 `experimentID=0`，`/api/student/lab/vm?ID=6655` 不返回任何实验环境；不涉及 envID / podID / 端口映射 / SSH。flag 不来自靶机，也**没有 token、没有兑换服务** |
| flag 来源 | 附件 `challenge.elf` 的静态分析（真值）＋ 本机 Docker `linux/amd64` 实跑校验器（动态佐证） |
| 附件 | `.local/process/8-1-scripts/files/challenge.elf`，**706576 B**，MD5 **`572dd2e111a8e5d84545a2bc1e0acbf6`**，SHA256 `22d4cf3e85eb86e35999e9cc35366bbc72e7a5825430e003a73f830820e37a5c`（与题面 `questionFiles[0].size = 706576` 一致，附件在解题全程未被修改） |
| 附件属性 | `ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, BuildID[sha1]=a1509016f336d92b616c2a1407b878e1f672b5b5, for GNU/Linux 3.2.0, stripped`；`e_type=0x2`（**ET_EXEC，非 PIE**）；共 4 个 `LOAD` 段，`.rodata` 落在 `off 0x7f000 → vaddr 0x47f000` 这一段（`flags=4`，只读） |
| 本机工具 | **本机 Docker 可用**（Docker Desktop 29.4.3；`docker run --platform linux/amd64 alpine:3.19` 实测可跑 `x86_64`）；反汇编用 Apple LLVM `objdump` 21.0.0（`-d --no-show-raw-insn -M intel`），字符串用 BSD `strings`，Python 3.14（标准库 + Pillow + numpy）；截图用 playwright-core 驱动系统 Chrome（无头）。本机**没有** `readelf` / Ghidra / radare2 / pwntools / capstone / pyelftools ⇒ 程序头、节表与 `.rela.plt` 全部用 Python 自行解析 |
| 选择题判分 | **9407=B、9409=C、9411=A、9413=A、B、D（num=3）**：提交前已独立判定并落盘 `.local/process/8-1-answers-rationale.md`，与 Lead 独立判定逐项一致；`GET /api/student/get/answerHistory?sectionID=6655&contestMode=0` 返回 **5/5 `isCorrect=true`**（含 9443）。按惯例本文不展开选择题解析 |

## 解题过程

### 1. 附件核对与题面：本题没有靶机实例

先核对附件、确认题目形态（无实例可打）：

```console
$ md5 files/challenge.elf
572dd2e111a8e5d84545a2bc1e0acbf6
$ shasum -a 256 files/challenge.elf
22d4cf3e85eb86e35999e9cc35366bbc72e7a5825430e003a73f830820e37a5c  files/challenge.elf
$ file files/challenge.elf
files/challenge.elf: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked,
  BuildID[sha1]=a1509016f336d92b616c2a1407b878e1f672b5b5, for GNU/Linux 3.2.0, stripped
$ strings -t x files/challenge.elf | grep -Ei "Enter the flag|Correct!|Wrong!"
   7f00e @@Enter the flag: 
   7f021 Wrong!
   7f028 Correct!
```

三个字符串说明这就是一个「提示 → 读入 → 判定」的 flag 校验器；题面又说「顺着字符串的线索」，于是整条路径自然变成 **字符串 → 引用它的代码 → 校验逻辑 → 解出明文**。

章节 `experimentID=0`、`/api/student/lab/vm?ID=6655` 无实验环境，所以**没有任何实例可连**，全部结论都必须落到这个二进制里。换句话说：本题的难点不在"打进去"，而在"读出来"——flag 的每一个字节都由这个 ELF 自己决定。

### 2. 分析路径与关键证据

#### 2.1 一句话结论

`main()`（在静态链接二进制里是 `0x401905`）只做三件事：打印 `Enter the flag: ` → `fgets` 读一行并去掉行尾换行 → **长度必须等于 42**，且逐字节满足 `(input[i] ^ 0xAA) == target[i]`。`target[]` 是 `.rodata` 里 VA `0x481140` 处的 **42 字节硬编码数组**；把它逐字节 `^0xAA` 就是 flag。

#### 2.2 证据链①：`strings -t x` 拿到的是**文件偏移**，不是虚拟地址（截图 01）

```console
$ strings -t x files/challenge.elf | grep -Ei "Enter the flag|Correct!|Wrong!"
   7f00e @@Enter the flag: 
   7f021 Wrong!
   7f028 Correct!
```

`7f00e` 是 `@@Enter the flag: ` 这一整串的起始偏移，`Enter the flag: ` 本体从 `0x7f010` 开始。实测该处字节为 `@@Enter the flag: \0Wrong!\0Correct!\0`，三个字符串紧挨着放在 `.rodata` 开头，也正因如此才可能"一条线索牵出整个校验器"。

这里踩到的第一个坑：本机是 **BSD `strings`**（来自 CommandLineTools），`-tx` 会直接报错，必须写成 `-t x`：

```console
$ strings -tx files/challenge.elf
error: /Library/Developer/CommandLineTools/usr/bin/strings: unknown flag: -tx
Usage: .../strings [-] [-a] [-o] [-t format] [-number] [-n number] [-arch <arch_flag>] ... [--] [file ...]
```

#### 2.3 证据链②：用程序头把文件偏移换算成虚拟地址（截图 01）

本机没有 `readelf`，用 Python 解析 ELF 程序头（`logs/01-disasm.txt` 为同批命令产物）；换算公式与实测值：

```text
PH 2  type 0x1(LOAD)  off 0x7f000  vaddr 0x47f000  filesz 0x258a5  flags 4(R)   <- .rodata 所在段
VA = p_vaddr + (file_off - p_offset)
VA("Enter the flag: ") = 0x47f000 + (0x7f010 - 0x7f000) = 0x47f010
VA("Wrong!")           = 0x47f021
VA("Correct!")         = 0x47f028
```

（`flags=4` 即只读段，与"这是只读数据/字符串"的直觉一致；非 PIE 的 `ET_EXEC` 让 VA 是编译期常量，换算关系唯一。）

#### 2.4 证据链③：全量反汇编后 grep 三个 VA，定位唯一校验点（截图 01）

```console
$ objdump -d --no-show-raw-insn -M intel files/challenge.elf > logs/01-disasm.txt   # 124377 行
$ grep -n -E "47f010|47f021|47f028" logs/01-disasm.txt
618:  40191e:      	lea	rsi, [rip + 0x7d6eb]    # 0x47f010
646:  401995:      	lea	rdi, [rip + 0x7d68c]    # 0x47f028
650:  4019a8:      	lea	rdi, [rip + 0x7d672]    # 0x47f021
654:  4019bb:      	lea	rdi, [rip + 0x7d65f]    # 0x47f021
```

**全二进制只有这 4 处引用**，且全部落在 `0x40191e–0x4019bb` 这一小段里（`0x4019a8` / `0x4019bb` 两处分别是长度分支与字节不等分支的 `"Wrong!"`）⇒ 这一段就是 flag 校验器。再补一步确认函数入口：`__libc_start_main` 的调用点在 `0x4017f8`，上一行 `mov rdi, 0x401905` 把首参传进去，所以 `0x401905` 就是 `main`：

```asm
  4017f8:      	mov	rdi, 0x401905
  4017ff:      	addr32  call	0x403e70          ; __libc_start_main(main, ...)
```

![静态分析链条：`strings -t x` 拿文件偏移 → 程序头换算 VA `0x47f010 / 0x47f021 / 0x47f028` → `objdump` 全量反汇编后 `grep` 三个 VA，4 处引用全部落在 `0x401905–0x4019ee`；真实命令回显的渲染稿（非终端实拍）](screenshots/01-strings-xref-va-xref.png)

#### 2.5 证据链④：循环语义 = `strlen == 0x2a` 且 `input[i] ^ 0xAA == target[i]`（截图 02）

`main@0x401905` 的完整反汇编（`objdump -d --no-show-raw-insn -M intel`，Intel 语法；注解为人工添加）：

```asm
401905 <main>:                                        ; __libc_start_main 在 0x4017f8 用 mov rdi,0x401905 传入
 401905: endbr64
 401909: push   rbx
 40190a: sub    rsp,0x50
 40190e: mov    rax,QWORD PTR fs:0x28
 401917: mov    QWORD PTR [rsp+0x48],rax          ; 栈保护 canary
 40191c: xor    eax,eax
 40191e: lea    rsi,[rip+0x7d6eb]        # 0x47f010   ; "Enter the flag: "
 401925: mov    edi,0x2
 40192a: call   0x41bb60                            ; 打印提示（stdout）
 40192f: mov    rdi,rsp
 401932: mov    rdx,QWORD PTR [rip+0xa8d9f] # 0x4aa6d8 ; stdin
 401939: mov    esi,0x40
 40193e: call   0x404e40                            ; fgets(buf, 64, stdin)
 401943: test   rax,rax
 401946: je     0x4019e2                            ; fgets 返回 NULL(EOF) -> return 1
 40194c: mov    rbx,rsp
 40194f: lea    rsi,[rip+0x7e89a]        # 0x4801f0   ; reject = "\n"（实测该处字节 0a 00）
 401956: mov    rdi,rbx
 401959: call   0x401140                            ; strcspn(buf,"\n")   ← glibc IFUNC/PLT 桩
 40195e: mov    BYTE PTR [rsp+rax],0x0              ; 去掉行尾换行
 401962: mov    rdi,rbx
 401965: call   0x401160                            ; strlen(buf)         ← glibc IFUNC/PLT 桩
 40196a: mov    rdx,rax                             ; rdx = 输入长度
 40196d: mov    eax,0x0
 401972: lea    rcx,[rip+0x7f7c7]        # 0x481140   ; ★ 硬编码目标字节数组（.rodata）
 401979: cmp    rdx,0x2a                            ; ★ 长度必须 = 0x2a = 42
 40197d: jne    0x4019a8                            ;   长度不对 -> "Wrong!"
 40197f: movzx  edx,BYTE PTR [rsp+rax]              ; ┐ 取输入第 i 字节
 401983: xor    edx,0xffffffaa                      ; │ ★ 低字节 ^= 0xAA（反汇编写作 xor edx,-0x56）
 401986: cmp    dl,BYTE PTR [rcx+rax]               ; │ ★ 与 target[i] 比较（只比低字节 dl）
 401989: jne    0x4019bb                            ; ┘ 不等 -> "Wrong!"
 40198b: add    rax,0x1
 40198f: cmp    rax,0x2a
 401993: jne    0x40197f                            ; 循环 42 次
 401995: lea    rdi,[rip+0x7d68c]        # 0x47f028   ; "Correct!"
 40199c: call   0x4051d0
 4019a1: mov    eax,0x0                             ; return 0
 4019a6: jmp    0x4019cc
 4019a8: lea    rdi,[rip+0x7d672]        # 0x47f021   ; "Wrong!"（长度分支）
 4019af: call   0x4051d0
 4019b4: mov    eax,0x1
 4019b9: jmp    0x4019cc
 4019bb: lea    rdi,[rip+0x7d65f]        # 0x47f021   ; "Wrong!"（字节不等分支）
 4019c2: call   0x4051d0
 4019c7: mov    eax,0x1
 4019cc: mov    rdx,QWORD PTR [rsp+0x48]            ; canary 校验
 4019d1: sub    rdx,QWORD PTR fs:0x28
 4019da: jne    0x4019e9                            ; 栈被写坏 -> __stack_chk_fail
 4019dc: add    rsp,0x50
 4019e0: pop    rbx
 4019e1: ret
 4019e2: mov    eax,0x1                             ; EOF 出口
 4019e7: jmp    0x4019cc
 4019e9: call   0x41bc30                            ; __stack_chk_fail
 4019ee: nop
```

两个实现细节值得记下来，它们是"程序被 strip 了、却依然能读"的关键：

- `0x401140` / `0x401160` 是 glibc 的 **IFUNC/PLT 桩**（每条 16 字节：`endbr64` + `jmp qword ptr [rip+…]`）。实测该二进制 `.rela.plt` 共 **22 条重定位、类型全是 37 = `R_X86_64_IRELATIVE`**；按字节核对 GOT 槽：`0x401144` 跳 `0x4aa090`（表中 addend `0x4127e0`）、`0x401164` 跳 `0x4aa0a0`（addend `0x412800`），两者都是返回具体实现地址的解析器。函数名随符号表一起被 strip 掉了，因此这两个桩是**按调用约定辨认**的：一次是 `rdi=buf, rsi=0x4801f0`（实测该处字节 `0a 00`，即 `"\n"`）且返回值立刻被当作下标写 0（去掉行尾换行），另一次只传 `rdi=buf` 且返回值直接被当成输入长度 —— 即 `strcspn(buf,"\n")` 与 `strlen(buf)`。**静态链接 + strip 并没有抹掉字符串函数的语义**。
- `xor edx,0xffffffaa` 与 `cmp dl,[rcx+rax]` 的组合：`xor` 不改变高字节，所以对 `edx` 异或 `0xffffffaa` 等价于**只对低字节异或 `0xAA`**；比较也只看低字节 `dl`，因为 `target[]` 是字节数组。语义即 `input[i] ^ 0xAA == target[i]`，反解 `input[i] = target[i] ^ 0xAA`。

![校验器 `main@0x401905` 的反汇编与逐条中文注解（`cmp rdx,0x2a` 长度判断、`xor edx,0xffffffaa` 的 0xAA key、`target` 数组 VA `0x481140`）；图内三条关键指令已用红色高亮标注（`401979 cmp rdx,0x2a` / `401983 xor edx,0xffffffaa` / `401986 cmp dl,BYTE PTR [rcx+rax]`），整图指令清单完整到 `4019e9`；真实命令回显的渲染稿（非终端实拍）](screenshots/02-checker-disasm-xor-0xAA.png)

#### 2.6 证据链⑤：`.rodata` VA `0x481140` 的 42 字节 `^0xAA` = flag（截图 03）

目标数组与 `.rodata` 同段，所以文件偏移同样是"VA 减段基址再加段偏移"（脚本 `.local/process/8-1-scripts/extract_target.py`，输出 `logs/09-extract-target.out`）：

```console
$ python3 extract_target.py
target VA      : 0x481140
target hex     : ccc6cbcdd19dcf99cb93cc98c987c8929e9b879ece9c9d87cb9acf9f879bcc9cc992c899939ace989ed7
key            : 0xaa
flag           : flag{7e3a9f2c-b841-4d67-a0e5-1f6c8b390d24}
flag len       : 42 (expect 0x2a = 42)
bytes after 42 : 0000000000000000 (全 0 ⇒ 数组边界自证)
```

换算过程：`file_off = 0x481140 - 0x47f000 + 0x7f000 = 0x81140`（`va2off(va) = va - 0x47f000 + 0x7f000`）。

两条独立的"边界自证"：

1. **数组正好 42 字节**：`xxd -s 0x81130 -l 0x48` 显示数组前 16 字节全是 `0x00` 填充、数组后紧跟 8 个 `0x00`，即这是一个"被 0 包住的独立块"，与 `cmp rdx,0x2a` 里的长度常量互为印证；
2. **长度本身自洽**：`42 = 5("flag{") + 36(UUID) + 1("}")`，且 42 字节的紧凑数组放在 `.rodata` 里完全合理。

![目标数组还原：VA `0x481140` → 文件偏移 `0x81140` → 42 字节 hex，逐字节 `^0xAA` 得到 flag，并用 `xxd` 给出"数组前后都是 0x00 填充"的边界自证与长度自证；真实命令回显的渲染稿（非终端实拍）](screenshots/03-python-xor-decode-flag.png)

### 3. 本机 Docker 动态佐证：正例 / 反例 / 补丁双向差分（截图 04）

macOS 跑不了 ELF，但**本机 Docker 的 `linux/amd64` 可以**（原始输出 `.local/process/8-1-scripts/logs/02-docker-verify.{sh,out}`）：把附件挂进 `alpine:3.19` 容器实跑，一共 7 组用例。注意挂载进来的附件权限是 `644`（无 `x` 位），所以容器内先 `cp /w/challenge.elf /tmp/orig.elf && chmod +x`，**不改仓库内附件的权限与内容**。

| # | 输入 | 结果（回显 / 退出码） | 说明了什么 |
| --- | --- | --- | --- |
| 0 | `/dev/null`（立即 EOF） | `Enter the flag: ` 后 **exit 1** | 命中 `test rax,rax; je 0x4019e2` ⇒ `fgets` 返回 NULL 时直接返回 1 |
| 1 | 静态还原出的候选 flag（42 B + `\n`） | **`Correct!`** / exit 0 | 正向确认：静态分析的结论成立 |
| 2 | 候选末位 `4`→`5`（**同为 42 字节**） | `Wrong!` / exit 1 | 排除"只要长度对就过"，逐字节比较确实生效 |
| 3 | 候选截断到 **41** 字节 | `Wrong!` / exit 1 | 命中长度分支 `cmp rdx,0x2a` |
| 4 | 候选填充到 **43** 字节 | `Wrong!` / exit 1 | 同上（长度必须严格相等） |
| 5 | **补丁**：把 `xor` 的立即数 `0xAA` 改成 `0x00`（文件偏移 `0x1985`，`83 f2 aa` → `83 f2 00`），喂候选 flag | `Wrong!` / exit 1 | key 一变候选就不通过 ⇒ **key 确实是 `0xAA`** |
| 6 | 同补丁，喂**静态提取的 42 字节原始数组** | **`Correct!`** / exit 0 | ⇒ **target 数组逐字节还原无误** |

```console
$ xxd -s 0x1980 -l 8 /tmp/orig.elf        # 0x1985 正好是 xor 的立即数字节
00001980: b614 0483 f2aa 3a14             #         ^^ = 0xaa
$ xxd -s 0x1980 -l 8 /tmp/patched.elf
00001980: b614 0483 f200 3a14             # 补丁后 = 0x00
```

第 5、6 条合起来构成**双向差分**，这是本题最有力的一步：`候选 flag ↔ key=0xAA` 一致、`原始数组 ↔ key=0x00` 一致，两侧同时自洽才可能同时成立 ⇒ 密钥与目标数组**两个未知量都被独立坐实**，而不只是"猜出了一个能过的字符串"。

（另有一条原始日志里的补充观察：候选 flag **不带换行符**喂进去同样是 `Correct!`——因为 `strcspn(buf,"\n")` 没找到换行时不会截断，长度不受影响；这条说明程序只依赖 `fgets` + 去换行的常规行为，没有额外陷阱。上表第 0–6 组就是截图 04 所示的那 7 组，这条额外用例在原始日志里编号为第 7 组。）

另外用重定向把 stdout / stderr 分开验证过：`2>/dev/null` 时 `Enter the flag: Correct!` 照常出现，`1>/dev/null` 时什么都没有 ⇒ 提示与判定**全部走 stdout**（`logs/03-fd-split.out`），与反汇编里连续两次 `call 0x4051d0`（`puts`）一致。

![本机 Docker（`--platform linux/amd64`、`alpine:3.19`）动态佐证：EOF、候选 flag → `Correct!`、末位改字 / 长度 41 / 长度 43 → `Wrong!`、把 key 补丁成 `0x00` 后的双向差分；真实命令回显的渲染稿（非终端实拍）](screenshots/04-docker-amd64-dynamic-verify.png)

### 4. 提交答案与平台判分：5/5 全对（截图 05）

四道选择题在提交前就已独立判定并落盘（`.local/process/8-1-answers-rationale.md`），与 Lead 的独立判定逐项一致（9407=B、9409=C、9411=A、9413=A、B、D），随后**一次性提交 5 题**。难点在 flag 题的格式：本题 flag 题是 **`questionType=4`（代码/Flag 题）**，题面是 `{{input}}` 输入框，需要实测内层 JSON：

```console
$ python3 submit.py all '{"answer":["flag{7e3a9f2c-b841-4d67-a0e5-1f6c8b390d24}"],"num":1}'
### POST /api/student/submitAnswers
    sectionID = 6655
    answers = {"questionID":9407,"answer":"{\"answer\":[\"B\"],\"num\":1}"}
    answers = {"questionID":9409,"answer":"{\"answer\":[\"C\"],\"num\":1}"}
    answers = {"questionID":9411,"answer":"{\"answer\":[\"A\"],\"num\":1}"}
    answers = {"questionID":9413,"answer":"{\"answer\":[\"A\",\"B\",\"D\"],\"num\":3}"}
    answers = {"questionID":9443,"answer":"{\"answer\":[\"flag{7e3a9f2c-b841-4d67-a0e5-1f6c8b390d24}\"],\"num\":1}"}
    contestMode = 0
### HTTP 200
{"code":0,"msg":"success", ...}      # 5 条记录 answerTimes=1，id 5350985/87/89/91/93
```

- **格式尝试 #1 一次成功**：type-4 用 `{"answer":["flag{...}"],"num":1}`（外层再包 `{"questionID":9443,"answer":"<内层 JSON 字符串>"}`）⇒ HTTP 200、`code=0`、`msg=success`，**没有换过格式、没有重试**（如实记录，避免后续误以为试过其它写法）。
- 顶层 `isCorrect:false`、各条 `scoreRate:0` 是平台的已知现象（不作为判分依据）。
- 判分唯一依据 `GET /api/student/get/answerHistory?sectionID=6655&contestMode=0`：

| order | questionID | 题面标题 | 题型 | 提交值 | isCorrect |
| --- | --- | --- | --- | --- | --- |
| 1 | 9407 | `C036-G1-S1` | 单选 | `{"answer":["B"],"num":1}` | **true** |
| 2 | 9409 | `C036-G1-S2` | 单选 | `{"answer":["C"],"num":1}` | **true** |
| 3 | 9411 | `C036-G1-S3` | 单选 | `{"answer":["A"],"num":1}` | **true** |
| 4 | 9413 | `C036-G1-M` | 多选 | `{"answer":["A","B","D"],"num":3}` | **true** |
| 5 | 9443 | `C036-G1-F` | **type-4 代码/Flag** | `{"answer":["flag{7e3a9f2c-b841-4d67-a0e5-1f6c8b390d24}"],"num":1}` | **true** |

**5/5 全部 `isCorrect=true`。** 平台作答页 5 题均显示「作答正确」，第 5 题可见附件 `challenge.elf 690.02K`，输入框内为最终 flag（截图 05）。`answerHistory` 的 5 条记录与 `submitAnswers` 原始返回原文见 `.local/process/8-1-scripts/logs/06-answerHistory-after-fmt1.json` 与 `logs/05-submit-fmt1.json`（其中 `currentUser` 含账号/昵称/学号/IP，**已在本记录与本文中剔除**）。

![VMC 作答页真实页面截图：5 题全部「作答正确」（第 1–3 题正确项高亮、第 4 题 A/B/D 勾选、第 5 题 flag 输入框内为最终 flag），第 5 题可见附件 `challenge.elf 690.02K`；顶栏账号已涂白并标注「账号已脱敏」](screenshots/05-vmc-answerpage-5题作答正确.png)

### 5. 教学问答：5 问 5 答，覆盖原理 / 机制 / 加固 / 检测（截图 06）

围绕本题向课程教学问答平台（Qwen2.5）提了 **5 个问题**，覆盖方法原理 / 机制细节（2 问）/ 加固修复 / 检测与应急五个维度；每题各起一段会话（`conversation_id` 依次 **5649 / 5650 / 5652 / 5654 / 5656**），相邻提问间隔 ≥12 s，**5 问全部首次尝试成功**（无排队、无重试）。问答原文另存 `.local/process/8-1-qa-transcript.json`，运行日志 `logs/07-qa-run.out`。

| # | 会话 id | 覆盖维度 | 问题要点 | 回答要点 | 口径说明（与实测/标准不符处） |
| --- | --- | --- | --- | --- | --- |
| Q1 | 5649 | 方法 / 原理 | 无符号的静态链接 stripped ELF，如何从 `strings` 提示串定位校验函数？为什么字符串的虚拟地址能直接反查引用 | 提取字符串 → 用段表确定所在段与 VA → 反汇编后按 VA 找 `lea`/引用；核心是"字符串的 VA 就是代码里 `lea reg,[rip+disp]` 的目标" | ⚠️ 其第 3 步写「这通常是通过 `strings` 命令输出的字符串前缀的虚拟地址来确定的」——**`strings -t x` 打印的是文件偏移，不是 VA**（本题必须经程序头换算，见 2.3；同一模型的 Q3 也讲了这一步换算）。原始记录只标注了 Q2 的口径问题，**这条是本次逐字核对问答原文时补充指出** |
| Q2 | 5650 | 机制细节 | `movzx edx,[rsp+rax] ; xor edx,0xffffffaa ; cmp dl,[rcx+rax] ; jne` 为什么 `xor edx,-0x56` 等价于低字节 `^0xAA`？为什么只比 `dl` | 补码 `0xffffffaa = -0x56`；`xor` 不改变高字节，故等价于对低字节异或；比较只用 `dl` 是因为目标是字节数组 | ❌ 把补码解释写成「`0xffffffaa` 可以看作是 `256 - 0x56`」，严格说应是 **`2^32 - 0x56`**（`0xffffffaa` 是 32 位补码形式）；结论（低字节 `^0xAA`）正确，措辞不严谨（原始记录 §6 已标注）。另外"比较只用 `dl` 是为了**减少寄存器使用**"的说法牵强，真正原因是字节数组比较只需低字节 |
| Q3 | 5652 | 机制细节 | 非 PIE 静态链接 ELF 里，`strings -t x` 的文件偏移如何用程序头换算成 VA（举例 `p_offset=0x7f000`、`p_vaddr=0x47f000`） | 先用 `readelf -l` 找到覆盖该偏移的 LOAD 段，再套 `VA = p_vaddr + (off - p_offset)` | ⚠️ 推导行文有一处写歪（写成了"虚拟地址 = 虚拟地址偏移 + 文件偏移 − 文件偏移"），但最终给出的公式与示例结论正确；本机无 `readelf` 是用 Python 解析程序头完成的，公式一致 |
| Q4 | 5654 | 加固 / 修复 | 「读一行 → 逐字节 XOR 固定常量 → 与硬编码数组比较」为什么不算安全保护？正确做法该怎么选（对称加密 / MAC / 非对称签名） | 可逆、无密钥管理、无完整性校验；应按场景用对称加密保密、MAC 保证完整性/真实性、签名保证不可否认 | ⚠️ 结论与本题一致，但只到原则层面（"硬编码数组一旦泄露就无法挽救"这类白盒视角没展开），可作清单用 |
| Q5 | 5656 | 检测与应急 | 蓝队如何在磁盘上识别「硬编码密文数组 + 单字节 XOR 解码」样本？YARA / 熵分析 / 二进制相似性 / 沙箱各有什么误报来源 | 四类手段与各自误报来源（编码变体、合法压缩/随机数据、结构相似、环境依赖行为）都覆盖到了 | ⚠️ 只到名词层面，未给可落地的检测点（例如本题这种"42 字节高熵块 + 前后全 `0x00` 填充"的 `.rodata` 特征、或直接扫描 `xor` 立即数/循环常量） |

**口径说明**：以上偏差**均不作为解题依据**——本题的校验语义、目标数组、key 全部以 `objdump` 反汇编、Python 提取与 Docker 实跑为准；教学模型只用来梳理思路（Q1/Q3 讲方法、Q2 讲机制、Q4/Q5 列加固与排查清单）。

问答页截图用**会话指纹**核对：在历史面板里按 `data-id="5650"` 定位条目并点击打开（截图时历史面板已收起），再读主区域 `#log` 文本与 `.local/process/8-1-qa-transcript.json` 中 `conversation_id=5650` 的记录比对——**问句（`movzx edx, byte ptr [rsp+rax]`）与回答开头（`这段汇编代码涉及 x86-64 架构的汇编语言`）逐字一致**，页面文本另存 `logs/10-qa-page-log-fingerprint.txt` 备查。

![教学问答平台真实页面截图：主区域为本题第 2 问（`conversation_id=5650`）的原文与回答（含 `xor edx, 0xffffffaa`、`cmp dl, byte ptr [rcx+rax]`），该会话经 `data-id` 定位并以 `#log` 文本指纹核对一致；右上角账号胶囊已涂白并标注「账号已脱敏」，「帮助 / 退出」按钮完好](screenshots/06-AI问答-xor-key-0xAA.png)

### 6. 失败尝试与踩坑清单

| # | 尝试 | 现象 | 原因 | 如何调整 |
| --- | --- | --- | --- | --- |
| 1 | `strings -tx files/challenge.elf` | 报 `unknown flag: -tx` | 本机是 BSD `strings`（GNU binutils 才支持 `-tx` 连写） | 改用 `strings -t x`（顺带成为 9407 的实证） |
| 2 | 容器内直接执行 `./challenge.elf` | `Permission denied`（exit 126） | 挂载进容器的附件权限是 `644`，没有 `x` 位 | 容器内 `cp /w/challenge.elf /tmp/orig.elf && chmod +x`，**不改仓库内附件**（MD5 仍为 `572dd2e1…`） |
| 3 | 第一次跑 `qa.py` 采集问答 | 10 分钟无输出、transcript 未生成 | ① 问答平台 cookie jar 是 Netscape 格式，`session` 行以 `#HttpOnly_` 开头，被 `line.startswith('#')` 当注释跳过 ⇒ `sess=None` ⇒ 每次都抛 `TypeError` 并被重试逻辑吞掉；② stdout 重定向到文件后是块缓冲，进度看不到 | ① 解析时放行 `#HttpOnly_` 前缀行；② 改 `python3 -u` 并逐问 flush（修复后 5 问全部一次成功） |
| 4 | 无头浏览器访问 VMC 作答页 | 被踢回 `/login` | 只注入 `SESSIONID` cookie 不够，SPA 有自己的登录态存储 | 改为**表单真实登录**（填用户名/口令 + 点「登录」）再跳转作答页 |
| 5 | 问答页用 `page.evaluate(el => el.click())` 点历史项 | 点了历史项但主区域不变（文本长度恒为 842） | `#hist-list > *` 外层 div 不是可点元素，真实点击目标是内部 `.hist-open` 按钮的命中区域 | 改用 `page.mouse.click()` 点在条目几何中心，并按 `data-id` 精确定位目标会话（`5650`）后再做指纹校验 |
| 6 | （观察项，非失败）同一问题在会话列表里出现两条相邻 id（如 `5648/5650`） | 无法凭"最新一条"判断哪条是本题的 | 平台在同一次 POST 上会先后落两个会话 id（`/api/chat/history` 返回的第一个 `conversation_id` 与最终 id 不同），且该账号是**多 Agent 共用**（同页可见 7-4 / 8-2 的提问） | 只采信**指纹逐字匹配**的那条（本题取 `5650`，页面 `#log` 与 `-qa-transcript.json` 前 40 字逐字一致） |

### 7. 截图真实性与脱敏说明

`8-1/screenshots/` 共 **6 张 PNG，目录内没有其它文件**（渲染源 HTML 在 `.local/process/8-1-scripts/render/`，脚本与原始日志在 `.local/process/8-1-scripts/`，均不入库）。按取证方式分两类，**图注与正文均如实区分**：

| 文件 | 内容 | 真实性 | 脱敏 |
| --- | --- | --- | --- |
| `01-strings-xref-va-xref.png` | `strings -t x` → 程序头换算 VA → `grep` 三处 xref 的完整链条 | **真实命令回显的渲染稿**（非终端实拍；图内顶部黄条自带标注） | 无个人信息 |
| `02-checker-disasm-xor-0xAA.png` | `main@0x401905` 校验器反汇编 + 中文注解（长度 `0x2a`、`xor 0xffffffaa`、`target@0x481140`）；三条关键指令红色高亮，指令清单完整到 `4019e9` | 同上（渲染稿；视口高 ≥ 内容高后整屏截取，成品 2560×3014 device px） | 无 |
| `03-python-xor-decode-flag.png` | 目标数组路径/hex、`^0xAA` 还原 flag、`xxd` 边界自证 | 同上 | 无 |
| `04-docker-amd64-dynamic-verify.png` | 容器内 7 组动态验证（正例 / 反例 / 长度 / 补丁双向差分） | 同上（由 `logs/02-docker-verify.out` 的真实回显整理，仅去掉 `set -x` 的 `+ ` 跟踪行） | 无（flag 为题解内容） |
| `05-vmc-answerpage-5题作答正确.png` | VMC 作答页 `/student/course/answer/6655`：5 题「作答正确」+ 附件行 + 已提交 flag | **真实页面截图**（无头 Chrome + playwright-core，viewport 1280×2300、`dSF=2`、`fullPage` ⇒ 2560×4600） | **已涂白**顶栏昵称，见下 |
| `06-AI问答-xor-key-0xAA.png` | 问答平台 `/chat`：本题第 2 问会话 5650 的原文与回答 | **真实页面截图**（viewport 1280×1400、`dSF=2`、`fullPage` ⇒ 2560×3116） | **已涂白**右上角账号胶囊，见下 |

**为什么终端/命令类是渲染稿**：本题**没有靶机实例**（只有附件），也没有可供实拍的网页服务；本机 Agent 进程又没有屏幕录制权限（`screencapture` 报 `could not create image from display`）。因此 `01`–`04` 把**真实命令与原始日志输出逐字复制**渲染成黑底白字 HTML 再截图，**每张图顶部都标注「真实命令回显的渲染稿（非终端实拍）」**，渲染脚本只做 `html.escape`，未手工改写字符。

**VMC 作答页（`05`）确实渲染了账号昵称，已涂白**（脚本 `.local/process/8-1-scripts/mask_vmc_header_8-1.py`，坐标**逐图按本次 viewport 实测、未照抄其它题**）：

- 截图条件：viewport `1280×2300`、`dSF=2`、`fullPage` ⇒ PNG **2560×4600 device px**；顶栏背景色实测 **`rgb(114,177,239)`**（采样点 `(2000,20)`）；
- 定位：对 `y∈[30,130)`、`x∈[2300,2560)` 的近白文字像素做列聚类，得到 4 簇 —— `(2300,2334)`=左侧图标、`(2362,2395)`=「文A」图标、`(2440,2469)` 与 `(2475,2506)`=**昵称两个字** ⇒ 昵称本体 `x 2440..2506, y 69..100`；
- **处理矩形 `(2432,58)-(2518,112)`**：填顶栏背景色 + 写白字「账号已脱敏」；ink 判据为 `|R-114|+|G-177|+|B-239| > 60`，涂白前 **1263** → 涂白后 **477**（残留的 477 就是标签文字本身；本次复核 `--check` 复测仍为 477）；
- 复验：裁剪 `(2280,30)-(2560,140)` 目视确认昵称已被覆盖、左侧「文A」图标与右侧页面内容完好；另裁第 5 题区域确认「作答正确」与已提交 flag 清晰可读。

**问答页（`06`）确实有账号胶囊（含学号），已涂白**（脚本 `.local/process/8-1-scripts/mask_qa_account_8-1.py`）：

- 截图条件：viewport `1280×1400`、`dSF=2`、`fullPage` ⇒ PNG **2560×3116 device px**；顶栏背景色实测 **`rgb(255,252,247)`**；
- 定位：对 `y∈[0,190)`、`x∈[1450,2350)` 的深色文字像素做列聚类，得到「昵称」（两簇）与「（学号）」四段 ⇒ 账号胶囊 `x 1822..2135, y 59..91`（**含学号，必须脱敏**）；右侧 `(2184,2319)`、`(2344,2349)` 是「帮助 / 退出」按钮，**不覆盖**；
- **处理矩形 `(1806,32)-(2152,116)`**：填背景色 + 写深色字「账号已脱敏」；`sum(RGB) < 420` 记为 dark，涂白前 **3624** → 涂白后 **1400**（残留即标签文字；本次复核 `--check` 复测仍为 1400）；
- 复验：裁剪 `(1700,10)-(2450,140)` 目视确认胶囊被覆盖、「帮助 / 退出」按钮完好。

两处脱敏都可追溯、可回退：脚本支持 `--check`（只统计 ink、不落盘）与 `--apply`，回退方式是用同一 viewport 参数重新截图（`/tmp/shot/vmc8-1c.mjs`、`/tmp/shot/qa-shot8-1c.mjs`）。本文正文不记录任何凭据、cookie 或个人身份信息。

**`02` 的高亮与对照**：该渲染稿把 `401979 cmp rdx,0x2a`（长度必须 = 42）、`401983 xor edx,0xffffffaa`（低字节 `^0xAA`）与 `401986 cmp dl,BYTE PTR [rcx+rax]`（与 `target[i]` 比较）三条关键指令用 `#ff5f56` 红色高亮，整图指令清单完整到 `4019e9`，可与本文 2.5 节的代码块及 `logs/01-disasm.txt` 逐条对照。

### 8. 靶机遗留物与清理

| 位置 | 内容 | 说明 |
| --- | --- | --- |
| 靶机 | **不存在** | 本题 `experimentID=0`，无 podID、无端口映射、无容器内 `/flag`，无需清理 |
| 本机 Docker 容器 | 容器内只在 `/tmp` 写了 `orig.elf` / `patched.elf`（补丁只改本地副本） | 用 `--rm` 运行，随容器销毁；仓库内附件权限与内容**未被修改**（MD5 仍为 `572dd2e111a8e5d84545a2bc1e0acbf6`） |
| 本机仓库 | `8-1/screenshots/`（6 张 PNG）；`.local/process/8-1-scripts/`（`extract_target.py`、`gen_render.py`、`qa.py`、`submit.py`、`mask_vmc_header_8-1.py`、`mask_qa_account_8-1.py`、`files/challenge.elf`、`paper.json`、`render/` 渲染源、`logs/` 原始输出）；`.local/process/8-1-{ctf-process.md,qa-transcript.json,answers-rationale.md}` | `.local/` 全部不入库；未执行任何 git 操作、未改 `README.md`、未改动截图与原始记录 |

## Flag

```text
flag{7e3a9f2c-b841-4d67-a0e5-1f6c8b390d24}
```

该 flag 由静态分析还原（`strings -t x` → 程序头换算 VA `0x47f010` → 反汇编定位 `main@0x401905` → 读出 `strlen==0x2a` 且 `input[i]^0xAA==target[i]` → 取 `.rodata` VA `0x481140` 的 42 字节逐字节 `^0xAA`），并有三路独立核验一致：

1. **本机 Docker 正向跑通**：`alpine:3.19` + `--platform linux/amd64` 直跑附件校验器，该值输出 `Correct!`（exit 0）；末位改成 `…5`、截断到 41 字节、填充到 43 字节均输出 `Wrong!`；
2. **补丁双向差分**：把 `xor` 立即数改成 `0x00` 后，候选 flag 变 `Wrong!` 而静态提取的原始数组变 `Correct!` ⇒ key 与目标数组都被独立坐实；
3. **Lead 独立复核**（未参考解题结论）：用 `docker run --rm -i --platform linux/amd64 … alpine:3.19 /w/challenge.elf` 实跑，本 flag → `Correct!`，`…25` 变体与 `flag{wrong}` → `Wrong!`（记录见 `.local/process/7-4-8-1-8-2-lead-verification.md`）。

该值与平台作答页第 5 题输入框内的值、`answerHistory` 第 5 条（questionID 9443）判为正确的提交值三者逐字一致。

## 总结与心得

### 原理：单字节 XOR 不是"加密"，只是"可逆的表示变换"

1. **本题的全部安全强度都在同一个字节上**：`target[i] = flag[i] ^ 0xAA`。异或对称、可逆，且 key 只有 1 字节 —— 拿到 `target[]` 就等于拿到明文；即使暂时读不出比较逻辑，把 42 字节密文对 256 种单字节 key 全枚举一遍也必然命中（这也是 8-1 与 8-2 的分水岭：8-2 换成了 RC4 + 8 字节 key，暴力枚举不再可行）。
2. **"最简单的运算"恰恰是最容易被反汇编器完整暴露的运算**：`xor edx,0xffffffaa` + `cmp dl,[rcx+rax]` 一条循环就把算法、key、目标数组地址三者同时交代清楚。**没有任何混淆（没有内联、没有多态、没有白盒、没有防调试）** ⇒ 静态分析即可通关，这也是题面"顺着字符串的线索摸过去"的字面意思。
3. **`strings` 给的是文件偏移，不是虚拟地址** —— 这是本题最容易走偏的一步，也是"非 PIE + 静态链接 + 段偏移映射"这组知识点的落点：`VA = p_vaddr + (off - p_offset)`。只有完成这一步，才能在反汇编里用 VA 把"字符串"和"引用它的 `lea`"接起来。
4. **`strlen == 0x2a` 这类"魔法数字"是很好的交叉验证点**：42 既等于 `.rodata` 里那个孤立字节块的长度，也等于 `flag{`(5) + UUID(36) + `}`(1) —— 两条完全独立的线索指向同一个数，说明理解没有跑偏。

### 做题方法

- **先找"提示串"，再让提示串带你走**：`strings -t x` 的三个字符串（`Enter the flag: ` / `Wrong!` / `Correct!`）就是全局路标。**只要一个字符串的地址被引用，就能反推出使用它的函数**，不需要符号表、不需要函数识别插件。本题 124377 行反汇编里只需 `grep` 三个地址就收敛到了唯一校验点。
- **把"定位函数"和"读懂语义"分成两步做**：先靠 xref 把范围压到 `0x401905–0x4019ee`（纯机械操作、无需理解），再逐条读指令推语义（需要知识）。两步分开，出错时容易定位是哪一步错了。
- **工具缺失时用最小代价补齐**：本机没有 `readelf`，就用 Python 解析 ELF 头/程序头（30 行以内）；无法在 macOS 跑 ELF，就用**本机 Docker `--platform linux/amd64`** 跑。**关键是别让"工具不可用"卡住结论，但也别把手工解析当成权威**——两者都要能相互印证。
- **给结论设计"能被推翻的对照实验"**：本题最有价值的不是"跑出了 `Correct!`"，而是那组对照 —— 末位改字（证明确实逐字节比较）、长度 41/43（证明长度严格相等）、以及**把 key 补丁成 `0x00` 后的双向差分**（同时坐实 key 与目标数组）。**只做正例验证的结论是脆弱的**：万一你"猜"的字符串恰好能让一个错误理解下的程序通过，只有反例才能把它戳破。
- **平台提交格式要靠实测**：本题 flag 题是 `questionType=4`，与 7-4 的 `questionType=1` 填空不同；`{"answer":["flag{...}"],"num":1}` 一次通过（HTTP 200 / `code=0`），而判分只看 `answerHistory[].isCorrect`。**格式没有文档时，先用一次提交换确定答案，再复核判分接口。**
- **对教学模型的回答保持复核**：本题 5 问里 Q1 把"`strings` 前缀"当成了虚拟地址（实际是文件偏移），Q2 的补码解释写成 `256 - 0x56`（应为 `2^32 - 0x56`）且"减少寄存器使用"的理由牵强，Q5 只到手段名词层面。**教学问答适合梳理思路、列排查清单，结论必须回到反汇编、提取脚本与容器实跑上验证。**

### 修复与加固建议

- **代码级：不要把"可逆变换 + 硬编码比较"当成保护**。若要保护 flag/许可，至少要满足三条中的一条：① 校验方**持有服务端密钥**（客户端只提交凭据，比对在服务端做）；② 用 **MAC/HMAC** 保护完整性，离线也要能验证"确实由授权方签出"；③ 用**非对称签名**让公钥可分发、私钥不可提取。单字节 XOR（乃至任意"编译进程序的对称 key"）都做不到，因为**密钥与算法一起交付给了攻击者**，只是抬高了一点点阅读成本。
- **提高逆向成本要用"工程化"手段而不是"小聪明"**：真要做白盒/防篡改，方向是密钥分散存储 + 运行时派生、代码加密与自校验、反调试与完整性检查的组合，并接受"客户端可被攻破"这一前提（把价值判断放在服务端）。**单纯的 XOR/加减/Base64 轮换不构成保护**。
- **检测与应急排查（蓝队视角）**：
  - **静态特征**：`.rodata` 里出现"长度紧凑、熵偏高、前后被 `0x00` 填充包围"的字节块（本题即 `.rodata` VA `0x481140` 的 42 字节 + 前后零填充）；反汇编中出现"单字节 `movzx` → 与固定立即数 `xor` → `cmp`/`jne` 循环"的固定模式；`xor` 立即数集中出现（可用 YARA 规则匹配 `83 F2 ??` / `34 ??` / `80 3? ??` 类指令模式，配合文件类型与节区条件降低误报）。
  - **动态特征**：程序"读入一行 → 立即输出 `Correct!/Wrong!`"、无网络/文件副作用；用 `strace`/沙箱可看到只调用 `read`/`write` 而无敏感行为（得分仍需人工确认，因为这类样本本身可能只是 CTF 题或 license 校验）。
  - **误报来源**：合法的编解码/压缩/随机数数据同样熵高；编译器与库版本差异会改变指令选择（同一逻辑的 `xor` 可能被优化成 `sub`/查表）；不同样本结构相似度高并不能说明同源。
  - **排查要点**：对疑似样本先做**熵 + 节区 + 引用链**三角定位（本题的做法就是"字符串 → 引用 → 比较循环"）；提取疑似数组后先做 256 种单字节 key 枚举看是否出现可打印串（成本极低）；保留样本哈希与提取脚本，便于回溯与横向比对。

原始过程记录：`.local/process/8-1-ctf-process.md`（含"分析路径与关键证据"专节与 6 条失败尝试）；教学问答原文：`.local/process/8-1-qa-transcript.json`；选择题判定预登记：`.local/process/8-1-answers-rationale.md`；Lead 独立复核（含用 Docker 实跑校验器复现本 flag）：`.local/process/7-4-8-1-8-2-lead-verification.md`；脚本与全部证据日志：`.local/process/8-1-scripts/`（`extract_target.py`：目标数组提取与还原；`gen_render.py` + `render/`：渲染稿源；`qa.py`：问答 SSE 采集；`submit.py`：提交与判分；`mask_vmc_header_8-1.py` / `mask_qa_account_8-1.py`：两处脱敏；`files/challenge.elf`；`logs/01-disasm.txt` 等原始输出）。
