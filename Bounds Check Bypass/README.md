# Bounds Check Bypass PoC
本项目通过 C 代码演示了经典的“边界检查绕过”（Bounds Check Bypass）侧信道攻击原理，即 Spectre 漏洞。攻击者可利用 CPU 的分支预测和缓存时序侧信道，越界读取受害者内存中的敏感数据。

## 说明
- 原项目地址--> [SpectrePoc](https://github.com/crozone/SpectrePoC)
- 演示如何通过分支预测误导 CPU，利用缓存命中时间推测 secret 字符串内容。
- 支持多种缓解措施（如 Intel LFENCE、Linux nospec 掩码），可通过编译宏启用。
- 可在 Windows（MSVC）和 Linux（gcc/clang）平台编译运行。

## 编译
项目只有一个源文件 `main.c`，使用附带的 Makefile 即可一键编译
```bash
make          # 生成可执行文件 poc
make clean    # 清理生成的文件
```
Makefile 默认使用 gcc，编译选项为 -std=c99 -O0（无优化，方便调试）。

## 运行
### 基本用法
直接执行即可,程序会读取固定在 secret 中的字符串 `The Magic Words are Squeamish Ossifrage.`，并逐字节打印推测结果。
```bash
make run
```
### 自定义缓存命中阈值
通过第一个命令行参数调整“缓存命中阈值”（默认 80,测量的访存时钟周期数）
```bash
./poc 100
```
阈值越大，越难判定为命中；阈值越小，越容易产生误判。

### 读取任意地址与长度
通过第二、三个参数可任意指定要读取的地址和长度（仅用于研究，切勿在生产环境使用！）：
```bash
./poc 80 0x7ffeefbff9c0 16
```
- 参数 2：要读取的绝对虚拟地址（以 0x 开头的十六进制字符串）。
- 参数 3：希望读取的字节数。

> 注意：地址需要落在当前进程可访问的范围内，否则会触发段错误。

## 输出示例
```TEXT
Using a cache hit threshold of 80.
Build:
RDTSCP  Yes
MFENCE  Yes
CLFLUSH Yes
INTEL_MITIGATION        No
LINUX_KERNEL_MITIGATION No
Reading 40 bytes:
Reading at malicious_x = 0x55b3e2ae6020... Success: 0x54='T' count=101
Reading at malicious_x = 0x55b3e2ae6021... Success: 0x68='h' count=99
Reading at malicious_x = 0x55b3e2ae6022... Success: 0x65='e' count=103
...
```

每行依次给出：
- 推测是否成功（Success / Unclear）
- 十六进制值与对应 ASCII 字符
- 命中次数（最好和次好）

## 安全声明
本程序仅用于教学与研究目的，帮助理解现代 CPU 的微架构侧信道风险。请确保：
在受控、隔离的实验环境中运行；
不用于任何未经授权的渗透测试或攻击行为；
阅读并遵守当地法律法规。
作者不对任何滥用此代码造成的后果负责。