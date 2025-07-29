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
Using a cache hit threshold of 150.
Build:
RDTSCP  Yes
MFENCE  Yes
CLFLUSH Yes
INTEL_MITIGATION        No
LINUX_KERNEL_MITIGATION No
Reading 40 bytes:
Reading at malicious_x = 0xffffffffffffdfe8... Unclear: 0x4D='M' count=305      (second best: 0xE5='?' count=304)
Reading at malicious_x = 0xffffffffffffdfe9... Unclear: 0x84='?' count=875      (second best: 0xDA='?' count=872)
Reading at malicious_x = 0xffffffffffffdfea... Unclear: 0x16='?' count=883      (second best: 0x28='(' count=882)
Reading at malicious_x = 0xffffffffffffdfeb... Unclear: 0x9B='?' count=864      (second best: 0xE0='?' count=858)
Reading at malicious_x = 0xffffffffffffdfec... Unclear: 0xF6='?' count=870      (second best: 0xC0='?' count=865)
Reading at malicious_x = 0xffffffffffffdfed... Unclear: 0x3A=':' count=861      (second best: 0xE1='?' count=860)
Reading at malicious_x = 0xffffffffffffdfee... Unclear: 0x17='?' count=864      (second best: 0x45='E' count=858)
Reading at malicious_x = 0xffffffffffffdfef... Unclear: 0x31='1' count=856      (second best: 0x35='5' count=855)
Reading at malicious_x = 0xffffffffffffdff0... Unclear: 0x38='8' count=862      (second best: 0x28='(' count=858)
Reading at malicious_x = 0xffffffffffffdff1... Unclear: 0xEC='?' count=862      (second best: 0x34='4' count=862)
Reading at malicious_x = 0xffffffffffffdff2... Unclear: 0xD5='?' count=884      (second best: 0xE5='?' count=881)
Reading at malicious_x = 0xffffffffffffdff3... Unclear: 0xFF='?' count=933      (second best: 0x1C='?' count=932)
Reading at malicious_x = 0xffffffffffffdff4... Unclear: 0x7F='?' count=962      (second best: 0xDD='?' count=960)
Reading at malicious_x = 0xffffffffffffdff5... Unclear: 0xEE='?' count=960      (second best: 0xBB='?' count=957)
Reading at malicious_x = 0xffffffffffffdff6... Unclear: 0xA6='?' count=944      (second best: 0x62='b' count=944)
Reading at malicious_x = 0xffffffffffffdff7... Unclear: 0xE2='?' count=966      (second best: 0xDE='?' count=963)
Reading at malicious_x = 0xffffffffffffdff8... Unclear: 0xEF='?' count=967      (second best: 0x27=''' count=966)
Reading at malicious_x = 0xffffffffffffdff9... Unclear: 0xC7='?' count=938      (second best: 0xE9='?' count=936)
Reading at malicious_x = 0xffffffffffffdffa... Unclear: 0x96='?' count=928      (second best: 0x44='D' count=924)
Reading at malicious_x = 0xffffffffffffdffb... Unclear: 0xDD='?' count=952      (second best: 0x87='?' count=951)
Reading at malicious_x = 0xffffffffffffdffc... Unclear: 0x61='a' count=894      (second best: 0xFC='?' count=893)
Reading at malicious_x = 0xffffffffffffdffd... Unclear: 0xE6='?' count=885      (second best: 0xF7='?' count=882)
Reading at malicious_x = 0xffffffffffffdffe... Unclear: 0x61='a' count=911      (second best: 0xB6='?' count=910)
Reading at malicious_x = 0xffffffffffffdfff... Unclear: 0xC8='?' count=872      (second best: 0x35='5' count=871)
Reading at malicious_x = 0xffffffffffffe000... Unclear: 0x48='H' count=876      (second best: 0xC8='?' count=875)
Reading at malicious_x = 0xffffffffffffe001... Unclear: 0xE6='?' count=890      (second best: 0x1C='?' count=887)
Reading at malicious_x = 0xffffffffffffe002... Unclear: 0xA8='?' count=892      (second best: 0x61='a' count=882)
Reading at malicious_x = 0xffffffffffffe003... Unclear: 0x4D='M' count=879      (second best: 0x28='(' count=876)
Reading at malicious_x = 0xffffffffffffe004... Unclear: 0x21='!' count=860      (second best: 0xB0='?' count=856)
Reading at malicious_x = 0xffffffffffffe005... Unclear: 0xF7='?' count=876      (second best: 0x67='g' count=863)
Reading at malicious_x = 0xffffffffffffe006... Unclear: 0xE0='?' count=868      (second best: 0x30='0' count=867)
Reading at malicious_x = 0xffffffffffffe007... Unclear: 0x9C='?' count=870      (second best: 0x9D='?' count=862)
Reading at malicious_x = 0xffffffffffffe008... Unclear: 0x5C='\' count=864      (second best: 0x67='g' count=858)
Reading at malicious_x = 0xffffffffffffe009... Unclear: 0xB4='?' count=861      (second best: 0x9E='?' count=861)
Reading at malicious_x = 0xffffffffffffe00a... Unclear: 0xEC='?' count=863      (second best: 0x16='?' count=858)
Reading at malicious_x = 0xffffffffffffe00b... Unclear: 0xAC='?' count=880      (second best: 0x96='?' count=876)
Reading at malicious_x = 0xffffffffffffe00c... Unclear: 0xE5='?' count=969      (second best: 0x86='?' count=968)
Reading at malicious_x = 0xffffffffffffe00d... Unclear: 0x42='B' count=976      (second best: 0x26='&' count=968)
Reading at malicious_x = 0xffffffffffffe00e... Unclear: 0xEF='?' count=962      (second best: 0x27=''' count=959)
Reading at malicious_x = 0xffffffffffffe00f... Unclear: 0xE8='?' count=926      (second best: 0xBE='?' count=926)
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