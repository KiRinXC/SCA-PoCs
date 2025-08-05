# Bounds Check Bypass PoC
本项目通过 C 代码演示了经典的“分支目标注入”（Branch Target Injection）侧信道攻击原理，即 Spectre-BTI 漏洞。攻击者利用 CPU 的间接分支预测与缓存时序侧信道，诱导受害者错误地执行攻击者控制的“gadget”代码片段，从而越权读取本应不可访问的内存敏感数据。

## 说明
- 项目地址
    - [spectrev2-poc](https://github.com/Anton-Cao/spectrev2-poc)        
- 演示如何通过间接分支预测误导 CPU，利用缓存命中时间推测 secret 字符串内容。

- 本项目对上述代码有重构。

## 依赖环境
- 支持 x86_64 指令集的处理器（建议 Intel 平台）
- Linux/win11系统
- GCC 支持内联汇编（推荐使用 gcc 编译器）

- 支持 rdtscp, clflush, mfence 指令的处理器

## 编译
```bash
make           # 编译指定源文件（默认main.c）
make clean     # 清理中间文件
```

## 运行
运行程序可选指定缓存命中阈值：

```bash
./poc          # 使用内置阈值运行
./poc 100       # 手动设定阈值（推荐80~420之间尝试）
```
## 运行效果
程序运行后会逐字节恢复被保护的 "秘密" 数据（"The Magic Words are Squeamish Ossifrage."）.

多次实验结果证明，无论是Intel还是兆芯处理器，均可成功恢复秘密数据。


```TEXT
Using a cache hit threshold of 420.
Reading 40 bytes:
Reading at malicious_x = 0x56f156208008... Success: 0x54='T' count=2
Reading at malicious_x = 0x56f156208009... Success: 0x68='h' count=2
Reading at malicious_x = 0x56f15620800a... Success: 0x65='e' count=2
Reading at malicious_x = 0x56f15620800b... Success: 0x20=' ' count=1
Reading at malicious_x = 0x56f15620800c... Success: 0x4D='M' count=2
Reading at malicious_x = 0x56f15620800d... Success: 0x61='a' count=2
Reading at malicious_x = 0x56f15620800e... Success: 0x67='g' count=2
Reading at malicious_x = 0x56f15620800f... Success: 0x69='i' count=2
Reading at malicious_x = 0x56f156208010... Success: 0x63='c' count=1
Reading at malicious_x = 0x56f156208011... Success: 0x20=' ' count=2
Reading at malicious_x = 0x56f156208012... Success: 0x57='W' count=2
Reading at malicious_x = 0x56f156208013... Success: 0x6F='o' count=2
Reading at malicious_x = 0x56f156208014... Success: 0x72='r' count=2
Reading at malicious_x = 0x56f156208015... Success: 0x64='d' count=2
Reading at malicious_x = 0x56f156208016... Success: 0x73='s' count=2
Reading at malicious_x = 0x56f156208017... Success: 0x20=' ' count=2
Reading at malicious_x = 0x56f156208018... Success: 0x61='a' count=2
Reading at malicious_x = 0x56f156208019... Success: 0x72='r' count=2
Reading at malicious_x = 0x56f15620801a... Success: 0x65='e' count=1
Reading at malicious_x = 0x56f15620801b... Success: 0x20=' ' count=2
Reading at malicious_x = 0x56f15620801c... Success: 0x53='S' count=2
Reading at malicious_x = 0x56f15620801d... Success: 0x71='q' count=1
Reading at malicious_x = 0x56f15620801e... Success: 0x75='u' count=1
Reading at malicious_x = 0x56f15620801f... Success: 0x65='e' count=2
Reading at malicious_x = 0x56f156208020... Success: 0x61='a' count=2
Reading at malicious_x = 0x56f156208021... Success: 0x6D='m' count=2
Reading at malicious_x = 0x56f156208022... Success: 0x69='i' count=2
Reading at malicious_x = 0x56f156208023... Success: 0x73='s' count=1
Reading at malicious_x = 0x56f156208024... Success: 0x68='h' count=2
Reading at malicious_x = 0x56f156208025... Success: 0x20=' ' count=2
Reading at malicious_x = 0x56f156208026... Success: 0x4F='O' count=2
Reading at malicious_x = 0x56f156208027... Success: 0x73='s' count=2
Reading at malicious_x = 0x56f156208028... Success: 0x73='s' count=1
Reading at malicious_x = 0x56f156208029... Success: 0x69='i' count=2
Reading at malicious_x = 0x56f15620802a... Success: 0x66='f' count=2
Reading at malicious_x = 0x56f15620802b... Success: 0x72='r' count=2
Reading at malicious_x = 0x56f15620802c... Success: 0x61='a' count=2
Reading at malicious_x = 0x56f15620802d... Success: 0x67='g' count=2
Reading at malicious_x = 0x56f15620802e... Success: 0x65='e' count=2
Reading at malicious_x = 0x56f15620802f... Success: 0x2E='.' count=2
```

