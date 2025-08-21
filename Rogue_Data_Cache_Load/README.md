# Rogue Data Cache Load

本实验通过在用户态触发对内核地址的异常访问，借助处理器在异常架构化（抛出 SIGSEGV）之前的瞬态窗口执行少量指令，把目标字节的值经由 Flush+Reload 风格的缓存通道编码；随后在用户态测量缓存访问时延，还原被瞬态访问到的字节。


## 目录结构与文件说明
```bash
.
├── main-v1.c     # 自证瞬态窗口：对内核地址制造异常，但编码的是“用户态秘密”
├── main-v2.c     # PoC（阶段二）：带预热/绑定CPU等工程化细节的投喂与异常复位
├── main-v3.c     # PoC（阶段三）：完整的 Flush+Reload 解码与批量读取
├── run.sh        # 一键编译、自动解析内核符号地址并依次运行 poc2/poc3
└── Makefile      
```
### main-v1.c
用于验证“带异常的瞬态执行确实发生且可被侧信道观测”。
代码中用户态秘密为："USERSPACE-SECRET: Attack test 123!\n"，用于触发异常的地址常量为 0xffff000000000000UL。

### main-v2.c（对应可执行文件为 poc2）
引入工程化细节以接近真实内核读取：

可选“预加载（pre-load）”内核相关内容进缓存，这里通过反复 pread("/proc/version") 促进瞬态窗口利用；

信号处理器在崩溃前打印 页故障错误码并把 RIP 跳回 stopspeculate，继续用户态流程。该版本已包含瞬态阶段的“取值并映射到 256×4096 通道”的汇编框架，但不做缓存时延扫描统计，主要用于观测异常信息与流程是否跑通。运行形如：
```bash
./poc2 <hex_addr> <init_kernel_in_cache>。
```

### main-v3.c（对应可执行文件为 poc3）
完整实现 Flush+Reload 解码：循环若干次（默认 CYCLES=1000）进行“预加载→flush 通道→瞬态取值→扫描计时”，累计每个候选字节的命中次数，从而输出置信度最高的字节；支持自定义缓存命中阈值。用法：
```bash
./poc3 <hex_addr> <length> [cache_hit_threshold]。
```

### run.sh
一键脚本：先 make，再从 /proc/kallsyms 解析 linux_proc_banner 的地址（可用 ADDRESS=... 覆盖），随后依次运行
```bash
./poc2 <addr> 0（禁用预加载）

./poc2 <addr> 1（启用预加载）

./poc3 <addr> ARG1 ARG2（ARG1 缺省为 10，对应读取字节长度(十六进制)；ARG2 缺省为 400，对应缓存命中阈值）
```
run.sh 需要 sudo 才能在部分系统上读取 /proc/kallsyms。可用 -h/--help 查看帮助。


### 环境与前置条件
x86_64 平台，支持 rdtscp/clflush 等指令。

可编译 C（gcc/clang）与 make 环境。

建议以 root 运行或至少具备读取 /proc/kallsyms 的权限（脚本会使用 sudo）。

目标机器的 Meltdown 缓解措施（如 KPTI 等）可能影响或阻断 PoC 的效果；在不同 CPU/内核版本上结果会不同。

## 快速开始
方式一：一键脚本
```bash
# 可选：赋予执行权限
chmod +x run.sh
# 直接运行（默认读取 10 字节、命中阈值 400）
./run.sh

# 自定义读取长度与阈值，例如读取 0x32 字节、阈值 420
./run.sh 32 420

# 覆盖自动解析的地址（示例）
ADDRESS=ffffffff81a00060 ./run.sh 16 380
```

脚本会：make → 解析 linux_proc_banner 地址 → 运行两次 poc2（对比预加载开关）→ 运行 poc3 做实际字节解码。


方式二：手动运行
```bash
# 1) 编译
make

# 2) 获取目标内核地址 
sudo grep  linux_proc_banner /proc/kallsyms 

# 3) 对比预加载影响
./poc2 【ADDR】 0
./poc2 【ADDR】 1     # 预加载 /proc/version 提升瞬态窗口利用度

# 4) 读取 0xN 个字节（例如 16 字节，命中阈值默认 400）
./poc3 $ADDR 16
# 或显式指定阈值
./poc3 $ADDR 16 420
```
poc3 输出形如：
```python-repl
read ffffffff81a00060 = 61 a (score=XXX/1000)
...
```

其中 score 为该字节命中计数（1000 次循环内的次数）。



## 实现思路与关键机制
### 制造异常，扩大瞬态窗口
在内联汇编中先用若干 add 指令人为拉长流水（.rept 300），随后对 内核地址 执行一次会触发 页/权限错误 的加载；在异常真正架构化前，后续若干指令仍可能瞬态执行。

### 瞬态取值与缓存通道编码
在瞬态窗口内读取目标字节（movzx (%[addr]), %eax），以该字节的值左移 12 位作为偏移，访问 target_array[value * 4096]，从而把 字节值映射到唯一的 cache line。这一路径在 v1/v2/v3 的 speculate()/victim() 汇编中一致。

### 异常复位（不崩溃继续跑）
通过 sigaction(SIGSEGV) 的信号处理器，把 ucontext 中的 RIP 重写到标号 stopspeculate，进程得以继续执行并进入解码阶段；v2 还打印 PF_ERR 位（P/W/U）帮助确认故障类型与权限位。

### 工程化细节

预加载：v2/v3 在每轮前多次 pread("/proc/version")，让相关页/路径更可能驻留缓存，延长有效瞬态窗口（实践性技巧）；v2 通过参数让你对比开关的效果。

CPU 亲和：绑定到 CPU0 降低噪声（sched_setaffinity）。

阈值调参：缓存命中阈值默认为 400 个周期，可通过命令行/脚本参数调整。

自证与逐步推进

v1：不读内核真实数据，而是读取用户态自带的“秘密字符串”，仅验证“瞬态窗口+侧信道”链路可行。

v2：切到真实内核地址目标，铺设运行时环境（预加载/亲和/错误码观察）。

v3：加入统计解码，按字节批量读取并输出分数。


> 在未获授权的系统上运行可能违反法律或组织政策。请在自有/可授权环境中测试，并确保了解相关风险（日志、稳定性、告警等）。

