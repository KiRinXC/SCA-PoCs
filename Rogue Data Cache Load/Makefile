# 生成可执行文件 poc（v1）和 poc-v2（v2）
TARGET_V1 = poc1
TARGET_V2 = poc2
SRC_V1    = main-v1.c
SRC_V2    = main-v2.c

# 使用 gcc，关闭优化并启用 C99
CC     = gcc
CFLAGS = -std=c99 -O0

# 默认目标：同时编译 v1 和 v2
all: $(TARGET_V1) $(TARGET_V2)

$(TARGET_V1): $(SRC_V1)
	$(CC) $(CFLAGS) -o $@ $<

$(TARGET_V2): $(SRC_V2)
	$(CC) $(CFLAGS) -o $@ $<

# 运行 v1
run1: $(TARGET_V1)
	./$(TARGET_V1)

# 运行 v2
run2: $(TARGET_V2)
	./$(TARGET_V2)

# 清理生成的可执行文件
clean:
	rm -f $(TARGET_V1) $(TARGET_V2)

.PHONY: all clean run1 run2