# 生成可执行文件 poc，源文件为 main.c
TARGET = poc
SRC    = main.c

# 使用 gcc，关闭优化并启用 C99
CC      = gcc
CFLAGS  = -O0 -fno-pie -no-pie -std=gnu11 -Wall

# 默认目标
all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

# 运行可执行文件
run: $(TARGET)
	./$(TARGET)

# 清理生成的文件
clean:
	rm -f $(TARGET)

.PHONY: all clean run