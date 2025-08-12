# 内核模块部分
obj-m += kernel_secret.o
KDIR := /lib/modules/$(shell uname -r)/build

# 用户态程序部分
USER_TARGET := poc
USER_SRC := main.c
USER_CFLAGS := -std=c99 -O0

PWD := $(shell pwd)

all: $(USER_TARGET) modules

# 编译内核模块
modules:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# 编译用户态程序
$(USER_TARGET): $(USER_SRC)
	$(CC) $(USER_CFLAGS) -o $@ $<

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	$(RM) $(USER_TARGET)
