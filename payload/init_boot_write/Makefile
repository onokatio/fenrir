CC := aarch64-none-elf-gcc
LD := aarch64-none-elf-gcc
OBJCOPY := aarch64-none-elf-objcopy
BUILD := ../build/pacman/init_boot_write

.PHONY: all
all: $(BUILD)/payload.bin

$(BUILD)/payload.bin: payload.c linker.x
	@mkdir -p $(@D)
	$(CC) -Os -mcpu=generic -mgeneral-regs-only -ffreestanding -fno-builtin -fno-stack-protector -fno-pic -fno-pie -mcmodel=large -Wall -Wextra -Werror -c $< -o $(@D)/payload.o
	$(LD) -nostdlib -static -no-pie -Wl,--build-id=none,--no-undefined,-e,fastboot_entry -T linker.x $(@D)/payload.o -o $(@D)/payload.elf
	$(OBJCOPY) -O binary $(@D)/payload.elf $@
