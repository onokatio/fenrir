OUTPUT_FORMAT("elf64-littleaarch64")
OUTPUT_ARCH(aarch64)
ENTRY(fastboot_entry)
stock_lock_tail = 0xffff000050f820bc;
SECTIONS {
  . = 0xffff000050f6e4d0;
  .text : { KEEP(*(.entry)) *(.text*) }
  .rodata : { *(.rodata*) }
  .data : { *(.data*) }
  .bss : { *(.bss*) *(COMMON) }
  .tag : { KEEP(*(.fenrir_tag)) }
  /DISCARD/ : { *(.comment*) *(.note*) *(.eh_frame*) }
  ASSERT(protect_entry == fastboot_entry + 4, "protect entry moved")
  ASSERT(ioctl_entry == fastboot_entry + 8, "ioctl entry moved")
  ASSERT(lock_entry == fastboot_entry + 12, "lock entry moved")
  ASSERT(state_get_entry == fastboot_entry + 16, "state getter entry moved")
  ASSERT(state_set_entry == fastboot_entry + 20, "state setter entry moved")
  ASSERT(SIZEOF(.data) == 0 && SIZEOF(.bss) == 0, "payload must not require writable text")
  ASSERT(. <= 0xffff000050f6f820, "payload exceeds the unused eMMC function")
}
