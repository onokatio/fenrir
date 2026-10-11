#include <stdint.h>
#include <stddef.h>

/* shortcut: Pacman k6886v1_64_f26fec132_202511201009 only; re-analyse a new LK before adding it. */
#define API(offset, type) ((type)(uintptr_t)(0xffff000050f00000ULL + (offset)))
#define env_get API(0x31038, const char *(*)(const char *))
#define env_set API(0x3110c, int (*)(const char *, const char *))
#define env_init API(0x30d0c, void (*)(void))
#define get_suffix API(0x178c4, const char *(*)(void))
#define get_partition API(0x734a8, int (*)(const char *, const void **))
#define get_bootdev API(0x72e70, int (*)(void))
#define set_protect API(0x27d14, int (*)(uint8_t, int))
#define bio_ioctl API(0x5f6c0, int (*)(void *, unsigned, void *))
#define ufs_protect API(0x36f30, int (*)(unsigned, unsigned, uint64_t, uint32_t, unsigned))
#define fb_register API(0x5fe8, void (*)(const char *, void *, int, int))
#define fb_publish API(0x60c8, void (*)(const char *, const char *))
#define fb_okay API(0x63a8, void (*)(const char *))
#define fb_fail API(0x6378, void (*)(const char *))
#define notify_fastboot API(0x6a38, void (*)(void))
#define lk_assert API(0x60350, void (*)(const char *, unsigned, const char *))

struct range { uint64_t first; uint32_t count; uint8_t type; uint8_t padding[3]; };
struct window { uint64_t first, last; uint32_t enabled; };
/* Reuse the unused eMMC context in BSS, not the read-only payload's data. */
#define window (*(volatile struct window *)(uintptr_t)0xffff0000510c1da0ULL)
_Static_assert(offsetof(struct range, type) == 12, "LK ioctl ABI");

__asm__(".section .entry,\"ax\"\n"
        ".global fastboot_entry, protect_entry, ioctl_entry\n"
        "fastboot_entry: b fenrir_fastboot\n"
        "protect_entry: b fenrir_protect\n"
        "ioctl_entry: b fenrir_ioctl\n"
        ".text\n");
__attribute__((used, section(".fenrir_tag")))
static const char payload_tag[] = "FENRIR_INIT_BOOT_WRITE_V1";
static const char key[] = "fenrir_init_boot_write";
static const char variable[] = "fenrir-init-boot-write";

static int equal(const char *a, const char *b) {
    if (!a || !b) return 0;
    while (*a && *a == *b) { ++a; ++b; }
    return *a == *b;
}

static const char *pending(void) {
    const char *value = env_get(key);
    if (equal(value, "once-a")) return "once-a";
    if (equal(value, "once-b")) return "once-b";
    return "off";
}

static int save(const char *value) {
    if (env_set(key, value) != 0) return 0;
    /* Read back from storage; env_get alone would only inspect the cached value. */
    env_init();
    return equal(env_get(key), value);
}

static int extent(const char *suffix, uint64_t *first, uint64_t *last) {
    const void *part = NULL;
    const char *name;
    if (equal(suffix, "_a")) name = "init_boot_a";
    else if (equal(suffix, "_b")) name = "init_boot_b";
    else return 0;
    if (get_partition(name, &part) != 0 || !part) return 0;
    *first = *(const uint64_t *)((const uint8_t *)part + 0x20);
    *last = *(const uint64_t *)((const uint8_t *)part + 0x28);
    return *first <= *last && *last < UINT32_MAX;
}

static void command(const char *arg, void *data, unsigned size) {
    (void)data; (void)size;
    const char *value;
    if (equal(arg, " once")) {
        uint64_t first, last;
        const char *suffix = get_suffix();
        if (get_bootdev() != 2 || !extent(suffix, &first, &last)) {
            fb_fail("Cannot identify the UFS init_boot partition");
            return;
        }
        value = equal(suffix, "_a") ? "once-a" : "once-b";
    } else if (equal(arg, " cancel")) value = "off";
    else { fb_fail("Use: oem fenrir-init-boot-write once|cancel"); return; }
    if (!save(value)) { fb_fail("Cannot persist the init_boot write flag"); return; }
    fb_publish(variable, value);
    fb_okay(value);
}

void fenrir_fastboot(void) {
    fb_register("oem fenrir-init-boot-write", command, 1, 0);
    fb_publish(variable, pending());
    notify_fastboot();
}

int fenrir_protect(uint8_t mode, int lock_state) {
    window.enabled = 0;
    if (mode == 0 && lock_state == 4 && get_bootdev() == 2) {
        const char *value = pending();
        if (!equal(value, "off")) {
            uint64_t first, last;
            const char *suffix = get_suffix();
            int valid = ((equal(value, "once-a") && equal(suffix, "_a")) ||
                         (equal(value, "once-b") && equal(suffix, "_b"))) &&
                        extent(suffix, &first, &last);
            /* Consume before stock LK protects the environment partition. */
            if (save("off") && valid) {
                window.first = first;
                window.last = last;
                window.enabled = 1;
            }
        }
    }
    int result = set_protect(mode, lock_state);
    window.enabled = 0;
    return result;
}

static void protect_piece(unsigned lun, uint64_t first, uint32_t count) {
    if (count && ufs_protect(0, lun, first, count, 2) != 0) {
        /* Stock UFS bio_ioctl discards errors; do not boot with incomplete protection. */
        lk_assert("fenrir", 0, "UFS write-protect range failed");
        for (;;) {}
    }
}

int fenrir_ioctl(void *dev, unsigned op, struct range *range) {
    if (!window.enabled || op != 0x101 || !dev || !range || range->type != 2)
        return bio_ioctl(dev, op, range);
    unsigned lun = *(const unsigned *)((const uint8_t *)dev + 0xa0);
    /* LK uses one-based partition IDs: 3 is the user-data LU (physical LU 2). */
    if (lun != 3 || !range->count || range->first > UINT32_MAX ||
        range->count - 1ULL > UINT32_MAX - range->first)
        return bio_ioctl(dev, op, range);
    uint64_t end = range->first + range->count - 1ULL;
    if (window.first < range->first || window.last > end)
        return bio_ioctl(dev, op, range);
    window.enabled = 0;
    unsigned pieces = (window.first > range->first) + (window.last < end);
    unsigned entries = *(volatile unsigned *)(uintptr_t)0xffff0000510b4480ULL;
    /* Four SWPCB entries per LU; reserve one for stock LK's following seccfg range. */
    if (entries > 3 || pieces > 3 - entries)
        return bio_ioctl(dev, op, range);
    protect_piece(lun, range->first, (uint32_t)(window.first - range->first));
    protect_piece(lun, window.last + 1, (uint32_t)(end - window.last));
    return 0;
}
