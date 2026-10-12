"""Run the actual AArch64 payload on a mocked LK; never accesses a phone."""
import hashlib
from pathlib import Path
import struct
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_SP, UC_ARM64_REG_LR

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'injector'))
from init_boot_write import InitBootWriteStage
from utils import encode_bl

BASE = InitBootWriteStage.LK_BASE
ENTRY = BASE + InitBootWriteStage.PAYLOAD_OFFSET
STATE = 0xFFFF0000510C1DA0
BUFFER = 0x2000000
STOP = BUFFER + 0x10000
REGS = [UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X4]


class ProtectionError(Exception):
    pass


class LK:
    def __init__(self, flag=None, suffix='_b'):
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.uc.mem_map(BASE, 0x200000)
        self.uc.mem_map(BUFFER, 0x20000)
        self.uc.mem_write(ENTRY, (ROOT / 'payload/build/pacman/init_boot_write/payload.bin').read_bytes())
        self.flag = self.cache = flag
        self.suffix = suffix
        self.first, self.last = 1400, 1599
        self.partition_found = True
        self.storage_ok = self.reload_ok = True
        self.bootdev = 2
        self.bio_result = 0
        self.hw_error_on = 0
        self.writes = []
        self.protect_calls = []
        self.hardware = []
        self.ioctls = []
        self.responses = []
        self.publications = []
        self.command = None
        self.captured = None
        self.uc.hook_add(UC_HOOK_CODE, self.api)

    def string(self, addr):
        if not addr: return None
        return bytes(self.uc.mem_read(addr, 128)).split(b'\0', 1)[0].decode()

    def text(self, addr, value):
        self.uc.mem_write(addr, value.encode() + b'\0')
        return addr

    def api(self, uc, addr, size, _):
        offset = addr - BASE
        args = [uc.reg_read(r) for r in REGS]
        result = 0
        if offset == 0x31038:
            self.assert_key(args[0])
            result = self.text(BUFFER, self.cache) if self.cache is not None else 0
        elif offset == 0x3110C:
            self.assert_key(args[0])
            value = self.string(args[1])
            self.writes.append(value)
            if self.storage_ok: self.flag = self.cache = value
            else: result = -5
        elif offset == 0x30D0C:
            self.cache = self.flag if self.reload_ok else None
        elif offset == 0x178C4:
            result = self.text(BUFFER + 0x100, self.suffix)
        elif offset == 0x734A8:
            assert self.string(args[0]) == 'init_boot' + self.suffix
            part = BUFFER + 0x200
            uc.mem_write(part + 0x20, struct.pack('<QQ', self.first, self.last))
            uc.mem_write(args[1], struct.pack('<Q', part if self.partition_found else 0))
        elif offset == 0x72E70: result = self.bootdev
        elif offset == 0x27D14:
            self.protect_calls.append(args[:2])
            self.captured = bytes(uc.mem_read(STATE, 20))
            result = 77
        elif offset == 0x5F6C0:
            self.ioctls.append(args[:3])
            result = self.bio_result
        elif offset == 0x36F30:
            self.hardware.append(args)
            if len(self.hardware) == self.hw_error_on: result = -5
        elif offset == 0x5FE8:
            assert self.string(args[0]) == 'oem fenrir-init-boot-write'
            assert args[2:4] == [1, 0]
            self.command = args[1]
        elif offset == 0x60C8:
            self.publications.append([self.string(args[0]), self.string(args[1])])
        elif offset in (0x63A8, 0x6378):
            self.responses.append(('OKAY' if offset == 0x63A8 else 'FAIL', self.string(args[0])))
        elif offset == 0x6A38:
            assert self.command is not None and self.publications
        elif offset == 0x60350:
            raise ProtectionError(self.string(args[2]))
        else: return
        uc.reg_write(UC_ARM64_REG_X0, result & ((1 << 64) - 1))
        # Skip all stock LK calls; only the injected binary is executed.
        from unicorn.arm64_const import UC_ARM64_REG_PC
        uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))

    def assert_key(self, addr):
        assert self.string(addr) == 'fenrir_init_boot_write'

    def run(self, addr, *args):
        for reg, value in zip(REGS, args): self.uc.reg_write(reg, value)
        self.uc.reg_write(UC_ARM64_REG_SP, BUFFER + 0x1F000)
        self.uc.reg_write(UC_ARM64_REG_LR, STOP)
        self.uc.emu_start(addr, STOP, count=100000)
        result = self.uc.reg_read(UC_ARM64_REG_X0) & 0xFFFFFFFF
        return result - (1 << 32) if result & 0x80000000 else result

    def activate(self, boot_state=4):
        assert self.run(ENTRY + 4, 0, boot_state) == 77
        assert struct.unpack_from('<I', self.captured, 16)[0] == 1
        assert struct.unpack('<I', self.uc.mem_read(STATE + 16, 4))[0] == 0
        self.uc.mem_write(STATE, self.captured)

    def ioctl(self, first=1000, count=1000, mode=2, lun=3, op=0x101):
        dev, request = BUFFER + 0x300, BUFFER + 0x400
        self.uc.mem_write(dev + 0xA0, struct.pack('<I', lun))
        blob = struct.pack('<QIB3x', first, count, mode)
        self.uc.mem_write(request, blob)
        result = self.run(ENTRY + 8, dev, op, request)
        assert bytes(self.uc.mem_read(request, len(blob))) == blob
        return result


class PayloadTests(unittest.TestCase):
    def test_default_and_invalid_flags_protect(self):
        for flag in (None, 'off', '', 'once', 'once-b-extra', '1'):
            with self.subTest(flag=flag):
                lk = LK(flag)
                self.assertEqual(lk.run(ENTRY + 4, 0, 4), 77)
                self.assertEqual(struct.unpack_from('<I', lk.captured, 16)[0], 0)
                self.assertEqual(lk.writes, [])
                self.assertEqual(lk.ioctl(), 0)
                self.assertEqual(len(lk.ioctls), 1)

    def test_fastboot_arm_query_and_cancel(self):
        for suffix in ('_a', '_b'):
            lk = LK(suffix=suffix)
            lk.run(ENTRY)
            self.assertEqual(lk.publications[-1][1], 'off')
            lk.run(lk.command, lk.text(BUFFER + 0x500, ' once'), 0, 0)
            self.assertEqual(lk.flag, 'once-' + suffix[1])
            self.assertEqual(lk.responses[-1], ('OKAY', lk.flag))
            lk.run(ENTRY)
            self.assertEqual(lk.publications[-1][1], lk.flag)
            lk.run(lk.command, lk.text(BUFFER + 0x500, ' cancel'), 0, 0)
            self.assertEqual(lk.flag, 'off')

    def test_command_errors(self):
        for failure in ('argument', 'storage_ok', 'reload_ok', 'partition_found', 'bootdev'):
            lk = LK()
            lk.run(ENTRY)
            arg = ' once'
            if failure == 'argument': arg = ' once extra'
            elif failure == 'bootdev': lk.bootdev = 1
            else: setattr(lk, failure, False)
            lk.run(lk.command, lk.text(BUFFER + 0x500, arg), 0, 0)
            self.assertEqual(lk.responses[-1][0], 'FAIL')

    def test_split_only_init_boot_and_consume(self):
        for suffix in ('_a', '_b'):
            lk = LK('once-' + suffix[1], suffix)
            lk.activate()
            self.assertEqual(lk.flag, 'off')
            self.assertEqual(lk.writes, ['off'])
            self.assertEqual(lk.ioctl(), 0)
            self.assertEqual(lk.hardware, [[0, 3, 1000, 400, 2], [0, 3, 1600, 400, 2]])
            self.assertEqual(lk.ioctls, [])
            lk.ioctl()
            self.assertEqual(len(lk.ioctls), 1)
            lk.run(ENTRY + 4, 0, 4)
            self.assertEqual(struct.unpack_from('<I', lk.captured, 16)[0], 0)

    def test_stock_caller_security_states_consume_and_split(self):
        # Stock LK passes its cached state (1/3), not the spoofed LKS_LOCK (4).
        for boot_state in (1, 3):
            with self.subTest(boot_state=boot_state):
                lk = LK('once-b')
                # Device GPT and LK log: init_boot_b inside md1img_b -> tee_b.
                lk.first, lk.last = 453376, 455423
                lk.uc.mem_write(BASE + 0x1B4480, struct.pack('<I', 1))
                lk.activate(boot_state)
                self.assertEqual(lk.protect_calls, [[0, boot_state]])
                self.assertEqual(lk.flag, 'off')
                lk.ioctl(first=321536, count=145408)
                self.assertEqual(lk.hardware, [[0, 3, 321536, 131840, 2], [0, 3, 455424, 11520, 2]])
                self.assertEqual(lk.ioctls, [])

    def test_zero_length_pieces(self):
        for first, count, pieces in ((1400, 200, []), (1400, 600, [[0, 3, 1600, 400, 2]]),
                                     (1000, 600, [[0, 3, 1000, 400, 2]])):
            lk = LK('once-b'); lk.activate(); lk.ioctl(first, count)
            self.assertEqual(lk.hardware, pieces)

    def test_other_ranges_and_luns_keep_protection(self):
        cases = [dict(first=2000), dict(first=1500), dict(count=0), dict(mode=0), dict(lun=1),
                 dict(lun=2), dict(op=0x102), dict(first=0xFFFFFFFF, count=2)]
        for args in cases:
            lk = LK('once-b'); lk.activate(); lk.bio_result = -5
            self.assertEqual(lk.ioctl(**args), -5)
            self.assertEqual(lk.hardware, [])
            self.assertEqual(len(lk.ioctls), 1)

    def test_failed_consumption_or_lookup_keeps_protection(self):
        for failure in ('storage_ok', 'reload_ok', 'partition_found', 'suffix', 'extent'):
            lk = LK('once-b')
            if failure == 'suffix': lk.suffix = '_a'
            elif failure == 'extent': lk.last = lk.first - 1
            else: setattr(lk, failure, False)
            lk.run(ENTRY + 4, 0, 4)
            self.assertEqual(struct.unpack_from('<I', lk.captured, 16)[0], 0)

    def test_other_boot_modes_do_not_consume(self):
        for mode, locked, bootdev in ((1, 4, 2), (4, 4, 2), (0, 2, 2), (0, 4, 1)):
            lk = LK('once-b'); lk.bootdev = bootdev
            lk.run(ENTRY + 4, mode, locked)
            self.assertEqual(lk.flag, 'once-b')
            self.assertEqual(struct.unpack_from('<I', lk.captured, 16)[0], 0)

    def test_hardware_error_stops_boot(self):
        for failed_piece in (1, 2):
            lk = LK('once-b'); lk.activate(); lk.hw_error_on = failed_piece
            with self.assertRaises(ProtectionError): lk.ioctl()

    def test_write_protect_entry_budget(self):
        for entries in (0, 1, 2, 3, 4):
            lk = LK('once-b'); lk.activate()
            lk.uc.mem_write(BASE + 0x1B4480, struct.pack('<I', entries))
            lk.ioctl()
            if entries <= 1:
                self.assertEqual(len(lk.hardware), 2)
                self.assertEqual(lk.ioctls, [])
            else:
                self.assertEqual(lk.hardware, [])
                self.assertEqual(len(lk.ioctls), 1)


class InjectorTests(unittest.TestCase):
    def test_wrong_build_and_missing_payload_fail_without_mutation(self):
        stage = InitBootWriteStage()
        lk = SimpleNamespace(data=b'wrong build')
        ctx = SimpleNamespace(base=BASE, lk=lk, payload_dir=Path('/nonexistent'))
        with self.assertRaises(ValueError): stage.execute(ctx)
        self.assertEqual(lk.data, b'wrong build')
        with patch.object(stage, 'LK_SHA256', hashlib.sha256(lk.data).hexdigest()):
            with self.assertRaises(RuntimeError): stage.execute(ctx)
        self.assertEqual(lk.data, b'wrong build')

    def test_patch_changes_only_three_calls_and_payload(self):
        stage = InitBootWriteStage()
        original = bytearray(0xE2610)
        for call, target, _ in stage.HOOKS:
            original[call:call + 4] = encode_bl(BASE + call, BASE + target)
        lk = SimpleNamespace(data=bytes(original))
        ctx = SimpleNamespace(base=BASE, lk=lk, payload_dir=ROOT / 'payload/build')
        with patch.object(stage, 'LK_SHA256', hashlib.sha256(original).hexdigest()): stage.execute(ctx)
        payload = stage.load_payload(ctx.payload_dir, 'pacman')
        allowed = set(range(stage.PAYLOAD_OFFSET, stage.PAYLOAD_OFFSET + len(payload)))
        for call, _, entry in stage.HOOKS:
            allowed.update(range(call, call + 4))
            self.assertEqual(lk.data[call:call + 4], encode_bl(BASE + call, ENTRY + entry))
        changed = {i for i, (a, b) in enumerate(zip(original, lk.data)) if a != b}
        self.assertTrue(changed <= allowed)
        self.assertEqual(len(original), len(lk.data))

    def test_corrupt_payload_and_call_fail_before_mutation(self):
        stage = InitBootWriteStage()
        original = bytearray(0xE2610)
        for call, target, _ in stage.HOOKS:
            original[call:call + 4] = encode_bl(BASE + call, BASE + target)
        valid = stage.load_payload(ROOT / 'payload/build', 'pacman')
        for invalid in (b'', valid[:-32], valid + b'x' * stage.CAPACITY, b'x' * len(valid)):
            lk = SimpleNamespace(data=bytes(original))
            ctx = SimpleNamespace(base=BASE, lk=lk, payload_dir=ROOT / 'payload/build')
            with patch.object(stage, 'LK_SHA256', hashlib.sha256(original).hexdigest()), patch.object(stage, 'load_payload', return_value=invalid):
                with self.assertRaises(ValueError): stage.execute(ctx)
            self.assertEqual(lk.data, original)
        original[stage.HOOKS[0][0]] ^= 1
        lk = SimpleNamespace(data=bytes(original))
        with patch.object(stage, 'LK_SHA256', hashlib.sha256(original).hexdigest()):
            with self.assertRaises(ValueError): stage.execute(SimpleNamespace(base=BASE, lk=lk, payload_dir=ROOT / 'payload/build'))
        self.assertEqual(lk.data, original)


if __name__ == '__main__':
    unittest.main()
