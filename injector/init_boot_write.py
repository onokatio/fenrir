import hashlib
import struct

from stage import PayloadStage, InjectionContext
from utils import encode_b, encode_bl


class InitBootWriteStage(PayloadStage):
    """Only the already-patched Pacman LK build analysed for this fork."""

    LK_BASE = 0xFFFF000050F00000
    PAYLOAD_OFFSET = 0x6E4D0
    CAPACITY = 0x1350
    LK_SHA256 = "6d9417d1f2bb118ff1ea0767b3f6bab1d4cedd0f9205cec9a810d8d5d4ef0cd1"
    HOOKS = ((0xE18C, 0x6A38, 0), (0xDA2C, 0x27D14, 4), (0x73330, 0x5F6C0, 8))
    FUNCTION_HOOKS = (
        (0x820AC, bytes.fromhex('88008052080000b900008052c0035fd6'), 12),
        (0x4F2E0, bytes.fromhex('c8030090002141b9c0035fd6'), 16),
        (0x4F2EC, bytes.fromhex('c80300901f2101b9c0035fd6'), 20),
    )

    def __init__(self):
        super().__init__(
            "init_boot_write", self.LK_BASE + self.PAYLOAD_OFFSET,
            self.LK_BASE + self.HOOKS[0][0],
            description="One normal boot with active init_boot writable, default protected",
        )

    def execute(self, ctx: InjectionContext) -> None:
        if ctx.base != self.LK_BASE or hashlib.sha256(ctx.lk.data).hexdigest() != self.LK_SHA256:
            raise ValueError("Unsupported LK: requires Fenrir Pacman k6886v1_64_f26fec132_202511201009")
        try:
            payload = self.load_payload(ctx.payload_dir, "pacman")
        except FileNotFoundError as error:
            # This stage must not inherit the injector's optional-payload skip behaviour.
            raise RuntimeError("Build the init-boot-write target before injecting") from error
        tag = b"FENRIR_INIT_BOOT_WRITE_V3\0"
        if not 64 <= len(payload) <= self.CAPACITY or payload.count(tag) != 1 or not payload.rstrip(b'\0').endswith(tag[:-1]):
            raise ValueError("Invalid init_boot_write payload")
        for entry in (0, 4, 8, 12, 16, 20):
            instruction = struct.unpack_from("<I", payload, entry)[0]
            offset = instruction & 0x3FFFFFF
            if offset & 0x2000000:
                offset -= 0x4000000
            if instruction >> 26 != 5 or not 24 <= entry + offset * 4 < len(payload):
                raise ValueError("Invalid payload entry branch")
        data = bytearray(ctx.lk.data)
        for call, original, entry in self.HOOKS:
            if data[call:call + 4] != encode_bl(ctx.base + call, ctx.base + original):
                raise ValueError("Unexpected LK call instruction")
            data[call:call + 4] = encode_bl(ctx.base + call, self.base_addr + entry)
        for function, expected, entry in self.FUNCTION_HOOKS:
            if data[function:function + len(expected)] != expected:
                raise ValueError("Unexpected Fenrir state function")
            data[function:function + 4] = encode_b(ctx.base + function, self.base_addr + entry)
        data[self.PAYLOAD_OFFSET:self.PAYLOAD_OFFSET + len(payload)] = payload
        ctx.lk.data = bytes(data)
        print("Injected init_boot_write; protection remains enabled unless explicitly armed")
