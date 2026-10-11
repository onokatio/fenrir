# One normal boot with writable init_boot (experimental)

This fork adds an experimental flag-controlled exception to UFS write protection while retaining Fenrir's locked / green spoof. Default boots use stock LK's protection ranges. Only an explicit flag excludes the selected slot's `init_boot` on the next normal boot.

Booting on hardware, the resulting UFS protection, and KernelSU-Next writes have not been tested. Generated LK images are experimental. Building and testing do not operate a phone.

## Supported LK

Only the existing Fenrir-patched Nothing Phone (2a) / Pacman LK `k6886v1_64_f26fec132_202511201009` is supported. Its main LK payload must have SHA-256:

```text
6d9417d1f2bb118ff1ea0767b3f6bab1d4cedd0f9205cec9a810d8d5d4ef0cd1
```

Use a backup of a Fenrir LK already known to boot. Stock LK and other builds are rejected. Existing `Pacman` and other injectors retain their original behavior; select `PacmanInitBootWrite` to add this feature.

## Build

From the repository root, install Python dependencies and put the AArch64 GNU toolchain on PATH:

```sh
python3 -m pip install -r requirements.txt
make -C payload/init_boot_write
python3 injector/inject.py PacmanInitBootWrite /path/to/fenrir-lk-backup.img \
  -o /path/to/fenrir-lk-init-boot-write-experimental.img
```

The Linux `aarch64-linux-gnu` toolchain also works:

```sh
make -C payload/init_boot_write CC=aarch64-linux-gnu-gcc \
  LD=aarch64-linux-gnu-gcc OBJCOPY=aarch64-linux-gnu-objcopy
```

Missing or oversized payloads and mismatching input LK images stop injection with an error. Successful injection does not flash anything. Use different input and output files.

## Flag commands

These commands describe the interface after this LK is installed. They are not available in ordinary Fenrir LK or fastbootd. Arming and cancelling write the flag to LK's environment area in `para`.

```sh
# Read the pending state without writing
fastboot getvar fenrir-init-boot-write

# Allow the currently selected slot once, on the next normal boot
fastboot oem fenrir-init-boot-write once

# Cancel the pending exception
fastboot oem fenrir-init-boot-write cancel
```

The variable reports `off`, `once-a`, or `once-b`. It describes the next-boot request, not the hardware's current protection state.

Before installing protection during normal boot, the payload persists `off` and verifies it by re-reading storage. If the recorded and selected slots match, their `init_boot` is excluded for that Android session. The following normal boot restores stock protection. Recovery and fastboot boots do not consume the request.

## Protection and errors

The payload splits stock LK's range before and after the GPT extent of `init_boot_a` or `init_boot_b`. The opposite slot, LK, preloader, seccfg, and other ranges follow the original protection logic. Lock-state and Verified Boot spoof patches are untouched.

Failed persistence, readback, slot matching, or GPT lookup uses the original protection. Each LU supports at most four SWPCB entries: if the split cannot leave one entry for the following seccfg range, the original full range is protected. A hardware error while applying either split calls LK's assert handler, preventing Android from booting with incomplete protection.

The flag does not grant root. Android writes still require root through KernelSU or another mechanism and an image for the correct slot and build.

## Verification

```sh
python3 -m pip install unicorn==2.1.4
python3 -m unittest discover -s tests -v
```

Tests execute the compiled AArch64 binary in an emulator with mocked LK and UFS functions. They cover arming, cancellation, consumption, slot checks, range splitting, protection-entry limits, and errors. They do not replace hardware validation.

## Injection locations

The analysed LK virtual base is `0xffff000050f00000`:

| Target | Offset |
| --- | --- |
| Payload replacing an unused eMMC function | `0x6e4d0`, at most `0x1350` bytes |
| Call to `notify_enter_fastboot` | `0xe18c` |
| Call to `set_write_protect` | `0xda2c` |
| General partition-range call to `bio_ioctl` | `0x73330` |
| LK environment get / set / init | `0x31038` / `0x3110c` / `0x30d0c` |
| GPT lookup / UFS protection | `0x734a8` / `0x36f30` |

Runtime state uses the unused eMMC BSS at `0xffff0000510c1da0`. Other LK subimages, total image size, and GPT are unchanged. Supporting another build requires fresh analysis.
