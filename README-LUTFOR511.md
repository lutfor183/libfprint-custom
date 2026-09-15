# Lutfor Goodix 511 TLS driver for libfprint (`lutfor511`)

Custom libfprint build carrying a reverse-engineered driver for the
**Goodix 27c6:5117 / 27c6:5110** fingerprint reader
(GF_ST411SEC_APP_12118 firmware family).

Driver id is **`lutfor511`** (not `goodixtls511`), so it co-installs next to
the distribution libfprint without conflicts.

## What's custom vs upstream libfprint

- TLS PSK + MCU config for 27c6:5117/5110 (`goodix511.h`, `goodixtls.c`).
- Reliability hardening in `libfprint/drivers/goodixtls/`:
  frame validation, reassembly of coalesced USB packets, TLS record drain,
  read-error backoff, shutdown ordering, exact image-size checks.
- Responsiveness: calibration reuse (one capture per tap instead of two),
  skip static FW/PSK/OTP re-query after first activation, cached `SSL_CTX`,
  patient capture timeout. Powerdown scan frequency stays at the gentle
  default (`100`).
- PSK bytes, cipher suite (`ALL`), TLS 1.2 pinning and protocol bytes are
  untouched — provisioning behavior is identical to the working baseline.

See `git log` / `git diff` for the full change history.

## Install on Zorin OS / Ubuntu (fresh machine)

```bash
sudo dpkg -i libfprint-2-lutfor-opt_1.94.5-lutfor6_amd64.deb
sudo systemctl restart fprintd
fprintd-enroll "$USER"   # ~5-10 taps
fprintd-verify "$USER"   # tap to test
```

The package installs to `/opt/lutfor-fprint` (never touches system
libfprint), registers `ld.so`, installs a systemd override so `fprintd`
loads this build, and adds a udev rule that keeps the sensor off USB
autosuspend (the #1 "works until suspend" cause).

`apt upgrade` of the distro `libfprint-2-2` is safe; just re-run
`sudo systemctl restart fprintd` if auth feels stale afterwards.

## Rebuild from source

```bash
meson setup build-snappy-opt --prefix=/opt/lutfor-fprint \
  --libdir=/opt/lutfor-fprint/lib/x86_64-linux-gnu --buildtype=release \
  -Db_lto=true -Ddrivers=goodixtls511 -Dudev_rules=enabled \
  -Dintrospection=false -Dgtk-examples=false -Ddoc=false
ninja -C build-snappy-opt
```

## Troubleshooting

- `Device was already claimed`: close Settings → Fingerprint, then retry.
  The GUI holds the device claim exclusively.
- `Command timed out: 0x00` at activation: known firmware quirk — NOP is
  fire-and-forget on 5117 (no ACK); the driver already handles this.
- Logs: `journalctl -u fprintd --since "10 min ago"`.
- Enroll each finger twice at different angles if multi-finger matching
  feels weak (matcher-side, `sigfm` threshold is fixed).

## Maintainer

Lutfor <lutfor183.du@gmail.com> — protocol/TLS key reverse engineering,
driver tuning and packaging.
