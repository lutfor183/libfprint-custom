# libfprint-custom

Custom libfprint build for the Goodix 27c6:5117 fingerprint sensor on Ubuntu.

## Status

Active development moved to lutfor183/libfprint-lutfor511
(branch main, commit f069b59). That repo has the current source and
the co-installable deb (lutfor9: threshold 28, calibration 5x30s,
installs to /opt, no conflicts with libfprint-2-2).

This repo keeps the old build_20260618 baseline and the branch
lutfor511 below, which mirrors the active source.

## Old prebuilt install (baseline only)

1. Grab the .deb from Releases.
2. Install:

  sudo dpkg -i --force-overwrite build_*_amd64.deb
  sudo apt install -f

Prefer the lutfor511 repo for new installs.
