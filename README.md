# libfprint-custom
Custom-tailored libfprint source and package build for Goodix ID 27c6:5117  fingerprint sensor
# Custom libfprint Build for Ubuntu

A tailored source and package build of `libfprint-1` to support fingerprint readers on Linux systems.

## 🚀 Overview
This repository contains the source code, configurations, and build assets for a customized `libfprint` package designed to resolve driver compatibility or missing hardware integration issues for Goodix 27c6:5117

## 📦 Pre-built Installation
If you want to install the compiled package directly:
1. Grab the `.deb` file from the [Releases](../../releases) section.
2. Run the following command to install it and bypass file collisions:
   ```bash
   sudo dpkg -i --force-overwrite build_*_amd64.deb
   sudo apt install -f

## ➡️ Canonical repo (active)
New peaceful driver lives in [lutfor183/libfprint-lutfor511](https://github.com/lutfor183/libfprint-lutfor511) (`lutfor511`, co-installable `/opt`, `lutfor9` deb, threshold 28 + calib 5x30s). This repo keeps the old `build_20260618` baseline only.
