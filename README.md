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
