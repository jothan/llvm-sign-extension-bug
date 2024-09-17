# Build instructions

1. Grab the 1.81 esp-rs toolchain with espup.
```bash
espup install --toolchain-version 1.81.0.0
source ~/export-esp.sh
```
2. Put your wifi-credentials in the wifi-ssid and wifi-pass files.
```bash
echo -n "MyNet" > wifi-ssid
echo -n "hunter42" > wifi-pass
```
3. Build the project with cargo
```bash
cargo build
```
