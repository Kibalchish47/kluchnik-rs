# "Kluchnik" Client Application

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![Made with Rust](https://img.shields.io/badge/made%20with-Rust-orange.svg)](https://www.rust-lang.org/)

This is the repository for the desktop client application that interacts with the "Kluchnik" hardware True Random Number Generator (TRNG). The application is written in **Rust** using the cross-platform **Iced** GUI framework.

## ✨ Features

* **Wi-Fi Connection:** Automatically connects to the access point created by the "Kluchnik" device.
* **Secure Data Transfer:** Receives an encrypted 128-bit key over the TCP protocol.
* **Decryption:** Uses the **AES-128-CBC** standard to decrypt the key, ensuring its integrity.
* **Password Generation:** Creates cryptographically strong passwords based on the truly random data.
* **Visualization:** Displays the generated password and a QR code for easy use on mobile devices.
* **Remote Control:** Allows you to control the device's menu using buttons in the interface or keyboard hotkeys (arrow keys, Enter, Space).
* **Customization:** Supports light and dark UI themes.

## 🖥️ System Requirements

* **Operating System:** Linux (primary target), Windows, macOS.
* **Build Dependencies (Linux):** To compile on Debian/Ubuntu-based distributions, you may need to install development packages:
    ```bash
    sudo apt-get install build-essential libgtk-3-dev libxcb-shape0-dev libxcb-xfixes0-dev
    ```

## 🛠️ Build and Run

### 1. Install Rust

If you don't have Rust installed, use the official installer:
```bash
curl --proto '=https' --tlsv1.2 -sSf [https://sh.rustup.rs](https://sh.rustup.rs) | sh
```

### 2. Clone and Setup

```bash
git clone [https://github.com/your-repo/kluchnik-rs.git](https://github.com/your-repo/kluchnik-rs.git)
cd kluchnik-rs
```

**Important:** For the interface to display correctly, place the following files in the root folder of the project (next to `Cargo.toml`):
* `logo.svg` — your logo in SVG format.
* `GeistMono-Regular.otf` — the custom font file.

### 3. Run in Development Mode

```bash
cargo run
```

### 4. Build for Distribution

To compile an optimized version of the application, run:
```bash
cargo build --release
```
The final executable file will be located in the `target/release/` directory.

## 🚀 Distribution

To distribute the application to users:
1.  Create a new folder.
2.  Copy the executable file from `target/release/` into it.
3.  Copy the `logo.svg` and `GeistMono-Regular.otf` files into the same folder.
4.  Archive the folder and send it to the user.

The application is now ready to run!
