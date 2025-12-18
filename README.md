 HEAD

# AndroidSecurityTesting
An advanced Android Security Testing Suite with GUI (PyQt5) for ethical penetration testing, device analysis, and learning Android security techniques.

# 🔐 AndroidSecurityTesting

An advanced **Android Security Testing Suite** built with **Python + PyQt5**.  
This project provides a graphical interface for interacting with Android devices via **ADB** for **ethical security testing, learning, and research**.

> ⚠️ **DISCLAIMER**  
> This tool is intended **ONLY** for devices and applications you own or have **explicit permission** to test.  
> Any illegal or unauthorized use is strictly forbidden.

---

## ✨ Features

- 🖥️ Modern GUI built with **PyQt5**
- 📱 Android device detection via **ADB**
- 🔌 USB connection monitoring
- 📦 List connected Android devices
- 🧩 Modular & clean architecture
- 🎨 Icon-based interface
- 🛡️ Designed for **Android security testing**

---

## 🖥️ Supported OS

- Kali Linux (recommended)
- Other Linux distributions

---

## ⚙️ Requirements

- Python **3.9+**
- Android device
- USB cable
- **USB Debugging enabled**
- System ADB installed

## Install ADB:
```bash
sudo apt install adb

---

## 📦 Python Dependencies

adb_shell==0.4.4
certifi==2025.11.12
cffi==2.0.0
charset-normalizer==3.4.4
cryptography==46.0.3
idna==3.11
pure-python-adb==0.3.0.dev0
pyasn1==0.6.1
pycparser==2.23
PyQt5==5.15.11
PyQt5-Qt5==5.15.18
PyQt5_sip==12.17.2
requests==2.32.5
rsa==4.9.1
urllib3==2.6.2

---

## nstall dependencies:
pip install -r requirements.txt

---

## USB Setup (Important)

# On your Android phone:

1. Enable Developer Options

2. Enable USB Debugging

3. Set USB mode to:

4. File Transfer (MTP)

# Verify connection:

adb devices

# You should see your device listed.


## Run the Tool:
python3 src/main.py

---

## 🔒 Ethical Use Notice

This project is for:
- Learning Android security
- Testing your own devices
- Authorized penetration testing

❌ Do NOT use on:
- Other people's phones
- Apps you don’t own
- Any illegal activity

---

## 👨‍💻 Author

**Mazin**  
Android Security Researcher  
Kali Linux User

>>>>>>> 6ddea4e (Initial release: Android Security Testing GUI)
