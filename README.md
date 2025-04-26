# 🔒 Secure SSL VPN System with raw sockets and AES-256 encryption

## 📜 Project Overview

This project presents the development of a **secure SSL-based Virtual Private Network (VPN)** system, combined with a **modern GUI** built using **PyQt5**.  
It offers secure, encrypted communication between a client and server using **OpenSSL** and **AES-256-CBC** encryption.

🔹 **Languages/Technologies:**  
- C (for server and client backend)  
- Python (for GUI frontend)  
- OpenSSL (TLS communication)  
- PyQt5 (GUI development)  
- AES-256-CBC (encryption)

---

## 🛠️ Components

### 🖥️ 1. VPN Server (`vpn_server.c`)
- C-based multithreaded server using **OpenSSL**.
- Performs **mutual TLS authentication**.
- Encrypts and decrypts messages using **AES-256-CBC**.
- Handles multiple concurrent client connections securely.

### 💻 2. VPN Client (`vpn_client.c`)
- C-based client program connecting to the VPN server via **TLS**.
- Ensures **encrypted communication** using AES symmetric encryption.

### 🎨 3. VPN GUI (`vpn_gui.py`)
- PyQt5-based graphical interface to:
  - 🔹 Start/Stop VPN connections
  - 🔹 Select server IP, port, and protocol (UDP, TCP, WireGuard placeholder)
  - 🔹 Monitor real-time logs
  - 🔹 Track connection duration
  - 🔹 Enable Auto-Reconnect
  - 🔹 Save/load VPN profiles (secured using Fernet encryption)
  - 🔹 Toggle between Dark Mode / Light Mode 🌙☀️

---

## 🚀 Features

- ✅ **Mutual TLS Authentication** for client-server validation.
- ✅ **AES-256-CBC** Encryption for secure communication.
- ✅ **User-Friendly GUI** for managing VPN sessions.
- ✅ **Connection Logs** and **Timer** display.
- ✅ **Profile Management** with Encryption.

---

## ⚙️ Setup Instructions

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/secure-vpn-gui.git
   cd secure-vpn-gui
   '''
2. Install Python dependencies:
     pip install pyqt5 cryptography

3. Compile the server and client:
     gcc vpn_server.c -o vpn_server -lssl -lcrypto -lpthread
     gcc vpn_client.c -o vpn_client -lssl -lcrypto

4. Run the VPN Server and Client and initiate the gui:
     ./vpn_server
     ./vpn_client
     python vpn_gui.py

   ## 📚 References

- 🔗 [OpenSSL Project](https://www.openssl.org/)
- 🔗 [PyQt5 Documentation](https://doc.qt.io/qtforpython/)
- 🔗 [Cryptography Python Package](https://cryptography.io/)

---

## 📈 Future Enhancements

- 🔥 Add WireGuard protocol support.
- 📡 Implement dynamic IP filtering and kill switch.
- 📱 Develop a mobile app version.
- 📦 Improve automatic server discovery.

---

# 🚀 Stay Safe and Connected!

