# android-vpn-fileserver
VPN‑aware, background‑safe, authenticated file‑transfer server designed specifically for the Debian VM inside Android’s AVF

## What is this?
Android devices running the experimental linux terminal cannot accept inbound connections from the internet due to carrier NAT, android firewalls, VM isolation, and no public ipv4 address.
These scripts allow you to bypass that by allowing access to files in a directory inside your VM instance by connecting to a VPN and serving the files through the VPN tunnel.

## What does it do?
- Connects to a VPN Ip Address by auto detecting tun0 ip address on either WireShark or OpenVPN
- Asks if you want to start WireShark or OpenVPN if a connection does not exist.
- Pushes VPN instance to the background to avoid taking over the terminal window. (assuming you started the VPN with the script)
- Creates a server and asks for you to set access credentials.
- Pushes server to the background to avoid taking over the terminal window.

## Security Notes:
- The server binds only to the VPN IP, never to Wi‑Fi or mobile interfaces.
- Basic authentication is required for all access.
- HTTPS is optional (self‑signed certificate).
- Uploads and downloads are logged.
- No third‑party tunnels (Cloudflare/ngrok/etc.) are used.
- This setup is intended for temporary, controlled access.

## Quick Start:
- Fork the repo or clone it or download the 2 script files with curl or wget
- Make both scripts executable
- Run the main script ./ultimate_vpn_file_server.sh
- Follow the prompts

  ```bash
  chmod +x ultimate_vpn_file_server.sh
  chmod +x stop_vpn_file_server.sh
  ```

  ```bash
  ./ultimate_vpn_file_server.sh
  ```

  ```bash
  ./stop_vpn_file_server.sh
  ```
