#!/bin/bash

LOGFILE="fts_log_$(date +%Y%m%d_%H%M%S).txt"
VPN_LOGFILE="vpn_log_$(date +%Y%m%d_%H%M%S).txt"
SERVER_LOGFILE="server_log_$(date +%Y%m%d_%H%M%S).txt"

log() {
    echo -e "$1" | tee -a "$LOGFILE"
}

# ------------------------------------------------------------
# Detect VPN interface
# ------------------------------------------------------------
detect_vpn() {
    if ip addr show tun0 >/dev/null 2>&1; then
        VPN_IF="tun0"
    elif ip addr show wg0 >/dev/null 2>&1; then
        VPN_IF="wg0"
    else
        VPN_IF=""
    fi
}

# ------------------------------------------------------------
# Safely start VPN in background
# ------------------------------------------------------------
start_vpn_safely() {
    echo ""
    echo "No VPN detected. Start one?"
    echo "1) WireGuard (wg-quick up wg0)"
    echo "2) OpenVPN (.ovpn config)"
    echo "3) Cancel"
    read -p "Choose: " vpn_choice

    case "$vpn_choice" in
        1)
            read -p "WireGuard config name (default wg0): " wgname
            wgname=${wgname:-wg0}
            log "Starting WireGuard ($wgname)..."
            sudo wg-quick up "$wgname" >"$VPN_LOGFILE" 2>&1 &
            echo $! > vpn.pid
            disown
            ;;
        2)
            read -p "Path to .ovpn config: " ovpn
            log "Starting OpenVPN with config $ovpn..."
            sudo openvpn --config "$ovpn" >"$VPN_LOGFILE" 2>&1 &
            echo $! > vpn.pid
            disown
            ;;
        3)
            log "VPN start cancelled by user."
            return
            ;;
        *)
            echo "Invalid option."
            return
            ;;
    esac

    echo "Waiting for VPN interface (tun0 or wg0)..."
    for i in {1..20}; do
        if ip addr show tun0 >/dev/null 2>&1 || ip addr show wg0 >/dev/null 2>&1; then
            echo "VPN connected."
            log "VPN connected."
            return
        fi
        sleep 1
    done

    echo "VPN failed to start. Check $VPN_LOGFILE"
    log "VPN failed to start. See $VPN_LOGFILE"
}

# ------------------------------------------------------------
# Get VPN IP
# ------------------------------------------------------------
get_vpn_ip() {
    if [[ -n "$VPN_IF" ]]; then
        VPN_IP=$(ip -4 addr show "$VPN_IF" | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
        log "Detected VPN interface: $VPN_IF"
        log "VPN IP: $VPN_IP"
    else
        echo "No VPN interface detected."
        read -p "Enter VPN IP address to bind the server to: " VPN_IP
        log "Using manually provided VPN IP: $VPN_IP"
    fi
}

# ------------------------------------------------------------
# Choose directory
# ------------------------------------------------------------
choose_directory() {
    while true; do
        echo ""
        echo "Choose a directory to serve:"
        echo "1) Enter a directory path"
        echo "2) Use current directory: $(pwd)"
        read -p "Select option (1 or 2): " choice

        if [[ "$choice" == "2" ]]; then
            SERVE_DIR="$(pwd)"
            break
        elif [[ "$choice" == "1" ]]; then
            read -p "Enter full directory path: " input_dir
            if [[ -d "$input_dir" ]]; then
                SERVE_DIR="$input_dir"
                break
            else
                echo "[ERROR] Directory does not exist. Try again."
            fi
        else
            echo "[ERROR] Invalid option."
        fi
    done
    log "Serving directory: $SERVE_DIR"
}

# ------------------------------------------------------------
# HTTPS certificate generation
# ------------------------------------------------------------
generate_cert() {
    if [[ ! -f server.pem ]]; then
        echo "Generating self-signed certificate (server.pem)..."
        log "Generating self-signed certificate (server.pem)..."
        openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes \
            -subj "/CN=FileServer" >>"$LOGFILE" 2>&1
    fi
}

# ------------------------------------------------------------
# Start secure HTTP(S) server with upload + auth (background)
# ------------------------------------------------------------
start_secure_server() {
    cd "$SERVE_DIR"

    read -p "Enter port (default 8000): " PORT
    PORT=${PORT:-8000}

    read -p "Set username: " USERNAME
    read -s -p "Set password: " PASSWORD
    echo ""

    echo ""
    echo "Enable HTTPS?"
    echo "1) Yes (self-signed cert)"
    echo "2) No (HTTP only)"
    read -p "Choose: " https_choice

    if [[ "$https_choice" == "1" ]]; then
        USE_HTTPS=1
        generate_cert
    else
        USE_HTTPS=0
    fi

    cat > secure_server.py <<EOF
import os, base64, ssl
from http.server import SimpleHTTPRequestHandler, HTTPServer
import cgi

USERNAME = "$USERNAME"
PASSWORD = "$PASSWORD"
AUTH = base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode()

class Handler(SimpleHTTPRequestHandler):
    def do_AUTHHEAD(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Secure Area"')
        self.end_headers()

    def authenticate(self):
        auth_header = self.headers.get("Authorization")
        if auth_header is None:
            self.do_AUTHHEAD()
            return False
        if auth_header == "Basic " + AUTH:
            return True
        self.do_AUTHHEAD()
        return False

    def do_GET(self):
        if not self.authenticate():
            return
        super().do_GET()

    def do_POST(self):
        if not self.authenticate():
            return

        form = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ={'REQUEST_METHOD':'POST',
                     'CONTENT_TYPE':self.headers['Content-Type'],})

        if "file" in form:
            file_item = form["file"]
            if file_item.filename:
                with open(file_item.filename, "wb") as f:
                    f.write(file_item.file.read())
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"Upload successful")
                return

        self.send_response(400)
        self.end_headers()
        self.wfile.write(b"Upload failed")

os.chdir("$SERVE_DIR")
server = HTTPServer(("$VPN_IP", $PORT), Handler)

if $USE_HTTPS:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("server.pem")
    server.socket = context.wrap_socket(server.socket, server_side=True)

print("Serving on $VPN_IP:$PORT")
server.serve_forever()
EOF

    log "Starting secure server on $VPN_IP:$PORT (HTTPS: $USE_HTTPS)"
    if [[ "$USE_HTTPS" == "1" ]]; then
        URL="https://$VPN_IP:$PORT"
    else
        URL="http://$VPN_IP:$PORT"
    fi

    python3 secure_server.py >"$SERVER_LOGFILE" 2>&1 &
    SERVER_PID=$!
    echo $SERVER_PID > server.pid
    disown

    echo ""
    echo "Server started in background."
    echo "URL: $URL"
    echo "Server PID: $SERVER_PID"
    echo "Server log: $SERVER_LOGFILE"
    log "Server started in background. PID: $SERVER_PID, URL: $URL, log: $SERVER_LOGFILE"
}

# ------------------------------------------------------------
# MAIN
# ------------------------------------------------------------
log "=== VPN-Aware Secure File Server ==="

detect_vpn

if [[ -z "$VPN_IF" ]]; then
    echo "No VPN interface detected."
    start_vpn_safely
    detect_vpn
fi

get_vpn_ip
choose_directory
start_secure_server

echo ""
echo "You can keep using this terminal."
echo "To stop the server, run:  ./stop_vpn_file_server.sh"
echo "Logs:"
echo "  Server log: $SERVER_LOGFILE"
echo "  VPN log:    $VPN_LOGFILE"
echo "  Main log:   $LOGFILE"