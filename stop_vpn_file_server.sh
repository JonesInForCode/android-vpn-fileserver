#!/bin/bash

echo "=== Stopping VPN-Aware File Server ==="

# Stop server
if [[ -f server.pid ]]; then
    SERVER_PID=$(cat server.pid)
    if kill "$SERVER_PID" 2>/dev/null; then
        echo "Stopped file server (PID $SERVER_PID)"
    else
        echo "File server not running or already stopped"
    fi
    rm -f server.pid
else
    echo "No server.pid file found — server may not be running"
fi

# Stop VPN
if [[ -f vpn.pid ]]; then
    VPN_PID=$(cat vpn.pid)
    if kill "$VPN_PID" 2>/dev/null; then
        echo "Stopped VPN process (PID $VPN_PID)"
    else
        echo "VPN process not running or already stopped"
    fi
    rm -f vpn.pid
else
    echo "No vpn.pid file found — VPN may not be running"
fi

echo "=== Shutdown complete ==="