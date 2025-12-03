#!/bin/bash

set -e

echo "[+] Installing build dependencies..."
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r) make wget

# Install Go if not already installed
if ! command -v go &> /dev/null; then
    echo "[+] Installing Go..."
    GO_VERSION="1.25.4"
    ARCH=$(uname -m)

    if [ "$ARCH" = "x86_64" ]; then
        GO_ARCH="amd64"
    elif [ "$ARCH" = "aarch64" ]; then
        GO_ARCH="arm64"
    else
        echo "[!] Unsupported architecture: $ARCH"
        exit 1
    fi

    wget -q https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf go${GO_VERSION}.linux-${GO_ARCH}.tar.gz
    rm go${GO_VERSION}.linux-${GO_ARCH}.tar.gz

    # Add Go to PATH if not already present
    if ! grep -q "/usr/local/go/bin" ~/.bashrc; then
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
        echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
    fi

    export PATH=$PATH:/usr/local/go/bin
    echo "[+] Go ${GO_VERSION} installed successfully"
else
    GO_CURRENT=$(go version | awk '{print $3}' | sed 's/go//')
    echo "[+] Go already installed (version: ${GO_CURRENT})"
fi

# Install nfpm for package building
echo "[+] Installing nfpm..."
echo 'deb [trusted=yes] https://repo.goreleaser.com/apt/ /' | sudo tee /etc/apt/sources.list.d/goreleaser.list
sudo apt-get update
sudo apt-get install -y nfpm

echo "[+] Build setup complete!"
echo "[!] Please run: source ~/.bashrc (or restart your shell) to update PATH"