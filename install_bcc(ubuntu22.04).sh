#!/bin/bash

set -e  # Exit immediately if a command exits with a non-zero status

echo "Updating package lists..."
sudo apt update
cd ~
echo "Installing required packages..."
sudo apt install -y zip bison build-essential cmake flex git libedit-dev \
    libllvm14 llvm-14-dev libclang-14-dev python3 zlib1g-dev libelf-dev \
    libfl-dev python3-setuptools liblzma-dev libdebuginfod-dev arping \
    netperf iperf libbpf-dev gcc-multilib clang llvm-14 python3-pip

echo "Cloning BCC repository..."
if [ ! -d "bcc" ]; then
    git clone https://github.com/iovisor/bcc.git
else
    echo "BCC repository already exists, skipping clone..."
fi

echo "Building BCC..."
mkdir -p bcc/build
cd bcc/build
cmake ..
make -j$(nproc)
sudo make install

echo "Building and installing Python bindings for BCC..."
cmake -DPYTHON_CMD=python3 ..
pushd src/python/
make -j$(nproc)
sudo make install
popd

echo "Installing BCC and Python dependencies..."
sudo apt install -y bcc
pip3 install --user bcc pyroute2
cd ~
echo "Installation completed successfully!"
