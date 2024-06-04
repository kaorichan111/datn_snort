#!/bin/bash

# Run the configure_cmake.sh script
./configure_cmake.sh

# Change directory to 'build'
cd build

# Run 'make'
make

# Install the built software using sudo
sudo make install
