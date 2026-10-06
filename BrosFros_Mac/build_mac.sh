#!/bin/bash
echo "Building BrosFros for macOS..."
pip3 install pyinstaller
pyinstaller --noconsole --onefile --windowed --icon=logo.ico --add-data "logo.png:." brosfros.py
echo "Build complete. Check the 'dist' folder for your macOS app."
