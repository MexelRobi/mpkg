#!/bin/bash

# Alte Build-Ordner entfernen
rm -rf build dist

# PyInstaller ausführen, um eine einzelne Binärdatei zu erstellen
pyinstaller --onefile mpkg.py

# Status überprüfen
if [ $? -eq 0 ]; then
    echo "Successfully built the executable."
else
    echo "Error occurred during the build process."
    exit 1
fi
