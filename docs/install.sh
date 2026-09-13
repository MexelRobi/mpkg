#!/bin/bash

set -e

# ============================================================
# mpkg Installer / Updater
# ============================================================

GITHUB_USER="MexelRobi"
GITHUB_REPO="mpkg"
GITHUB_BRANCH="main"

INSTALL_PATH="/usr/local/bin/mpkg"

REPO_RAW="https://githubusercontent.com/${GITHUB_USER}/${GITHUB_REPO}/${GITHUB_BRANCH}"

TEMP_FILE="/tmp/mpkg-install-$$"


# ============================================================
# Colors
# ============================================================

RESET='\033[0m'
BOLD='\033[1m'
CYAN='\033[1;36m'
GREEN='\033[1;32m'
RED='\033[1;31m'
YELLOW='\033[1;33m'


# ============================================================
# Functions
# ============================================================

error() {
    echo -e "${RED}ERROR: $1${RESET}"
    rm -f "$TEMP_FILE"
    exit 1
}

ask() {
    local question="$1"

    echo ""
    echo -e "${YELLOW}${BOLD}${question}${RESET}"
    
    # FIX: Liest Eingaben direkt vom Terminal, auch wenn das Skript per Pipe (| bash) läuft
    read -r -p "Continue? (y/N): " answer < /dev/tty

    case "$answer" in
        y|Y|yes|YES)
            return 0
            ;;
        *)
            echo "Cancelled."
            rm -f "$TEMP_FILE"
            exit 0
            ;;
    esac
}

cleanup() {
    rm -f "$TEMP_FILE"
}

trap cleanup EXIT


# ============================================================
# Header
# ============================================================

echo ""
echo -e "${CYAN}${BOLD}============================================================${RESET}"
echo -e "${CYAN}${BOLD} mpkg // Installer${RESET}"
echo -e "${CYAN}${BOLD}============================================================${RESET}"
echo ""


# ============================================================
# Dependencies
# ============================================================

command -v curl >/dev/null 2>&1 || \
    error "curl is required."

command -v python3 >/dev/null 2>&1 || \
    error "python3 is required."


# ============================================================
# Find latest version
# ============================================================

echo "Checking available mpkg versions..."

RELEASE_INDEX=$(curl -fsSL \
    "https://github.com/${GITHUB_USER}/${GITHUB_REPO}/contents/release" \
) || error "Could not access the GitHub repository."


LATEST_VERSION=$(echo "$RELEASE_INDEX" |
    python3 -c '
import json
import sys
import re

try:
    data = json.load(sys.stdin)

    versions = []

    for item in data:
        if item.get("type") != "dir":
            continue

        name = item.get("name", "")

        if re.fullmatch(r"\d+(?:\.\d+)*", name):
            versions.append(name)

    def version_key(v):
        return tuple(int(x) for x in v.split("."))

    if not versions:
        sys.exit(1)

    print(max(versions, key=version_key))

except Exception:
    sys.exit(1)
'
) || error "No valid mpkg version was found."


BINARY_URL="${REPO_RAW}/release/${LATEST_VERSION}/mpkg"


# ============================================================
# Detect existing installation
# ============================================================

echo ""
echo "Latest version: ${LATEST_VERSION}"
echo "Download:       ${BINARY_URL}"
echo "Destination:    ${INSTALL_PATH}"
echo ""

MODE="install"

if [ -f "$INSTALL_PATH" ]; then

    MODE="update"

    echo -e "${YELLOW}${BOLD}Existing mpkg installation detected.${RESET}"
    echo ""

    # Try to determine installed version.
    INSTALLED_VERSION="unknown"

    if "$INSTALL_PATH" --version >/dev/null 2>&1; then
        INSTALLED_VERSION=$(
            "$INSTALL_PATH" --version 2>/dev/null |
            head -n 1
        )
    fi

    echo "Installed version: ${INSTALLED_VERSION}"
    echo "Available version: ${LATEST_VERSION}"
    echo ""

    ask "mpkg is already installed. Update it?"

else

    echo -e "${GREEN}mpkg is not installed.${RESET}"
    echo ""

    ask "Install mpkg?"

fi


# ============================================================
# Download binary
# ============================================================

echo ""
echo "Downloading mpkg ${LATEST_VERSION}..."

curl \
    -fL \
    --progress-bar \
    "$BINARY_URL" \
    -o "$TEMP_FILE" \
    || error "Failed to download mpkg."


# ============================================================
# Basic validation
# ============================================================

if [ ! -s "$TEMP_FILE" ]; then
    error "Downloaded binary is empty."
fi


# Make temporary binary executable.
chmod +x "$TEMP_FILE"


# FIX: macOS Quarantine vorab temporär für die Validierung entfernen.
# Unsignierte Binärdateien blockieren sonst den "--version"-Check.
xattr -d com.apple.quarantine "$TEMP_FILE" 2>/dev/null || true

# Check that it is actually executable.
if ! "$TEMP_FILE" --version >/dev/null 2>&1; then

    echo ""
    echo -e "${YELLOW}Warning: downloaded binary could not be executed with --version.${RESET}"
    echo ""

    ask "The downloaded file could not be verified. Install it anyway?"

fi


# ============================================================
# Final confirmation
# ============================================================

echo ""
echo -e "${CYAN}${BOLD}Installation Preview${RESET}"
echo ""
echo "Action:       ${MODE}"
echo "Version:      ${LATEST_VERSION}"
echo "Source:       ${BINARY_URL}"
echo "Destination:  ${INSTALL_PATH}"
echo ""

ask "Perform this change?"


# ============================================================
# Install
# ============================================================

echo ""
echo "Installing mpkg..."

sudo mkdir -p /usr/local/bin

sudo cp "$TEMP_FILE" "$INSTALL_PATH"

sudo chmod 755 "$INSTALL_PATH"

# Remove macOS quarantine if present.
sudo xattr -d com.apple.quarantine \
    "$INSTALL_PATH" \
    2>/dev/null || true


# ============================================================
# Verify
# ============================================================

if [ ! -x "$INSTALL_PATH" ]; then
    error "mpkg was copied but is not executable."
fi


# ============================================================
# Finished
# ============================================================

echo ""

if [ "$MODE" = "update" ]; then

    echo -e "${GREEN}${BOLD}SUCCESS: mpkg updated to ${LATEST_VERSION}.${RESET}"

else

    echo -e "${GREEN}${BOLD}SUCCESS: mpkg ${LATEST_VERSION} installed.${RESET}"

fi

echo ""
echo "Installed at:"
echo "  ${INSTALL_PATH}"
echo ""
