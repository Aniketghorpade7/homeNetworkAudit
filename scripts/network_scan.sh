#!/bin/bash

# Checks if nmap is present or not if not then installs it
if pacman -Qi nmap >/dev/null 2>&1; then 
    echo "Namp is present"
else
    echo "Installing Nmap"
    sudo pacman -S --noconfirm nmap
fi

echo "Finding the SUBNET now..."

# Finds SUBNET to scan and stores it inside the variable for later use
SUBNET=$(ip route | awk '/default/ {print $3}' | cut -d. -f1-3).0/24

#if SUBNET is sot found then stops the excution
if [[ -n "$SUBNET" ]]; then
    echo "SUBNET found $SUBNET"
else    
    echo "No default SUBNET found"
    exit 1
fi

#sacns the SUBNET and stores the output into a file
nmap -sV --top-ports 20 $SUBNET > ../scans/output.txt