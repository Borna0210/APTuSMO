#!/bin/bash

# Check if a command exists
command_exists () {
    type "$1" &> /dev/null ;
}

# Remove and update Ruby
sudo apt-get remove -y ruby
sudo apt-get update
sudo apt-get upgrade -y

# Install necessary Python packages from requirements.txt
pip3 install -r requirements.txt

# Remove and reinstall theHarvester
sudo apt-get remove -y theharvester
sudo apt-get install -y theharvester

# Install metagoofil
sudo apt install -y metagoofil

# Install ClamAV
sudo apt-get install -y clamav clamav-daemon
if command_exists yum; then
    sudo yum install -y epel-release
    sudo yum install -y clamav clamav-update
fi
sudo freshclam

# Clone vulscan into Nmap scripts directory
if [ ! -d /usr/share/nmap/scripts/vulscan ]; then
    cd /usr/share/nmap/scripts/
    sudo git clone https://github.com/scipag/vulscan.git
fi

# Install PostgreSQL
sudo apt install -y postgresql postgresql-contrib

# Install WhatWeb and WPScan
sudo apt install -y whatweb
sudo apt install -y wpscan

sudo apt install -y metasploit-framework

# Decompress rockyou.txt.gz if it exists
if [ -f /usr/share/wordlists/rockyou.txt.gz ]; then
    sudo gunzip -f /usr/share/wordlists/rockyou.txt.gz
fi
