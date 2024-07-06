#!/bin/bash

# Function to read variables from the config file
read_config() {
    local config_file="$1"
    if [[ ! -f "$config_file" ]]; then
        echo "Configuration file not found!"
        exit 1
    fi
    source "$config_file"
}

# Path to the configuration file
config_file="configs.txt"

# Read the configuration file
read_config "$config_file"

# Construct the input sequence based on the test type
if [ "$test_type" -eq "1" ]; then
    # For network penetration test
    if [ "$hydra_scan_needed" -eq "1" ]; then
        # If Hydra crack scan is needed
        input_sequence="$test_type\n$target_ip_or_network\n$network_type\n$hydra_scan_needed\n$username_wordlist\n$password_wordlist\n$services_to_test\n$network_interface"
    else
        # If Hydra crack scan is not needed
        input_sequence="$test_type\n$target_ip_or_network\n$network_type\n$hydra_scan_needed"
    fi
elif [ "$test_type" -eq "2" ]; then
    # For domain penetration test
    input_sequence="$test_type\n$domain_url"
else
    echo "Invalid option. Please run the script again and choose 1 or 2."
    exit 1
fi

# Output the input sequence for debugging
echo -e "Running APTuSMO.py with the following input sequence:\n$input_sequence"

# Run the Python script with the constructed input sequence
sudo python3 APTuSMO.py <<EOF
$(echo -e $input_sequence)
EOF
