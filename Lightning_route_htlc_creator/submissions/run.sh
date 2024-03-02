#!/bin/bash
# Check if three arguments are provided
if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <input_file_path> <payment_request_hex> <current_block_height>"
    exit 1
fi

# Assign arguments to variables
input_file_path="$1"
payment_request_hex="$2"
current_block_height="$3"

# Please fill in the version of the programming language you used here to help us with debugging if we run into problems!
# programming language used = rust
# rustc --version => rustc 1.74.0 (79e9716c9 2023-11-13)
version="rustc 1.74.0 (79e9716c9 2023-11-13)"

# Check if the 'version' variable is not null
if [ -z "$version" ]; then
    echo "Please fill in the version of the programming language you used."
    exit 1
fi

# Your run command here:

# RUST
cargo run --manifest-path ./rust/Cargo.toml -- "$input_file_path" "$payment_request_hex" "$current_block_height"