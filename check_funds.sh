#!/bin/bash

# Simple script to check for funds at a specific address using the Electrum backend
# This script will connect to the running LND instance and check for funds

echo "Checking for funds at address: tb1pv6wu2k2pls6eclghkyv4rehmv8pf93kj5x7pejzak3gzd3a9778shsgnq0"

# Check if LND is running
if ! pgrep -f "lnd-debug.*electrum" > /dev/null; then
    echo "LND is not running. Please start LND first."
    exit 1
fi

# Check the current balance
echo "Current wallet balance:"
./lncli-debug --macaroonpath /Users/satoshi/.lnd-electrum-testnet/chain/bitcoin/testnet/admin.macaroon walletbalance

echo ""
echo "Checking for unspent outputs:"
./lncli-debug --macaroonpath /Users/satoshi/.lnd-electrum-testnet/chain/bitcoin/testnet/admin.macaroon listunspent

echo ""
echo "Checking for chain transactions:"
./lncli-debug --macaroonpath /Users/satoshi/.lnd-electrum-testnet/chain/bitcoin/testnet/admin.macaroon listchaintxns

echo ""
echo "Fund check completed."

