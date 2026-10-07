#!/bin/bash
# Script to generate a proper RSA private key for JWT signing
# Usage: ./scripts/generate-key.sh

KEY_DIR="src/main/resources/keys"
KEY_FILE="$KEY_DIR/private-key.pem"

# Create keys directory if it doesn't exist
mkdir -p "$KEY_DIR"

# Generate a 2048-bit RSA key pair
openssl genpkey -algorithm RSA \
    -out "$KEY_FILE" \
    -pkeyopt rsa_keygen_bits:2048

echo "Generated RSA private key at: $KEY_FILE"
echo "To extract the public key for ServiceNow configuration:"
echo "openssl pkey -in $KEY_FILE -pubout -out ${KEY_FILE%.pem}-public.pem"
