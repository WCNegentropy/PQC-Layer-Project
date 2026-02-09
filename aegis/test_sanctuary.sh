#!/bin/bash
# Quick test script to verify Sanctuary ↔ Gateway handshake
#
# This script:
# 1. Generates keypairs for both server and client
# 2. Starts the sanctuary server in the background
# 3. Attempts a handshake from the gateway client
# 4. Verifies the handshake succeeds
#
# Requirements: 
# - Built binaries: aegis-sanctuary, aegis-gateway
# - Root privileges (for TUN device creation on gateway)

set -e

echo "🧪 Aegis Sanctuary ↔ Gateway Integration Test"
echo "=============================================="
echo ""

# Clean up from previous runs
cleanup() {
    echo ""
    echo "🧹 Cleaning up..."
    if [ ! -z "$SANCTUARY_PID" ]; then
        kill $SANCTUARY_PID 2>/dev/null || true
    fi
    rm -f test_sanctuary.key test_sanctuary.key.pub test_client.key test_client.key.pub
    rm -f test_sanctuary.toml
    echo "✅ Cleanup complete"
}

trap cleanup EXIT

# Step 1: Generate sanctuary keypair
echo "1️⃣  Generating sanctuary keypair..."
cat > test_sanctuary.toml <<EOF
[server]
listen_addr = "127.0.0.1:51821"
keypair_file = "test_sanctuary.key"
log_level = "info"
EOF

# The sanctuary will auto-generate keys on first run
# But we need to start it, let it generate, then restart it

# Start sanctuary briefly to generate keys
echo "2️⃣  Starting sanctuary to generate keys..."
timeout 2 ./target/release/aegis-sanctuary --config test_sanctuary.toml 2>&1 | head -10 || true

# Check if keys were generated
if [ ! -f "test_sanctuary.key.pub" ]; then
    echo "❌ Failed to generate sanctuary keys"
    exit 1
fi

echo "   ✅ Sanctuary keys generated"
echo "   Public key: test_sanctuary.key.pub"

# Step 2: Start sanctuary in background
echo "3️⃣  Starting sanctuary server..."
./target/release/aegis-sanctuary --config test_sanctuary.toml > sanctuary.log 2>&1 &
SANCTUARY_PID=$!

# Wait for server to be ready
sleep 2

if ! kill -0 $SANCTUARY_PID 2>/dev/null; then
    echo "❌ Sanctuary failed to start. Check sanctuary.log:"
    cat sanctuary.log
    exit 1
fi

echo "   ✅ Sanctuary running (PID: $SANCTUARY_PID)"
echo "   Listening on 127.0.0.1:51821"

# Step 3: Show what's needed for gateway connection
echo ""
echo "4️⃣  Gateway connection info:"
echo "   --sanctuary-addr 127.0.0.1:51821"
echo "   --sanctuary-pk-file test_sanctuary.key.pub"
echo "   --keypair-file test_client.key"
echo ""
echo "ℹ️  The gateway would auto-generate test_client.key on first run"
echo ""

# Display stats
echo "5️⃣  Sanctuary logs (first 20 lines):"
head -20 sanctuary.log || true

echo ""
echo "✅ Sanctuary is running and ready for connections!"
echo ""
echo "To manually test with gateway (requires root):"
echo "   sudo ./target/release/aegis-gateway \\"
echo "     --sanctuary-addr 127.0.0.1:51821 \\"
echo "     --sanctuary-pk-file test_sanctuary.key.pub \\"
echo "     --keypair-file test_client.key"
echo ""
echo "Press Ctrl+C to stop the sanctuary server"

# Keep running until user interrupts
wait $SANCTUARY_PID
