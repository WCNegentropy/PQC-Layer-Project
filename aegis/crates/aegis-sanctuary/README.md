# Aegis Sanctuary Server

The **Sanctuary** is the server-side component of the Aegis PQ-WireGuard tunnel system. It accepts quantum-resistant encrypted connections from Aegis Gateway clients and provides secure internet access.

## Architecture

```
Client (Gateway) ──PQ-WG/UDP──▶ Sanctuary ──NAT──▶ Internet
   (ML-KEM-768 + X25519)          (Server)
```

## Features

- **Post-Quantum Handshake**: Uses hybrid KEM (ML-KEM-768 + X25519) for quantum-resistant key exchange
- **ChaCha20-Poly1305 Transport**: Fast authenticated encryption for tunnel data
- **Anti-Replay Protection**: RFC 6479 sliding-window bitmap prevents replay attacks
- **Multi-Client Support**: Handles multiple concurrent client sessions
- **Authorized Peers**: Optional allowlist of client public keys for access control
- **Docker Ready**: Includes Dockerfile and docker-compose for easy deployment

## Quick Start

### 1. Build from Source

```bash
cd aegis
cargo build --release -p aegis-sanctuary
```

### 2. Generate Server Keypair

The server will automatically generate a keypair on first run, but you can also do it explicitly:

```bash
# The keygen happens automatically, or use the sanctuary binary:
./target/release/aegis-sanctuary --config sanctuary.toml
# This will create sanctuary.key and sanctuary.key.pub
```

### 3. Configure

Edit `sanctuary.toml`:

```toml
[server]
listen_addr = "0.0.0.0:51820"
keypair_file = "sanctuary.key"
log_level = "info"

# Optional: restrict to authorized clients only
# authorized_peers_dir = "/etc/aegis/peers"

# Simple per-peer handshake flood protection
handshake_rate_limit_window_secs = 10
handshake_rate_limit_max_attempts = 8
```

### 4. Run

```bash
./target/release/aegis-sanctuary --config sanctuary.toml
```

## Docker Deployment

### Using docker-compose (Recommended)

```bash
# Build and start
docker-compose -f docker-compose.sanctuary.yml up -d

# View logs
docker-compose -f docker-compose.sanctuary.yml logs -f sanctuary

# Stop
docker-compose -f docker-compose.sanctuary.yml down
```

### Using Docker directly

```bash
# Build image
docker build -t aegis-sanctuary:v0.1 -f Dockerfile.sanctuary .

# Run container
docker run -d \
  --name aegis-sanctuary \
  -p 51820:51820/udp \
  -v $(pwd)/sanctuary.toml:/etc/aegis/sanctuary.toml:ro \
  -v $(pwd)/sanctuary-data:/home/aegis/.aegis:rw \
  aegis-sanctuary:v0.1
```

## Client Configuration

On the client side (Aegis Gateway), you need:

1. **Sanctuary's public key** (`sanctuary.key.pub`)
2. **Sanctuary's address** (IP:port)

Gateway configuration:

```bash
aegis-gateway \
  --sanctuary-addr <sanctuary-ip>:51820 \
  --sanctuary-pk-file sanctuary.key.pub \
  --keypair-file client.key
```

## Authorized Peers (Optional)

To restrict access to specific clients:

1. Create a directory for peer keys:
   ```bash
   mkdir -p /etc/aegis/peers
   ```

2. Copy client public keys into the directory:
   ```bash
   cp client1.key.pub /etc/aegis/peers/
   cp client2.key.pub /etc/aegis/peers/
   ```

3. Update `sanctuary.toml`:
   ```toml
   [server]
   authorized_peers_dir = "/etc/aegis/peers"
   ```

4. Restart the sanctuary

## Monitoring

The sanctuary logs statistics every 30 seconds:

```
📊 Server Stats: handshakes=5 | rate_limited=0 | unauthorized=0 | encrypted=1234 | decrypted=1234 | replay_rejected=0 | rx_bytes=65536 | tx_bytes=65536
```

Monitor these metrics to:
- Verify client connections (`handshakes`)
- Watch for abusive peers (`rate_limited`, `unauthorized`)
- Check tunnel traffic (`encrypted`, `decrypted`)
- Detect replay attacks (`replay_rejected`)

## Security Considerations

### v0 Limitations

⚠️ **Version 0 is for testing and demonstration only**. Production deployment requires:

1. **NAT/Forwarding**: v0 uses echo-back; real deployment needs TUN/NAT setup
2. **Rate Limiting**: Add per-client bandwidth limits
3. **Abuse Prevention**: Implement connection rate limits and DDoS protection
4. **Key Rotation**: Add support for periodic rekeying
5. **Monitoring**: Deploy metrics/alerting (Prometheus, Grafana)

### Firewall Configuration

Open UDP port 51820:

```bash
# UFW
sudo ufw allow 51820/udp

# iptables
sudo iptables -A INPUT -p udp --dport 51820 -j ACCEPT
```

### Key Management

- **Keep `sanctuary.key` secure**: This is the server's private key. Use file permissions `0600`.
- **Distribute `sanctuary.key.pub` to clients**: The public key can be shared freely.
- **Rotate keys periodically**: Generate new keypairs and redistribute to clients.

## Troubleshooting

### Server won't start

**Check port availability:**
```bash
sudo lsof -i :51820
```

**Check permissions:**
```bash
ls -l sanctuary.key
# Should show: -rw------- (0600)
```

### Clients can't connect

**Check firewall:**
```bash
sudo iptables -L -n | grep 51820
```

**Verify server is listening:**
```bash
sudo netstat -ulnp | grep 51820
```

**Check logs:**
```bash
# If using docker-compose
docker-compose -f docker-compose.sanctuary.yml logs sanctuary

# If running directly
# (logs appear in stdout/stderr)
```

### High replay_rejected count

This indicates:
- A client is replaying old packets (possible attack)
- Clock skew between client and server
- Network issues causing packet duplication

Investigate the source and consider blocking the offending client.

## Performance Tuning

For high-throughput deployments:

1. **Increase UDP buffer sizes:**
   ```bash
   sysctl -w net.core.rmem_max=26214400
   sysctl -w net.core.wmem_max=26214400
   ```

2. **Use multiple CPU cores:** The sanctuary is async/multi-threaded and will use available cores.

3. **SSD for keypair storage:** Fast disk I/O helps with startup time.

## Contributing

See the main [project README](../../README.md) for contribution guidelines.

## License

MIT OR Apache-2.0 (see project root)
