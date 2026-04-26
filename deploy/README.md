# IDPS Deployment Guide

This directory contains the files needed to deploy IDPS as a systemd service.

## Files

- `nids.service` — systemd service unit file
- `nids.conf` — JSON configuration file

## Installation

1. Copy the service file to systemd directory:
   ```bash
   sudo cp deploy/nids.service /etc/systemd/system/
   ```

2. Copy the configuration file:
   ```bash
   sudo mkdir -p /etc/nids
   sudo cp deploy/nids.conf /etc/nids/nids.conf
   ```

3. Copy the rules file (or create your own):
   ```bash
   sudo cp rules.txt /etc/nids/rules.txt
   ```

4. Reload systemd and enable the service:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable nids
   ```

5. Start the service:
   ```bash
   sudo systemctl start nids
   ```

## Configuration File Format

The configuration file (`nids.conf`) uses JSON format:

```json
{
    "interface": "eth0",
    "rules_file": "/etc/nids/rules.txt",
    "event_log": "/var/log/nids/events.json",
    "use_syslog": true,
    "metrics_port": 8080,
    "ddos_threshold": 10000,
    "capture_cpu": -1
}
```

### Configuration Options

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `interface` | string | *(required)* | Network interface to attach XDP to, e.g. `eth0` |
| `rules_file` | string | *(required)* | Path to the rules file |
| `event_log` | string | *(required)* | Path to JSON event log output |
| `use_syslog` | boolean | `true` | Enable syslog logging |
| `metrics_port` | integer | `8080` | Port for Prometheus metrics server |
| `ddos_threshold` | integer | `10000` | DDoS detection threshold (packets per window) |
| `capture_cpu` | integer | `-1` | CPU core for capture thread (-1 = any) |

## Managing the Service

### Start the service
```bash
sudo systemctl start nids
```

### Stop the service
```bash
sudo systemctl stop nids
```

### Restart the service
```bash
sudo systemctl restart nids
```

### Check service status
```bash
sudo systemctl status nids
```

### View logs
```bash
sudo journalctl -u nids -f
```

## Metrics

Prometheus metrics are exposed on the configured `metrics_port` (default: 8080).

Metrics available:
- `nids_packets_total` — Total packets processed
- `nids_events_total` — Total events by type
- `nids_drops_total` — Total dropped packets
- `nids_rules_matched_total` — Total rule matches

Access metrics:
```bash
curl http://localhost:8080/metrics
```

## Signal Handling

The service handles the following signals for graceful shutdown:
- `SIGINT` (Ctrl+C) — Clean shutdown
- `SIGTERM` — Clean shutdown (systemd default)
- `SIGUSR1` — Hot reload rules

## Requirements

- Linux kernel with XDP support
- `CAP_NET_ADMIN`, `CAP_NET_RAW`, `CAP_SYS_ADMIN` capabilities (or root)
- The network interface must be up and not managed by another service
