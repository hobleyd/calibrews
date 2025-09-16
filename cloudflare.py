#!/usr/bin/env python3
"""
Cloudflare DDNS and Tunnel Management Script

This script provides functionality to:
1. Update DNS records dynamically (DDNS) using Cloudflare API
2. Manage Cloudflare Tunnels for secure access to home services
3. Monitor and maintain tunnel connections

Prerequisites:
- pip install requests
- pip install pyyaml (optional, for config files)
- Cloudflare account with API token
- Domain managed by Cloudflare
"""

import json
import time
import subprocess
import requests
import logging
from typing import Optional, Dict, Any
from pathlib import Path

# Configure logging
logging.basicConfig(
level=logging.INFO,
format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class CloudflareDDNS:
"""Handles dynamic DNS updates via Cloudflare API"""

def __init__(self, api_token: str, zone_id: str):
self.api_token = api_token
self.zone_id = zone_id
self.base_url = "https://api.cloudflare.com/client/v4"
self.headers = {
"Authorization": f"Bearer {api_token}",
"Content-Type": "application/json"
}

def get_public_ip(self) -> Optional[str]:
"""Get current public IP address"""
try:
response = requests.get("https://api.ipify.org", timeout=10)
return response.text.strip()
except Exception as e:
logger.error(f"Failed to get public IP: {e}")
return None

def get_dns_record(self, record_name: str) -> Optional[Dict[str, Any]]:
"""Get existing DNS record details"""
try:
url = f"{self.base_url}/zones/{self.zone_id}/dns_records"
params = {"name": record_name, "type": "A"}

response = requests.get(url, headers=self.headers, params=params)
response.raise_for_status()

data = response.json()
if data["result"]:
return data["result"][0]
return None
except Exception as e:
logger.error(f"Failed to get DNS record: {e}")
return None

def create_dns_record(self, record_name: str, ip_address: str) -> bool:
"""Create new DNS A record"""
try:
url = f"{self.base_url}/zones/{self.zone_id}/dns_records"
data = {
"type": "A",
"name": record_name,
"content": ip_address,
"ttl": 300  # 5 minutes
}

response = requests.post(url, headers=self.headers, json=data)
response.raise_for_status()

logger.info(f"Created DNS record: {record_name} -> {ip_address}")
return True
except Exception as e:
logger.error(f"Failed to create DNS record: {e}")
return False

def update_dns_record(self, record_id: str, record_name: str, ip_address: str) -> bool:
"""Update existing DNS A record"""
try:
url = f"{self.base_url}/zones/{self.zone_id}/dns_records/{record_id}"
data = {
"type": "A",
"name": record_name,
"content": ip_address,
"ttl": 300
}

response = requests.put(url, headers=self.headers, json=data)
response.raise_for_status()

logger.info(f"Updated DNS record: {record_name} -> {ip_address}")
return True
except Exception as e:
logger.error(f"Failed to update DNS record: {e}")
return False

def update_ddns(self, record_name: str) -> bool:
"""Main DDNS update function"""
current_ip = self.get_public_ip()
if not current_ip:
return False

existing_record = self.get_dns_record(record_name)

if existing_record:
if existing_record["content"] != current_ip:
return self.update_dns_record(
existing_record["id"],
record_name,
current_ip
)
else:
logger.info(f"DNS record {record_name} already up to date")
return True
else:
return self.create_dns_record(record_name, current_ip)

class CloudflareTunnel:
"""Manages Cloudflare Tunnel operations"""

def __init__(self, tunnel_name: str, config_path: str = "~/.cloudflared"):
self.tunnel_name = tunnel_name
self.config_path = Path(config_path).expanduser()
self.config_file = self.config_path / "config.yml"
self.tunnel_process = None

def create_tunnel(self) -> bool:
"""Create a new Cloudflare tunnel"""
try:
cmd = ["cloudflared", "tunnel", "create", self.tunnel_name]
result = subprocess.run(cmd, capture_output=True, text=True)

if result.returncode == 0:
logger.info(f"Created tunnel: {self.tunnel_name}")
return True
else:
logger.error(f"Failed to create tunnel: {result.stderr}")
return False
except Exception as e:
logger.error(f"Error creating tunnel: {e}")
return False

def list_tunnels(self) -> list:
"""List existing tunnels"""
try:
cmd = ["cloudflared", "tunnel", "list"]
result = subprocess.run(cmd, capture_output=True, text=True)

if result.returncode == 0:
return result.stdout.split('\n')[1:-1]  # Skip header and empty line
return []
except Exception as e:
logger.error(f"Error listing tunnels: {e}")
return []

def create_config_file(self, tunnel_id: str, services: Dict[str, str]):
"""Create tunnel configuration file"""
config_content = f"""tunnel: {tunnel_id}
credentials-file: {self.config_path}/{tunnel_id}.json

ingress:
"""

for hostname, service in services.items():
config_content += f"  - hostname: {hostname}\n"
config_content += f"    service: {service}\n"

# Catch-all rule (required)
config_content += "  - service: http_status:404\n"

self.config_path.mkdir(exist_ok=True)
with open(self.config_file, 'w') as f:
f.write(config_content)

logger.info(f"Created config file: {self.config_file}")

def route_dns(self, hostname: str, tunnel_id: str) -> bool:
"""Create DNS CNAME record pointing to tunnel"""
try:
cmd = [
"cloudflared", "tunnel", "route", "dns",
tunnel_id, hostname
]
result = subprocess.run(cmd, capture_output=True, text=True)

if result.returncode == 0:
logger.info(f"Created DNS route: {hostname}")
return True
else:
logger.error(f"Failed to create DNS route: {result.stderr}")
return False
except Exception as e:
logger.error(f"Error creating DNS route: {e}")
return False

def start_tunnel(self) -> bool:
"""Start the tunnel daemon"""
try:
cmd = ["cloudflared", "tunnel", "--config", str(self.config_file), "run"]
self.tunnel_process = subprocess.Popen(
cmd,
stdout=subprocess.PIPE,
stderr=subprocess.PIPE
)

logger.info(f"Started tunnel: {self.tunnel_name}")
return True
except Exception as e:
logger.error(f"Error starting tunnel: {e}")
return False

def stop_tunnel(self):
"""Stop the tunnel daemon"""
if self.tunnel_process:
self.tunnel_process.terminate()
self.tunnel_process.wait()
logger.info(f"Stopped tunnel: {self.tunnel_name}")

class HomeServerManager:
"""Main class to manage DDNS and tunnel operations"""

def __init__(self, config: Dict[str, Any]):
self.config = config
self.ddns = CloudflareDDNS(
config['cloudflare']['api_token'],
config['cloudflare']['zone_id']
)
self.tunnel = CloudflareTunnel(config['tunnel']['name'])

def setup_tunnel(self):
"""Complete tunnel setup process"""
tunnel_name = self.config['tunnel']['name']
services = self.config['tunnel']['services']

# Create tunnel
self.tunnel.create_tunnel()

# Get tunnel ID (you'll need to extract this from the output)
# For now, using a placeholder - in practice, parse the output
tunnel_id = "your-tunnel-id-here"  # Replace with actual tunnel ID

# Create config file
self.tunnel.create_config_file(tunnel_id, services)

# Route DNS for each service
for hostname in services.keys():
self.tunnel.route_dns(hostname, tunnel_id)

def run_ddns_loop(self, interval: int = 300):
"""Run DDNS update loop"""
record_name = self.config['ddns']['record_name']

while True:
try:
self.ddns.update_ddns(record_name)
time.sleep(interval)
except KeyboardInterrupt:
logger.info("DDNS loop stopped by user")
break
except Exception as e:
logger.error(f"Error in DDNS loop: {e}")
time.sleep(60)  # Wait before retrying

def start_services(self):
"""Start both DDNS and tunnel services"""
# Start tunnel
self.tunnel.start_tunnel()

# Run DDNS updates
try:
self.run_ddns_loop()
finally:
self.tunnel.stop_tunnel()

# Example configuration
EXAMPLE_CONFIG = {
"cloudflare": {
"api_token": "your-cloudflare-api-token",
"zone_id": "your-zone-id"
},
"ddns": {
"record_name": "home.yourdomain.com"
},
"tunnel": {
"name": "home-server-tunnel",
"services": {
"app.yourdomain.com": "http://localhost:8080",
"api.yourdomain.com": "http://localhost:3000",
"ssh.yourdomain.com": "ssh://localhost:22"
}
}
}

def main():
"""Main function to run the service"""
# Load configuration
config_file = Path("config.json")

if config_file.exists():
with open(config_file) as f:
config = json.load(f)
else:
# Create example config file
with open(config_file, 'w') as f:
json.dump(EXAMPLE_CONFIG, f, indent=2)

print(f"Created example config file: {config_file}")
print("Please edit the configuration file and run again.")
return

# Initialize manager
manager = HomeServerManager(config)

# Setup tunnel (run once)
print("Setting up tunnel...")
manager.setup_tunnel()

# Start services
print("Starting DDNS and tunnel services...")
manager.start_services()

if __name__ == "__main__":
main()