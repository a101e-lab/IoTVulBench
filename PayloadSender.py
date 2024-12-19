import argparse
import logging
import yaml
import os
import socket
import sys
import time
import subprocess
from pathlib import Path
from typing import List, Dict, Optional, Tuple

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="[+] %(message)s",
)
logger = logging.getLogger("exploit-sender")

MAX_RETRIES = 5  # Maximum number of retries

class VulnerabilityExploit:
    def __init__(self, vuln_id: str):
        """Initialize the vulnerability exploit class"""
        self.vuln_id = vuln_id
        self.vuln_dir = Path("Vulnerabilities") / vuln_id
        self.detail_file = self.vuln_dir / "detail.yml"
        
        if not self.detail_file.exists():
            raise FileNotFoundError(f"detail.yml not found for vulnerability: {vuln_id}")
            
        self.detail = self._load_detail()
        self.environments = self.detail.get("environments", [])
        
    def _load_detail(self) -> Dict:
        """Load the detail.yml file"""
        with open(self.detail_file, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
            
    def get_available_payloads(self) -> List[Dict]:
        """Get all available payload information"""
        payloads = []
        for env in self.environments:
            payload_path = self.vuln_dir / env["payload"]
            if payload_path.exists():
                payloads.append({
                    "name": env["name"],
                    "payload_file": env["payload"],
                    "path": payload_path
                })
        return payloads
        
    def read_payload(self, payload_file: str) -> str:
        """Read the content of the payload file"""
        payload_path = self.vuln_dir / payload_file
        try:
            with open(payload_path, 'r') as f:
                content = f.read()
                # Ensure using CRLF line endings
                if '\r\n' not in content:
                    content = content.replace('\n', '\r\n')
                logger.debug(f"Payload content:\n{content.encode()}")
                return content
        except Exception as e:
            logger.error(f"Error reading payload file: {e}")
            raise

def check_service_availability(ip: str, port: int) -> bool:
    """Check if the service is available using curl"""
    command = f"curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 3 --max-time 5 {ip}:{port}"
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        status_code = result.stdout.strip()
        return bool(status_code and status_code != '000')
    except subprocess.CalledProcessError:
        return False

def handle_authentication(benchmark_name: str, ip: str, port: int, payload_path: str) -> bool:
    """Handle the authentication logic"""
    benchmark_dir = Path("iot-benchmark/Benchmark") / benchmark_name
    
    # Check for authentication configuration file
    config_path = benchmark_dir / "benchmark.yml"
    if not config_path.exists():
        logger.error(f"Benchmark configuration not found: {config_path}")
        return False
        
    with open(config_path) as f:
        config = yaml.safe_load(f)
    
    # Get authentication method configuration
    auth_config = config.get("authkeeper", {})
    auth_method = auth_config.get("method")
    script_path = auth_config.get("script_path")
    
    # If no authentication method or explicitly set to none, return success
    if not auth_method or auth_method == "none" or script_path == "none":
        logger.debug("No authentication required")
        return True
        
    # Confirm that auth directory and script exist
    auth_script_path = benchmark_dir / "auth" / f"{auth_method}.py"
    if not auth_script_path.exists():
        logger.error(f"Authentication script not found: {auth_script_path}")
        return False
        
    try:
        command = [
            "python3",
            str(auth_script_path),
            "--ip", ip,
            "--port", str(port)
        ]
        
        if auth_method == "update":
            command.extend(["--seed", str(payload_path)])
            
        logger.info(f"Executing authentication script: {' '.join(command)}")
        result = subprocess.run(command, capture_output=True, text=True)
        
        if result.returncode != 0:
            logger.error(f"Authentication failed: {result.stderr}")
            return False
            
        logger.info("Authentication successful")
        return True
        
    except Exception as e:
        logger.error(f"Error during authentication: {e}")
        return False

def send_tcp_request(payload: str, ip: str, port: int) -> Optional[str]:
    """Send a TCP request and get the response"""
    for _ in range(MAX_RETRIES):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                s.connect((ip, port))
                s.sendall(payload.encode())
                response = ""
                while True:
                    try:
                        part = s.recv(4096)
                        if not part:
                            break
                        response += part.decode()
                    except socket.timeout:
                        break
                return response
        except socket.error as e:
            logger.debug(f"Socket error: {e}")
            return None

def print_banner():
    ascii_art_lines = [            
        " _    _______ ______                    _      ______ _       ",
        "| |  (_______|____  \                  | |    / _____|_)      ",
        "| | ___  _    ____)  )_____ ____   ____| |__ ( (____  _       ",
        "| |/ _ \| |  |  __  (| ___ |  _ \ / ___)  _ \ \____ \| |      ",
        "| | |_| | |  | |__)  ) ____| | | ( (___| | | |_____) ) |_____ ",
        "|_|\___/|_|  |______/|_____)_| |_|\____)_| |_(______/|_______)",
        "--------------------------------------------------------------",
        "Developed by CyberUnicorn.                                    " 
    ]

    colors = [
        (255, 0, 0),
        (255, 255, 0),
        (0, 255, 0),
        (0, 255, 255),
        (0, 0, 255)
    ]

    num_chars = max(len(line) for line in ascii_art_lines)
    num_segments = len(colors) - 1
    segment_length = num_chars // num_segments

    def interpolate_color(start, end, factor):
        return int(start + (end - start) * factor)

    for line in ascii_art_lines:
        for i, char in enumerate(line):
            segment_index = min(i // segment_length, num_segments - 1)
            start_color = colors[segment_index]
            end_color = colors[segment_index + 1]
            factor = (i % segment_length) / segment_length
            r = interpolate_color(start_color[0], end_color[0], factor)
            g = interpolate_color(start_color[1], end_color[1], factor)
            b = interpolate_color(start_color[2], end_color[2], factor)
            color = f"\033[38;2;{r};{g};{b}m"
            print(f"{color}{char}", end="")
        print("\033[0m") 

def main():
    parser = argparse.ArgumentParser(description="Send vulnerability exploit payload")
    parser.add_argument('-v', '--vuln', required=True, help="Vulnerability ID (e.g., CVE-2024-46313)")
    parser.add_argument('-i', '--ip', default='127.0.0.1', help="Target IP address (default: 127.0.0.1)")
    parser.add_argument('-p', '--port', type=int, required=True, help="Target port")
    parser.add_argument('--debug', action='store_true', help="Enable debug logging")
    args = parser.parse_args()
    
    if args.debug:
        logger.setLevel(logging.DEBUG)
    
    print_banner()
    
    try:
        # Initialize vulnerability exploit
        exploit = VulnerabilityExploit(args.vuln)
        available_payloads = exploit.get_available_payloads()
        
        if not available_payloads:
            logger.error(f"No available payloads found for {args.vuln}")
            sys.exit(1)
            
        # First check if the target service is available
        if not check_service_availability(args.ip, args.port):
            logger.error("Target service is not accessible. Please make sure the emulation environment is running correctly.")
            sys.exit(1)
        else:
            logger.info("Target service is accessible.")
            
        # If multiple payloads exist, let the user choose
        if len(available_payloads) > 1:
            print("\nAvailable payloads:")
            for i, payload in enumerate(available_payloads, 1):
                print(f"{i}. {payload['payload_file']} (Environment: {payload['name']})")
            choice = int(input("\nSelect payload number: ")) - 1
            if choice < 0 or choice >= len(available_payloads):
                logger.error("Invalid selection")
                sys.exit(1)
            selected_payload = available_payloads[choice]
        else:
            selected_payload = available_payloads[0]
            
        logger.info(f"Using payload: {selected_payload['payload_file']}")
        
        # Handle authentication
        if not handle_authentication(selected_payload['name'], args.ip, args.port, selected_payload['path']):
            logger.error("Authentication failed. Cannot proceed with exploit.")
            sys.exit(1)
        
        # Read the payload
        payload_content = exploit.read_payload(selected_payload['payload_file'])
        logger.info(f"Sending payload to {args.ip}:{args.port}...")
        
        # Send the payload
        response = send_tcp_request(payload_content, args.ip, args.port)
        
        # Only display detailed response content in debug mode
        if args.debug and response:
            print("\n" + "="*60)
            logger.debug("Response received:")
            print(response)
            print("="*60)
        elif response:
            logger.info("Response received from target")
        else:
            logger.info("No response received from target")
        
        # Wait a moment to give the service time to respond
        time.sleep(2)
        
        # Check the service status again
        if not check_service_availability(args.ip, args.port):
            logger.info("Target service is no longer accessible - payload appears to be effective (service crashed)")
        else:
            logger.warning("Target service is still accessible - payload may not have been effective")
            
    except FileNotFoundError as e:
        logger.error(e)
    except ValueError as e:
        logger.error(f"Error: {e}")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        
if __name__ == "__main__":
    main()
