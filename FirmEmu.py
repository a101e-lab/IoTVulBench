import argparse
import logging
import json
import time 
import subprocess
import random
import string
import yaml
import os
import sys
from pathlib import Path
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="[+] %(message)s",
)
logger = logging.getLogger("vulnerability-emulator")

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

class Spinner:
    def __init__(self):
        self.frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        self.start_time = datetime.now()
        self.frame_index = 0
        
    def spin(self, message):
        current_time = datetime.now()
        elapsed = current_time - self.start_time
        elapsed_seconds = elapsed.total_seconds()
        minutes = int(elapsed_seconds // 60)
        seconds = int(elapsed_seconds % 60)
        
        frame = self.frames[self.frame_index]
        self.frame_index = (self.frame_index + 1) % len(self.frames)
        
        sys.stdout.write(f'\r{frame} {message} ({minutes:02d}:{seconds:02d})')
        sys.stdout.flush()

def get_environment_info(vuln_id):
    """Get environment information from detail.yml."""
    detail_path = Path("Vulnerabilities") / vuln_id / "detail.yml"
    
    if not detail_path.exists():
        raise FileNotFoundError(f"detail.yml not found for vulnerability: {vuln_id}")
        
    with open(detail_path, 'r', encoding='utf-8') as file:
        detail = yaml.safe_load(file)
        
    if not detail.get('environments'):
        raise ValueError(f"No environments defined in detail.yml for {vuln_id}")
        
    # Get the first environment by default
    env = detail['environments'][0]
    return env['name']

def find_benchmark_path(env_name):
    """Find the corresponding benchmark path for an environment name."""
    benchmark_path = Path("iot-benchmark/Benchmark") / env_name / "benchmark.yml"
    
    if not benchmark_path.exists():
        raise FileNotFoundError(f"benchmark.yml not found for environment: {env_name}")
        
    return str(benchmark_path)

def run_docker_command(command, log_message):
    """Runs a Docker command and handles errors."""
    logger.info(f"Executing command: {' '.join(command)}")
    try:
        subprocess.run(command, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"Error occurred during {log_message}: {e}")
        raise e

def emulate(benchmark_path):
    """Emulate the vulnerability environment using the benchmark configuration."""
    config_file = Path(benchmark_path).resolve()
    with open(config_file, 'r', encoding='utf-8') as file:
        config = yaml.safe_load(file)

    image_tag = config["info"]["serial"].lower()
    context = (config_file.parent / config["emulation"]["context"]).resolve()
    
    # Generate a random container name
    container_name = f"{image_tag}_{''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(6))}"
    
    # Build Docker image
    build_command = [
        "docker", "build",
        "-f", str(context / "Dockerfile"),
        "--tag", image_tag,
        str(context)
    ]
    
    try:
        run_docker_command(build_command, "build")
        
        # Run Docker container
        run_command = [
            "docker", "run", "-it", "-d",
            "-e", f"REMOTE_IP={config['emulation']['ip']}",
            "-e", f"REMOTE_PORT={config['emulation']['port']}",
            "--privileged", "-P",
            "--name", container_name,
            image_tag
        ]
        
        run_docker_command(run_command, "run")
        
        # Get container port mapping
        inspect_command = ["docker", "inspect", container_name]
        inspect_result = subprocess.run(inspect_command, check=True, capture_output=True, text=True)
        ports = json.loads(inspect_result.stdout)[0]['NetworkSettings']['Ports']
        
        host_port = next(
            int(mapping['HostPort'])
            for port_mappings in ports.values()
            for mapping in port_mappings
            if mapping['HostIp'] == '0.0.0.0'
        )
        
        success = verify_service(host_port, container_name, image_tag)
        if success:
            print_cleanup_instructions(container_name, image_tag)
        return success
        
    except Exception as e:
        logger.error(f"Emulation failed: {e}")
        cleanup_container(container_name)
        return False

def print_cleanup_instructions(container_name, image_tag):
    """Print instructions for cleaning up container and image."""
    print("\nTo clean up the environment, you can run:")
    print(f"\n# Remove only the container:")
    print(f"\n    docker rm -f {container_name}")
    print(f"\n# Remove both container and image:")
    print(f"\n    docker rm -f {container_name} && docker rmi {image_tag}")
    print("\n")

def verify_service(port, container_name, image_tag, timeout_minutes=5):
    """Verify if the emulated service is running properly."""
    import requests
    
    spinner = Spinner()
    message = "Waiting for service to start"
    start_time = time.time()
    timeout_seconds = timeout_minutes * 60
    
    while (time.time() - start_time) < timeout_seconds:
        try:
            response = requests.get(f"http://0.0.0.0:{port}", timeout=5)
            if response.status_code:
                print()  # New line after spinner
                logger.info(f"Service successfully started at http://0.0.0.0:{port}")
                return True
        except requests.exceptions.RequestException:
            spinner.spin(message)
            time.sleep(0.1)
    
    print()  # New line after spinner
    logger.error(f"Service failed to start: Timeout after {timeout_minutes} minutes")
    cleanup_container(container_name)
    return False

def cleanup_container(container_name):
    """Clean up Docker container if it exists."""
    try:
        subprocess.run(["docker", "rm", "-f", container_name], 
                      check=True, capture_output=True)
    except subprocess.CalledProcessError:
        pass

def main():
    parser = argparse.ArgumentParser(description="IoT Vulnerability Emulator")
    parser.add_argument('-v', '--vuln', required=True, 
                       help="Vulnerability ID (e.g., CVE-2024-46313)")
    parser.add_argument('--debug', action='store_true',
                       help="Enable debug logging")
    
    args = parser.parse_args()
    
    if args.debug:
        logger.setLevel(logging.DEBUG)
    
    print_banner()
    
    try:
        # Get environment name from detail.yml
        env_name = get_environment_info(args.vuln)
        logger.info(f"Found environment: {env_name}")
        
        # Find benchmark path
        benchmark_path = find_benchmark_path(env_name)
        logger.info(f"Found benchmark configuration: {benchmark_path}")
        
        # Start emulation
        emulate(benchmark_path)
    except FileNotFoundError as e:
        logger.error(e)
    except ValueError as e:
        logger.error(e)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")

if __name__ == "__main__":
    main()