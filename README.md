# IoTVulBench

[English](README.md) | [中文](doc_zh/README_zh.md)

IoTVulBench is an open-source benchmark dataset for IoT security research, containing firmware-related vulnerabilities and the corresponding toolkits for building firmware emulations and verifying vulnerabilities.

## Dataset Structure

```bash
Vulnerabilities/
├── CVE-2017-13772    # vulnerability id
│   ├── BM-2024-00001-payload.seed    # poc
│   └── detail.yml    # vulnerability detail
├── CVE-2018-16334    # vulnerability id
│   ├── BM-2024-00012-payload.seed    # poc
│   └── detail.yml    # vulnerability detail
│...
```

The List of Vulnerable Environments: Please refer to [vulnerabilities list](vulnerabilities_list.md)

## Prerequisites

- Python >= 3.8
- Docker

## Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/a101e-lab/IoTVulBench
   cd IoTVulBench
   git submodule update --init
   ```

2. **Install the required Python packages:**

   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. **Start the firmware emulation using `FirmEmu.py`:**

   First, you need to emulate the firmware environment by running the `FirmEmu.py` script, which will start a Docker container and expose the service on a specific port.

   ```bash
   python3 FirmEmu.py -v <vulnerability-id>
   ```

   Replace `<vulnerability-id>` with the ID of the vulnerability you wish to emulate. For example:

   ```bash
   python3 FirmEmu.py -v CVE-2020-13390
   ```
   `FirmEmu.py`输出：

    ```bash
    [+] Service successfully started at http://0.0.0.0:32812
    ```

   This will start the Docker container and output the port number where the emulated service is running.

2. **Send the payload using `PayloadSender.py`:**

   After obtaining the port from the previous step, use the `PayloadSender.py` script to send the payload to the running service. You’ll need to provide the IP and port where the service is available.

   ```bash
   python3 PayloadSender.py -v <vulnerability-id> [-i <target-ip>] -p <target-port>
   ```

   Replace `<vulnerability-id>` with the same vulnerability ID you used in the previous step, `<target-ip>` with the target IP address (use `127.0.0.1` if running locally), and `<target-port>` with the port number you obtained from `FirmEmu.py`.

   For example:

   ```bash
   python3 PayloadSender.py -v CVE-2020-13390 -p 32809
   ```

   **Note:** The port number is the one printed by `FirmEmu.py` after emulating the firmware.

## Features

- Comprehensive IoT vulnerability collection
- Ready-to-use payload samples
- Standardized testing environment
- Easy-to-verify vulnerability reproduction
