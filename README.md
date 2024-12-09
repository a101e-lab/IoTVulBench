# IoTVulBench

[English](README.md) | [中文](doc_zh/README_zh.md)

IoTVulBench is an open-source benchmark dataset for IoT security research, containing firmware-related vulnerabilities and the corresponding toolkits for building firmware emulations and verifying vulnerabilities.

### Dataset Structure

```bash
./Vulnerabilities/
├── CVE-2017-13772    # vulnerability id
│   ├── BM-2024-00001-payload.seed    # poc
│   └── detail.yml    # vulnerability detail
├── CVE-2018-16334    # vulnerability id
│   ├── BM-2024-00012-payload.seed    # poc
│   └── detail.yml    # vulnerability detail
│……
```

### The List Of Vulnerable Environments

please refer to [vulnerabilities list](vulnerabilities_list.md)

### Features

- Comprehensive IoT vulnerability collection
- Ready-to-use payload samples
- Standardized testing environment
- Easy-to-verify vulnerability reproduction
