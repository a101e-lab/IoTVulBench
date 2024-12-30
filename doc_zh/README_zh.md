# IoTVulBench

[English](../README.md) | [中文](README_zh.md)

IoTVulBench 是一个用于物联网安全研究的开源基准数据集，包含与固件相关的漏洞及相应的工具包，用于构建固件仿真并验证漏洞。

## 数据集结构

```bash
Vulnerabilities/
├── CVE-2017-13772    # 漏洞 ID
│   ├── BM-2024-00001-payload.seed    # 漏洞利用（POC）
│   └── detail.yml    # 漏洞详情
├── CVE-2018-16334    # 漏洞 ID
│   ├── BM-2024-00012-payload.seed    # 漏洞利用（POC）
│   └── detail.yml    # 漏洞详情
│...
```

漏洞环境列表：请参考 [vulnerabilities list](vulnerabilities_list_zh.md)

## 环境要求

- Python >= 3.8
- Docker

## 安装

1. **克隆仓库：**

   ```bash
   git clone https://github.com/a101e-lab/IoTVulBench
   cd IoTVulBench
   git submodule update --init
   ```

2. **安装所需的 Python 包：**

   ```bash
   pip install -r requirements.txt
   ```

## 使用方法

1. **使用 `FirmEmu.py` 启动固件仿真：**

   首先，使用 `FirmEmu.py` 脚本来仿真固件环境，该脚本将启动一个 Docker 容器并在指定端口上暴露服务。

   ```bash
   python3 FirmEmu.py -v <漏洞-id>
   ```

   将 `<漏洞-id>` 替换为你希望仿真的漏洞 ID。例如：

   ```bash
   python3 FirmEmu.py -v CVE-2020-13390
   ```

   `FirmEmu.py` 会输出：

   ```bash
   [+] Service successfully started at http://0.0.0.0:32812
   ```

   这将启动 Docker 容器并输出仿真服务运行的端口号。

2. **使用 `PayloadSender.py` 发送漏洞载荷：**

   获取到端口号后，使用 `PayloadSender.py` 脚本向运行中的服务发送漏洞载荷。你需要提供服务的 IP 和端口号。

   ```bash
   python3 PayloadSender.py -v <漏洞-id> [-i <目标-ip>] -p <目标-port>
   ```

   将 `<漏洞-id>` 替换为之前使用的相同漏洞 ID，`<目标-ip>` 替换为目标 IP 地址（如果是本地运行，默认值为`127.0.0.1`，可省略），`<目标-port>` 替换为从 `FirmEmu.py` 获取到的端口号。

   例如：

   ```bash
   python3 PayloadSender.py -v CVE-2020-13390 -p 32812
   ```

   **注意：** 端口号是 `FirmEmu.py` 输出的服务运行端口号。

## 功能特点

- 全面的物联网漏洞收集
- 即用型漏洞利用样本
- 标准化测试环境
- 便捷的漏洞复现验证