# IoTVulBench

[English](../README.md) | [中文](README_zh.md)

IoTVulBench 是一个开源的物联网安全研究基准数据集，包含固件相关漏洞以及用于构建固件模拟和验证漏洞的相应工具包。

### 数据集结构

```bash
./Vulnerabilities/
├── CVE-2017-13772    # 漏洞编号
│   ├── BM-2024-00001-payload.seed    # 漏洞利用载荷
│   └── detail.yml    # 漏洞详情
├── CVE-2018-16334    # 漏洞编号
│   ├── BM-2024-00012-payload.seed    # 漏洞利用载荷
│   └── detail.yml    # 漏洞详情
│……
```

### 漏洞环境列表

请查看 [vulnerabilities_list_zh.md](vulnerabilities_list_zh.md)

### 特点

- 全面的物联网漏洞收集
- 即用型漏洞利用样本
- 标准化测试环境
- 便捷的漏洞复现验证
