# PCAP TCP Metrics Analyzer

## Overview
`pcap_tcp_metrics_analyzer.py` is a Python script that analyzes a given PCAP file, extracts TCP flows, and then calculates and prints the average Round-Trip Time (RTT) and throughput in Mbps for each flow.

## Requirements
- Python 3.x
- Scapy: `pip install scapy`

## Usage
```bash
python pcap_tcp_metrics_analyzer.py <path_to_pcap_file>
```

For example:
```bash
python pcap_tcp_metrics_analyzer.py example.pcap
```

## Output
The script provides an output for each identified TCP flow in the format:
```
Flow from [source_ip]:[source_port] to [destination_ip]:[destination_port] - Average RTT: [avg_rtt] ms, Throughput: [throughput] Mbps
```

## Credits
All code in this repository was generated by OpenAI's ChatGPT. Special thanks to the OpenAI team for their support and assistance.
