# Network Scanner
# Port Scanner

A simple TCP port scanner written in Python using Scapy. This script scans a specified range of ports on a given target IP address and retrieves the service names associated with the open ports.

## Features

- Scans a specified range of TCP ports (1-65535).
- Uses SYN scanning to determine the state of ports (open, closed, or filtered).
- Retrieves standard service names for open ports.
- Supports concurrent scanning using threading for faster results.

## Requirements

- Python 3.x
- Scapy library

### Install Dependencies

To install the required dependencies, create a `requirements.txt` file and run the following command:

```bash
pip install -r requirements.txt
python Main.py
```
## Example
```bash
Enter target IP address: 192.168.1.1
Enter start port (1-65535): 1
Enter end port (1-65535): 1024
```
## Output
```bash
Open Ports and Services:
Port: 22 - Service: ssh
Port: 80 - Service: http
...
Scan finished.
```
**Note that it can show some errors while scanning. 


