# CryptoGuardML
A Machine Learning based Cryptojacking Detector!

A machine learning-powered tool to detect cryptojacking attempts by monitoring system resource usage and network activity patterns.

## Overview

This tool uses anomaly detection with Isolation Forest algorithm to identify potential cryptojacking malware running on your system. It works by:

1. Establishing a baseline of normal system behavior during a training phase
2. Monitoring CPU, memory, and network usage in real-time
3. Detecting suspicious connections to known mining pools
4. Identifying processes with cryptomining signatures
5. Alerting when anomalous behavior is detected

## Features

- **Machine Learning Detection**: Uses Isolation Forest for anomaly detection
- **Resource Monitoring**: Tracks CPU, memory, and network usage patterns
- **Network Analysis**: Detects connections to known mining pools and suspicious ports
- **Process Inspection**: Identifies processes with cryptomining-related keywords
- **Automatic Training**: Learns your system's normal behavior
- **Customizable Sensitivity**: Adjustable detection thresholds
- **Detailed Logging**: Records all detections and system metrics

## Requirements

- Python 3.6+
- Dependencies:
  - numpy
  - pandas
  - scikit-learn
  - psutil

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/vishnuvrj7/CryptoGuardML.git
   cd CryptoGuardML
   ```

2. Install required dependencies:
   ```bash
   pip install numpy pandas scikit-learn psutil
   ```

## Usage

### Training Mode

Before using the detector, you need to train it on your system's normal behavior:

```bash
python cryptoguard.py --train --training-time 3600
```

This will run the detector in training mode for 1 hour (3600 seconds). Adjust the training time based on your needs.

### Detection Mode

After training is complete, run the detector in normal mode:

```bash
python cryptoguard.py
```

### Command Line Options

- `--train`: Start in training mode
- `--model PATH`: Specify path to model file (default: cryptojacking_model.pkl)
- `--interval SECONDS`: Set monitoring interval in seconds (default: 5)
- `--training-time SECONDS`: Set training duration in seconds (default: 3600)
- `--sensitivity FLOAT`: Set detection sensitivity between 0.9 and 0.99 (default: 0.95)
- `--threshold FLOAT`: Set alert threshold between 0.0 and 1.0 (default: 0.7)

Example with custom settings:
```bash
python cryptoguard.py --threshold 0.6 --interval 10
```

## Understanding the Output

The detector logs information to both the console and to a file named `cryptojacking_detector.log`. Each log entry includes:

- Current threat level (0.0 to 1.0, where higher values indicate more suspicious activity)
- CPU usage percentage
- Memory usage percentage
- Network traffic rates

When the threat level exceeds the threshold, alerts are displayed and detection details are saved to a JSON file.

## Detection JSON Files

When potential cryptojacking activity is detected, the tool saves detailed information to a JSON file named `detection_[timestamp].json`. This file contains:

- Timestamp of detection
- Threat level
- System metrics at time of detection
- List of suspicious processes

## Known Limitations

- False positives may occur with legitimate high-CPU applications
- Detection accuracy depends on the quality of the training data
- Does not detect cryptojacking in web browsers (JavaScript miners)
- Requires administrative privileges for some functionality

## Related Projects

Here are other repositories developed by me that focus on detecting and preventing **crypto-jacking** attacks:

### [CryptoPatrol](https://github.com/vishnuvrj7/CryptoPatrol)
A lightweight **browser-based intrusion detection tool** that monitors real-time web activity to identify unauthorized cryptocurrency mining using a **Chrome extension** and a **Python Flask backend**.

- **Tech Stack**: JavaScript, HTML, Flask, Socket.IO  
- **Key Features**:
  - Live browser monitoring
  - Rule-based detection system
  - Easy to install and run

---

### [CryptojackSentinal](https://github.com/vishnuvrj7/CryptojackSentinal)
An **advanced system-level sentinel** that detects and prevents stealthy crypto-mining scripts running on the machine, even outside the browser.

- **Tech Stack**: Python, psutil, watchdog, tkinter  
- **Key Features**:
  - Real-time monitoring of system processes
  - Alerts on suspicious mining behavior
  - Auto-kill mining processes with activity logs

---

> Explore these tools to build a complete defense system against in-browser and system-level crypto-jacking threats.


## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is provided for educational and research purposes only. It should not be used as the sole security measure against cryptojacking attacks, but rather as part of a comprehensive security strategy.
