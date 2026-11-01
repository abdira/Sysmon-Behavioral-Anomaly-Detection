# Sysmon Behavioral Anomaly Detection

**A Python-based Windows endpoint anomaly detection project using Sysmon telemetry and Isolation Forest.**

## Overview

Sysmon Behavioral Anomaly Detection is a cybersecurity project that explores how unsupervised machine learning can help identify unusual process execution behaviour on Windows endpoints.

The project collects Windows Sysmon telemetry, parses event data, extracts behavioural features, and applies the Isolation Forest algorithm to identify observations that differ from previously observed patterns.

The objective is to support security monitoring and SOC investigations by highlighting unusual endpoint activity for further investigation.

**Important:** An anomaly does not automatically mean malicious activity. Machine learning identifies unusual behaviour, while detection rules and security investigations provide the necessary context.

## Current Features

### Windows Event Collection

A Python collector built with `pywin32` retrieves available events from:

- `Microsoft-Windows-Sysmon/Operational`
- `Microsoft-Windows-PowerShell/Operational`

The Sysmon collector retrieves available event records in batches and parses their XML representation into structured Python dictionaries.

The PowerShell collector retrieves Event ID 4104 (Script Block Logging).

### Event Processing

The current machine learning workflow focuses on:

- Sysmon Event ID 1 — Process Creation.

Events are parsed and converted into a Pandas DataFrame. Timestamps are converted to UTC and observations are sorted chronologically.

### Behavioural Feature Extraction

The feature extraction module currently produces the following indicators:

| Feature | Description |
|---|---|
| `command_length` | Length of the process command line |
| `argument_count` | Number of command-line arguments |
| `has_powershell` | Identifies PowerShell process execution |
| `has_encoded_command` | Identifies an encoded-command indicator |
| `has_script_interpreter` | Identifies selected script interpreters |
| `has_suspicious_lolbin` | Identifies selected LOLBin executables |

The extracted data also retains investigation context:

- Event ID
- UTC timestamp
- Event record ID
- Process image
- Parent process image
- Command line
- Parent command line
- User

## Machine Learning

The project currently uses **Isolation Forest**, an unsupervised anomaly detection algorithm from Scikit-learn.

### Features currently used by the model

Although six behavioural indicators are extracted, the initial model currently uses four:

```python
features_for_ml = [
    "command_length",
    "argument_count",
    "has_powershell",
    "has_script_interpreter"
]
```

The encoded-command and suspicious-LOLBin indicators are retained for future experiments.

### Model configuration

```python
model = IsolationForest(
    n_estimators=100,
    contamination="auto",
    random_state=42
)
```

### Chronological training and testing

The current workflow:

1. Collects available Sysmon events.
2. Filters for Process Creation events (Event ID 1).
3. Extracts behavioural features.
4. Converts timestamps to UTC.
5. Sorts observations chronologically.
6. Uses the earliest 80% for model training.
7. Uses the latest 20% for testing.
8. Generates anomaly predictions and decision scores.

This provides an initial chronological holdout evaluation, rather than randomly mixing earlier and later observations.

### Model output

- `1` — observation classified as an inlier.
- `-1` — observation classified as an outlier.
- `decision_function()` — continuous decision score.

Lower decision scores indicate more unusual observations relative to the model's learned patterns.

These scores are not probabilities of malicious activity.

## Project Architecture

```text
Windows Endpoint
       |
       v
Windows Event Logs
       |
       +-----------------------------+
       |                             |
       v                             v
Sysmon Operational             PowerShell Operational
       |                             |
       v                             v
XML Event Parsing              Event ID 4104 Collection
       |
       v
Structured Sysmon Events
       |
       v
Filter Process Creation (ID 1)
       |
       v
Feature Extraction
       |
       v
Pandas DataFrame
       |
       v
UTC Conversion and Sorting
       |
       v
Chronological 80/20 Split
       |
       v
Isolation Forest
       |
       v
Anomaly Predictions and Scores
       |
       v
Investigation
```

## Technology Stack

- Python
- pywin32
- XML ElementTree
- Pandas
- Scikit-learn
- Windows Sysmon
- Windows PowerShell Logging

## Requirements

- Windows operating system
- Python 3
- Sysmon installed and configured
- PowerShell Script Block Logging enabled for Event ID 4104 collection
- Appropriate permissions to access Windows Event Logs

## Installation

Clone the repository:

```bash
git clone https://github.com/abdira/Sysmon-Behavioral-Anomaly-Detection.git
```

Enter the project directory:

```bash
cd Sysmon-Behavioral-Anomaly-Detection
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Running the Project

1. Install and configure Sysmon on your Windows endpoint.
2. Confirm that the Sysmon Operational channel contains events.
3. Enable PowerShell Script Block Logging if you want to use the PowerShell collector.
4. Install the Python dependencies.
5. Run the main machine learning script:

```bash
python main.py
```

The current prototype collects available Sysmon records, filters process creation events, extracts behavioural features, trains Isolation Forest on earlier observations, and evaluates newer observations.

**Note:** Replace `main.py` with the actual filename of your ML script if it is different.

## Development Roadmap

This project is under active development.

- [x] Windows Sysmon event collection.
- [x] PowerShell Event ID 4104 collection.
- [x] XML event parsing.
- [x] Behavioural feature extraction.
- [x] Process Creation event filtering.
- [x] Chronological 80/20 training and testing.
- [x] Initial Isolation Forest implementation.
- [x] Anomaly prediction and decision scoring.
- [ ] Incremental Sysmon collection with checkpoints.
- [ ] Improved event-specific feature engineering.
- [ ] Historical baseline management and evaluation.
- [ ] Score-based investigation prioritization.
- [ ] Detection rule correlation.
- [ ] False-positive analysis and tuning.
- [ ] SQLite integration.
- [ ] Streamlit investigation dashboard.
- [ ] Improved reporting and investigation workflows.

## Security and Data Privacy

Windows event logs may contain usernames, computer names, command lines, IP addresses, file paths, and other sensitive information.

Do not publish raw endpoint logs, credentials, or sensitive investigation data in a public repository.

Use sanitized or synthetic examples when demonstrating detection results.

## Project Status

**Current stage: Initial working prototype.**

Event collection, XML parsing, feature extraction, chronological data splitting, and the initial Isolation Forest workflow have been implemented.

Incremental collection, advanced evaluation, detection correlation, database integration, and the investigation dashboard remain under development.

## Author

GitHub: https://github.com/abdira/

LinkedIn: https://www.linkedin.com/in/abdirahman-ali-715163162/

---

**Core principle:** Machine learning identifies unusual behaviour. Detection rules and investigation provide security context. Neither should replace the other.
