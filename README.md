# Log Analysis Tool

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Table of Contents

1. [About the Project](#about-the-project)
2. [Features](#features)
3. [Getting Started](#getting-started)
   - [Prerequisites](#prerequisites)
   - [Installation](#installation)
4. [Usage](#usage)
5. [Configuration](#configuration)
6. [File Structure](#file-structure)
7. [Contributing](#contributing)
8. [License](#license)
9. [Contact](#contact)

---

## About the Project

The Log Analysis Tool is a Python-based project designed to parse and analyze server log files. It provides insights into server usage, suspicious activity, and endpoint access patterns, making it a useful tool for troubleshooting, security audits, and performance monitoring.

---

## Features

- Parses server log files to extract key details like IP addresses and endpoint usage.
- Identifies the most accessed endpoints.
- Detects suspicious activity by analyzing failed login attempts.
- Generates a detailed CSV report for easy analysis.

---

## Getting Started

### Prerequisites

Ensure you have the following installed:

- Python 3.7 or later

### Installation

Follow these steps to set up the project:

1. Clone the repository:
   ```bash
   git clone https://github.com/jenish-ml/log-analysis-tool.git
   cd log-analysis-tool
