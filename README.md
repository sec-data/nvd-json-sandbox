
# Fetching NVD Vulnerability Data Using Api2.0 and Updating JSON Feeds

A sandbox for experimenting with scripts for converting NVD API 2.0 data into their "legacy" JSON feed format (in preparation for this legacy feed to be shut off in December 2023)

## Overview

This document outlines the steps to fetch vulnerability data from the National Vulnerability Database (NVD) using API 2.0 and convert it to NVD JSON feeds. Additionally, it updates existing JSON feeds for the year 2024(for now).

## Things to keep in mind

- Ensure you have access to the NVD API 2.0 and obtain the API key.
- The script is written in Python, ensure you have Python installed on your system.
- Note: This script is in Initial phase there are lot improvements that can be done.

## Usage

1. Clone the repository:

    ```bash
    git clone https://github.com/yourusername/nvd-json-sandbox.git
    cd nvd-json-sandbox
    ```

2. Install dependencies:

    ```bash
    pip install -r requirements.txt
    ```

3. Run the script:

    ```bash
    python main.py
    ```




