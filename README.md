# SQL Checker Tool
*A Python-based SQL Injection Scanner by KixxU*

> [!WARNING]
> ## ⚠️ Legal Disclaimer
> This tool is intended for **educational purposes and for use in authorized security testing scenarios ONLY**. Using this script on systems without explicit, written permission is illegal. The author is not responsible for any misuse or damage caused by this tool.

## Description
SQL Checker is a command-line tool designed to help security researchers and web developers quickly test for basic SQL injection vulnerabilities in web applications. It automates the detection of several common SQLi types.

## Features
- **Error-Based Detection:** Identifies vulnerabilities by triggering and detecting common database error messages.
- **Boolean-Based Blind Detection:** Infers vulnerabilities by observing content changes based on TRUE/FALSE conditions.
- **Time-Based Blind Detection:** Confirms vulnerabilities by measuring response delays caused by injected `SLEEP` commands.

## Installation & Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/CMAgent007/sql-checker-tool(https://github.com/CMAgent007/sql-checker-tool)
   cd sql-checker-tool
   python sql.py [URL]
