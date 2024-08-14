# API-VulnScan
API VulnScan is a lightweight CLI tool designed to identify common security issues in APIs. It performs the following checks:

Open Endpoints: Detects endpoints accessible without authentication that could expose sensitive data or functionality.
Unsafe HTTP Methods: Checks if endpoints allow unsafe HTTP methods (e.g., PUT, DELETE) that could be exploited.
Missing Security Headers: Verifies the presence of important security headers to protect against common web vulnerabilities.

# Usage 
```cd API-VulnScan```

```python3 api-vulnscan.py```

# Sample Output
<img width="1410" alt="Screenshot 2024-08-14 at 3 05 00 AM" src="https://github.com/user-attachments/assets/69db059d-4df4-4818-a19b-192eba6f0d80">

# Ethical Use Notice
API VulnScan is intended for use in ethical contexts only. This tool should only be used to scan APIs for security vulnerabilities with proper authorization from the system owner. Unauthorized use of this tool on systems without consent is illegal and unethical. Always ensure you have explicit permission before conducting any security assessments. Use responsibly and respect privacy and security guidelines.
