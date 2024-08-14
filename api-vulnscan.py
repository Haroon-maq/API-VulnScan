#!/usr/bin/env python3

import requests

# List of example endpoints to check
ENDPOINTS = [
    "/public",
    "/admin",
    "/login",
    "/data",
]

# Example headers to check for
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
]

# ANSI escape codes for blue color
BLUE = "\033[94m"
RESET = "\033[0m"

def print_banner():
    print(f"{BLUE}API VulnScan{RESET}")
    print("=" * 30)

def check_open_endpoints(base_url):
    print("[*] Checking for open endpoints...")
    for endpoint in ENDPOINTS:
        url = base_url + endpoint
        try:
            response = requests.get(url)
            if response.status_code == 200:
                print(f"[!] Open endpoint found: {url}")
            else:
                print(f"[*] Endpoint {url} returned status code {response.status_code}")
        except requests.RequestException as e:
            print(f"[!] Error checking endpoint {url}: {e}")

def check_http_methods(base_url):
    print("[*] Checking for unsafe HTTP methods...")
    for endpoint in ENDPOINTS:
        url = base_url + endpoint
        try:
            methods = ['GET', 'POST', 'PUT', 'DELETE']
            for method in methods:
                response = requests.request(method, url)
                if response.status_code == 405:  # Method Not Allowed
                    print(f"[*] {method} method not allowed on {url}")
                elif response.status_code < 400:
                    print(f"[!] Unsafe method {method} allowed on {url}")
        except requests.RequestException as e:
            print(f"[!] Error checking methods on {url}: {e}")

def check_security_headers(base_url):
    print("[*] Checking for security headers...")
    for endpoint in ENDPOINTS:
        url = base_url + endpoint
        try:
            response = requests.get(url)
            headers = response.headers
            missing_headers = [header for header in SECURITY_HEADERS if header not in headers]
            if missing_headers:
                print(f"[!] Missing security headers on {url}: {', '.join(missing_headers)}")
            else:
                print(f"[*] All security headers present on {url}")
        except requests.RequestException as e:
            print(f"[!] Error checking headers on {url}: {e}")

def main():
    print_banner()
    base_url = input("Enter the base URL of the API to scan (e.g., https://api.example.com): ")
    check_open_endpoints(base_url)
    check_http_methods(base_url)
    check_security_headers(base_url)

if __name__ == "__main__":
    main()
