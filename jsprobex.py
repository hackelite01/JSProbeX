import requests
import re
import json
import os
import sys
import argparse
from urllib.parse import urlparse
import random
from colorama import Fore, Style, init
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Initialize Colorama
init(autoreset=True)

def print_banner():
    """Prints a banner with a random color every time it's used."""
    banner = """
     ▄█    ▄████████    ▄███████▄    ▄████████  ▄██████▄  ▀█████████▄     ▄████████ ▀████    ▐████▀ 
    ███   ███    ███   ███    ███   ███    ███ ███    ███   ███    ███   ███    ███   ███▌   ████▀  
    ███   ███    █▀    ███    ███   ███    ███ ███    ███   ███    ███   ███    █▀     ███  ▐███    
    ███   ███          ███    ███  ▄███▄▄▄▄██▀ ███    ███  ▄███▄▄▄██▀   ▄███▄▄▄        ▀███▄███▀    
    ███ ▀███████████ ▀█████████▀  ▀▀███▀▀▀▀▀   ███    ███ ▀▀███▀▀▀██▄  ▀▀███▀▀▀        ████▀██▄     
    ███          ███   ███        ▀███████████ ███    ███   ███    ██▄   ███    █▄    ▐███  ▀███    
    ███    ▄█    ███   ███          ███    ███ ███    ███   ███    ███   ███    ███  ▄███     ███▄  
█▄ ▄███  ▄████████▀   ▄████▀        ███    ███  ▀██████▀  ▄█████████▀    ██████████ ████       ███▄ 
▀▀▀▀▀▀                              ███    ███                                                      
                             Developed by Mayank Rajput (hackelite01)
    """
    
    # List of colors to choose from
    colors = [
        "\033[91m",  # Red
        "\033[92m",  # Green
        "\033[93m",  # Yellow
        "\033[94m",  # Blue
        "\033[95m",  # Magenta
        "\033[96m",  # Cyan
        "\033[97m",  # White
    ]
    
    # Select a random color from the list
    color = random.choice(colors)
    
    # Print the banner with the selected color
    print(color + banner)

def extract_links_from_js(js_content):
    """Extracts URLs from JavaScript content."""
    url_pattern = r'(https?://[^\s\'"<>]+)'
    return re.findall(url_pattern, js_content)

def extract_secrets(js_content):
    """Extracts potential secrets from JavaScript content."""
    secret_patterns = {
        'API Key': r'(?i)API_Key\s*:\s*[\'"]?([A-Za-z0-9_-]{32,})[\'"]?',
        'Algolia API Key': r'(?i)algolia_api_key\s*[:=]\s*[\'"]?([a-f0-9]{32})[\'"]?',
        'Algolia Admin Key': r'(?i)algolia_admin_key\s*[:=]\s*[\'"]?([a-f0-9]{32})[\'"]?',
        'API Key': r'(?i)api_key\s*[:=]\s*[\'"]?([A-Za-z0-9/_+=\-]{32,})[\'"]?',
        'Auth Domain': r'(?i)Auth_Domain\s*:\s*[\'"]?([A-Za-z0-9\-]+\.[a-z]{2,})[\'"]?',
        'AWS Access Key': r'(?i)AWS_Access_Key\s*:\s*[\'"]?([A-Z0-9]{20})[\'"]?',
        'AWS Secret Key': r'(?i)AWS_Secret_Key\s*:\s*[\'"]?([A-Za-z0-9/+=]{40})[\'"]?',
        'AWS Session Token': r'(?i)aws_session_token\s*[:=]\s*[\'"]?([A-Za-z0-9/+=]{16,})[\'"]?',
        'Basic Auth Credentials': r'[a-zA-Z0-9_\-]+:[a-zA-Z0-9_\-]+@[a-zA-Z0-9_\-]+\.[a-zA-Z]{2,}',
        'Cloudflare API Key': r'(?i)cloudflare_api_key\s*[:=]\s*[\'"]?([A-Za-z0-9]{37})[\'"]?',
        'Database URL': r'(?i)Database_URL\s*:\s*[\'"]?([a-z0-9\-]+\.[a-z]{2,})[\'"]?',
        'Dropbox API Key': r'dbx_[A-Za-z0-9]{64}',
        'Facebook Access Token': r'(?i)EAACEdEose0cBA[0-9A-Za-z]+',
        'Facebook Secret Key': r'(?i)fb_secret_key\s*[:=]\s*[\'"]?([a-f0-9]{32})[\'"]?',
        'Facebook Token': r'(?i)Facebook_Token\s*:\s*[\'"]?([A-Za-z0-9\.]+)[\'"]?',
        'Firebase API Key': r'(?i)firebase_api_key\s*:\s*[\'"]?([A-Za-z0-9_]{32})[\'"]?',
        'Firebase Database URL': r'https:\/\/[a-z0-9-]+\.firebaseio\.com',
        'Firebase Storage Bucket': r'(?i)"storageBucket"\s*:\s*"([A-Za-z0-9\-_]+\.appspot\.com)"',
        'GitHub Access Token': r'ghp_[A-Za-z0-9_]{36}',
        'GitHub OAuth Token': r'gho_[A-Za-z0-9_]{36}',
        'GitHub Secret Key': r'(?i)github_secret_key\s*:\s*[\'"]?([A-Za-z0-9_]{40})[\'"]?',
        'GitHub Token': r'(?i)GitHub Token\s*:\s*[\'"]?([A-Za-z0-9]{36})[\'"]?',
        'Google Cloud API Key': r'(?i)AIza[0-9A-Za-z-_]{35}',
        'Google Cloud Secret Key': r'(?i)"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----[A-Za-z0-9/+=\s]+-----END PRIVATE KEY-----"',
        'Google Maps API Key': r'(?i)Google Maps API Key\s*:\s*[\'"]?([A-Za-z0-9_-]+)[\'"]?',
        'Google OAuth Access Token': r'ya29\.[0-9A-Za-z\-_]+',
        'Google reCAPTCHA Key': r'(?i)Google reCAPTCHA Key\s*:\s*[\'"]?([A-Za-z0-9_-]+)[\'"]?',
        'Heroku API Key': r'(?i)heroku_api_key\s*:\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
        'Instagram Access Token': r'(?i)instagram_access_token\s*:\s*[\'"]?([A-Za-z0-9\-._]+)[\'"]?',
        'JWT Token': r'ey[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+',
        'LinkedIn Secret Key': r'(?i)linkedin_secret_key\s*[:=]\s*[\'"]?([A-Za-z0-9_]{32})[\'"]?',
        'Mailgun API Key': r'(?i)mailgun_api_key\s*:\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
        'Microsoft Client ID': r'(?i)microsoft_client_id\s*[:=]\s*[\'"]?([0-9a-fA-F\-]{36})[\'"]?',
        'Microsoft Client Secret': r'(?i)microsoft_client_secret\s*[:=]\s*[\'"]?([A-Za-z0-9/_+=]{32,})[\'"]?',
        'OAuth Token': r'(?i)OAuth_Token\s*:\s*[\'"]?([A-Za-z0-9_-]+)[\'"]?',
        'PayPal Client ID': r'(?i)paypal_client_id\s*:\s*[\'"]?([A-Za-z0-9-_]{15,})[\'"]?',
        'PayPal Secret': r'(?i)paypal_secret\s*:\s*[\'"]?([A-Za-z0-9-_]{15,})[\'"]?',
        'Private Key': r'(?i)"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----[A-Za-z0-9/+=\s]+-----END PRIVATE KEY-----"',
        'Secret Key': r'(?i)Secret_Key\s*:\s*[\'"]?([A-Za-z0-9_-]{32,})[\'"]?',
        'Secret Key': r'(?i)secret_key\s*[:=]\s*[\'"]?([A-Za-z0-9/_+=\-]{32,})[\'"]?',
        'Secret Token': r'[A-Za-z0-9]{64}',
        'Shopify API Key': r'(?i)shopify_api_key\s*[:=]\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
        'Shopify Access Token': r'(?i)shopify_access_token\s*[:=]\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
        'Slack API Key': r'(?i)xox[baprs]-[A-Za-z0-9]{10,48}',
        'Slack Webhook URL': r'https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9_\/-]+',
        'Square Access Token': r'sq0atp-[A-Za-z0-9\-_]{22,43}',
        'Stripe API Key': r'(?i)sk_live_[0-9a-zA-Z]{24}',
        'Stripe Publishable Key': r'(?i)pk_live_[0-9a-zA-Z]{24}',
        'Stripe Secret Key': r'(?i)Stripe_Secret_Key\s*:\s*[\'"]?([A-Za-z0-9]{24})[\'"]?',
        'Telegram Bot Token': r'(?i)Telegram Bot Token\s*:\s*[\'"]?([A-Za-z0-9:]+)[\'"]?',
        'Twilio Account SID': r'(?i)twilio_account_sid\s*:\s*[\'"]?([A-Za-z0-9]{34})[\'"]?',
        'Twilio Auth Token': r'(?i)twilio_auth_token\s*:\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    }

    found_secrets = {}
    for key, pattern in secret_patterns.items():
        matches = re.findall(pattern, js_content)
        if matches:
            found_secrets[key] = list(set(matches))
    return found_secrets

def process_js_content(js_url, cookies=None, extract_urls=True, extract_secrets_flag=True):
    """Fetches and processes JavaScript content for URLs and secrets."""
    headers = {'Cookie': cookies} if cookies else {}
    try:
        response = requests.get(js_url, headers=headers, verify=False)
        if response.status_code == 200:
            links = extract_links_from_js(response.text) if extract_urls else []
            secrets = extract_secrets(response.text) if extract_secrets_flag else {}
            return links, secrets
        else:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Failed to fetch {js_url}. Status Code: {response.status_code}")
    except requests.RequestException as e:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Could not fetch {js_url}: {e}")
    return [], {}

def process_file(input_file, cookies=None, extract_urls=True, extract_secrets_flag=True):
    """Processes a file containing JavaScript URLs."""
    if not os.path.exists(input_file):
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} File not found: {input_file}")
        return

    url_results = []
    secret_results = []

    with open(input_file, 'r') as file:
        js_links = file.readlines()

    for js_url in js_links:
        js_url = js_url.strip()
        if not js_url:
            continue

        print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Processing {js_url}...")
        links, secrets = process_js_content(js_url, cookies, extract_urls, extract_secrets_flag)

        if extract_urls and links:
            url_results.append(f"{js_url}:\n" + '\n'.join(links) + '\n')

        if extract_secrets_flag and secrets:
            secret_results.append(f"Secrets from {js_url}:\n" + json.dumps(secrets, indent=2) + '\n')

    # Generate output file names based on the first URL in the file
    if js_links:
        first_url = js_links[0].strip()
        output_url_file = generate_output_filename(first_url, "links")
        output_secret_file = generate_output_filename(first_url, "secrets")
    else:
        output_url_file = "extracted_links.txt"
        output_secret_file = "extracted_secrets.txt"

    # Write the URL results to the output URL file
    if url_results:
        with open(output_url_file, 'w') as output:
            output.writelines(url_results)
        print(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} URL results saved to {output_url_file}")

    # Write the secret results to the output secret file
    if secret_results:
        with open(output_secret_file, 'w') as output:
            output.writelines(secret_results)
        print(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} Secret results saved to {output_secret_file}")
    else:
        print(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} No secrets found.")

def generate_output_filename(url, suffix):
    """Generate a unique output file name based on the domain."""
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.replace('.', '_')
    return f"{domain}_{suffix}.txt"

def main():
    """Main function to parse arguments and run the script."""
    print_banner()  # Print the banner at the start of the script

    parser = argparse.ArgumentParser(description="JavaScript Analyzer for URLs and Secrets.")
    parser.add_argument("-f", "--file", help="Specify a file containing JavaScript URLs.")
    parser.add_argument("-o", "--output_file", help="Specify the output file to save results.")
    parser.add_argument("-u", "--url", help="Analyze a single JavaScript URL.")
    parser.add_argument("--secrets", action="store_true", help="Look for sensitive secrets in JavaScript content.")
    parser.add_argument("--urls", action="store_true", help="Extract URLs from JavaScript content.")
    parser.add_argument("--cookies", help="Specify cookies for authentication (optional).")

    args = parser.parse_args()

    if len(sys.argv) == 1:
        # If no arguments are passed, show the help menu
        parser.print_help()
        sys.exit(0)

    cookies = args.cookies
    extract_urls_flag = args.urls or not args.secrets  # Default to extracting URLs if no flag is set.
    extract_secrets_flag = args.secrets or not args.urls  # Default to extracting secrets if no flag is set.

    # If analyzing a single URL, process it
    if args.url:
        print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Processing single URL: {args.url}")
        links, secrets = process_js_content(args.url, cookies, extract_urls_flag, extract_secrets_flag)
        output_file = args.output_file if args.output_file else generate_output_filename(args.url, "extracted")
        with open(output_file, 'w') as output:
            if extract_urls_flag and links:
                output.write(f"{args.url}:\n" + '\n'.join(links) + '\n')
            if extract_secrets_flag and secrets:
                output.write(f"Secrets from {args.url}:\n" + json.dumps(secrets, indent=2) + '\n')
        print(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} Results saved to {output_file}")

    # If analyzing a file with multiple URLs, process it
    if args.file:
        print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Processing file: {args.file}")
        process_file(args.file, cookies, extract_urls_flag, extract_secrets_flag)

if __name__ == "__main__":
    main()