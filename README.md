# JSProbeX

JSProbeX is a Python-based tool for extracting URLs and sensitive secrets from JavaScript files. This tool helps you scan multiple URLs or files for sensitive information like API keys, secret tokens, and more. It is ideal for penetration testers and bug bounty hunters who need to efficiently analyze JavaScript files and identify valuable data.

<p align="center">
  <a href="https://www.producthunt.com/posts/jsprobex?embed=true&utm_source=badge-featured&utm_medium=badge&utm_souce=badge-jsprobex" target="_blank">
    <img src="https://api.producthunt.com/widgets/embed-image/v1/featured.svg?post_id=739691&theme=dark" alt="JSProbeX - Pentesting&#0032;tool&#0032;to&#0032;extract&#0032;secrets&#0032;&#0038;&#0032;URLs&#0032;from&#0032;JS&#0032;files | Product Hunt" style="width: 250px; height: 54px;" width="250" height="54" />
  </a>
</p>

## Features

- **URL Extraction**: Automatically extracts URLs from JavaScript files.
- **Secrets Detection**: Identifies sensitive data such as AWS keys, Stripe keys, GitHub tokens, and more (supports more than 49+ types of secrets).
- **Auto-generated Output**: Saves extracted data in a file with a unique name based on the given domain.
- **Input Support**: Accepts input through both single URLs or a file containing multiple URLs.
- **Clean Error Handling**: Provides beautifully formatted error messages for non-200 responses.
- **Organized Output**: Saves extracted data domain-wise or in a custom directory.

## Requirements

- Python 3.x
- `requests` - For making HTTP requests.
- `beautifulsoup4` - For parsing HTML content (optional based on your use case).
- `validators` - For validating URLs.
- `urllib3` - For handling URL connections and security.
- `colorama` - For coloring terminal output.



## Usage/Install

1. **Clone the repository**:
   ```bash
   git clone https://github.com/hackelite01/JSProbeX.git
   ```

2. **Install the required dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the tool**:

   - **For single URL input**:
     ```bash
     python jsprobex.py -u <URL>
     ```

   - **For multiple URLs from a file**:
     ```bash
     python jsprobex.py -f <file.txt>
     ```

   - **To extract secrets from URL**:
     ```bash
     python jsprobex.py -u <URL> --secrets
     ```

   - **To extract secrets from file**:
     ```bash
     python jsprobex.py -f <file.txt> --secrets
     ```

   - **To specify output file**:
     ```bash
     python jsprobex.py -u <URL> -o <output_file.txt> --secrets
     ```

---

## Disclaimer

This tool is intended for ethical penetration testing, bug bounty hunting, and security research. Use it responsibly and ensure you have permission to test the URLs and files you are scanning. Unauthorized scanning of websites and applications may be illegal.

## License

This project is licensed under the MIT License.

