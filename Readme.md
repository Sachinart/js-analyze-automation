# Advanced JavaScript Security Scanner

A Python tool that crawls websites, discovers JavaScript files recursively, and extracts API endpoints, secrets, and sensitive information from JS code.

## What It Does

This scanner helps security researchers and penetration testers by:

- Crawling websites to find all JavaScript files
- Recursively discovering JS files referenced within other JS files (imports, webpack chunks, etc.)
- Extracting API endpoints with HTTP methods and parameters
- Finding secrets like API keys, tokens, and credentials
- Generating ready-to-use cURL commands and Postman collections

The key feature is recursive discovery - if `index.js` imports `utils.js`, the scanner will automatically find and analyze `utils.js` too, even if it wasn't linked in the HTML.

## Installation

You need Python 3.7 or higher.

```bash
# Install required packages
pip install playwright jsbeautifier

# Install Chromium browser
playwright install chromium
```

## Basic Usage

```bash
python3 advanced_js_scanner.py <target_url> <api_base_url>
```

### Example

```bash
python3 advanced_js_scanner.py https://example.com https://api.example.com
```

This will:
1. Crawl `https://example.com` to find JS files
2. Recursively discover more JS files from imports
3. Analyze all JS for endpoints and secrets
4. Generate outputs in a timestamped folder

## Advanced Usage

### With Authentication Parameters

If the API requires auth parameters in the URL:

```bash
python3 advanced_js_scanner.py https://example.com https://api.example.com \
  --auth "uid=12345&token=abc123&type=2"
```

This appends authentication to all generated URLs.

### Adjust Crawl Depth

Control how deep the crawler goes (default is 11):

```bash
python3 advanced_js_scanner.py https://example.com https://api.example.com -d 5
```

### Verbose Output

See detailed progress:

```bash
python3 advanced_js_scanner.py https://example.com https://api.example.com -v
```

## Output Files

The scanner creates a folder like `example.com_20240103_143022/` with these files:

**00_SUMMARY.txt** - Overview of findings

**01_js_files.txt** - List of all discovered JavaScript files

**02_secrets.txt** and **02_secrets.json** - Found API keys, tokens, credentials

**03_endpoints_detailed.txt** and **03_endpoints_detailed.json** - Complete endpoint analysis with methods, parameters, and sample requests

**04_endpoints_by_method.txt** - Endpoints grouped by HTTP method (GET, POST, etc.)

**05_complete_urls.txt** - All complete URLs ready to test

**06_curl_commands.sh** - Ready-to-use cURL commands for all endpoints

**07_postman_collection.json** - Import into Postman for easy testing

**downloaded_js/** - All downloaded JavaScript files

## How Recursive Discovery Works

The scanner runs in multiple passes:

**Pass 1:** Crawls HTML pages, finds initial JS files, downloads and analyzes them

**Pass 2:** Looks at downloaded JS files for references to other JS files (imports, chunks), downloads new ones

**Pass 3:** Repeats until no new files are found

This ensures you get every JS file, even those loaded dynamically or through webpack code splitting.

## What Gets Detected

### Endpoints
- API paths like `/api/users/{id}`
- HTTP methods (GET, POST, PUT, DELETE, PATCH)
- Parameters (path, query, body)
- Content-Type headers

### Secrets
- API keys
- Secret keys
- Access tokens
- Bearer tokens
- JWT tokens
- AWS keys
- Google API keys
- Database connection strings
- OAuth secrets
- Private keys

## Example Workflow

```bash
# Scan the target
python3 advanced_js_scanner.py https://target.com https://target.com

# Check the results
cd target.com_20240103_143022/
cat 00_SUMMARY.txt

# Test endpoints with cURL
bash 06_curl_commands.sh

# Or import 07_postman_collection.json into Postman
```

## Common Use Cases

**Bug Bounty Hunting:** Find undocumented API endpoints and test them for vulnerabilities

**Security Assessments:** Discover all API endpoints and authentication mechanisms

**Competitive Analysis:** Understand how a web application's API is structured

**Development:** Document your own API by scanning the frontend

## Tips

1. Always get permission before scanning websites you don't own
2. Use verbose mode (-v) to see what's happening in real-time
3. If you have auth tokens, use --auth to include them in generated URLs
4. Check the secrets file carefully - filter out test/placeholder values
5. The Postman collection is great for organized endpoint testing

## Limitations

- Only finds internal JavaScript files (same domain)
- Requires the site to be accessible without complex authentication
- May miss endpoints in heavily obfuscated code
- Does not execute JavaScript, only analyzes static code

## Requirements

- Python 3.7+
- playwright
- jsbeautifier

## License

Free to use for security research and penetration testing. Use responsibly and ethically.

## Legal Notice

This tool is for authorized security testing only. Always obtain proper authorization before scanning any website or application you do not own.
