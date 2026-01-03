#!/usr/bin/env python3
"""
Advanced JavaScript Security Scanner with Recursive Discovery
Complete endpoint analysis with methods, parameters, and sample requests
"""

import asyncio
import re
import json
import argparse
import os
from pathlib import Path
from urllib.parse import urljoin, urlparse, urlunparse
from playwright.async_api import async_playwright
from datetime import datetime
from collections import defaultdict
import jsbeautifier

class AdvancedJSScanner:
    def __init__(self, scan_url, endpoint_base_url, max_depth=11, auth_params=None, verbose=False):
        self.scan_url = scan_url
        self.endpoint_base_url = endpoint_base_url
        self.max_depth = max_depth
        self.auth_params = auth_params or ""
        self.verbose = verbose

        self.js_files = set()
        self.visited_urls = set()
        self.base_domain = self._extract_base_domain(urlparse(scan_url).netloc)
        self.output_dir = self._create_output_directory()

        self.js_content_cache = {}
        self.processed_js_files = set()  # Track which JS files we've analyzed for references

        # Analysis results
        self.secrets = []
        self.endpoints = []
        self.complete_urls = []
        self.sample_requests = []

        # Enhanced secret patterns
        self.secret_patterns = {
            'API Key': [
                r'(?i)api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']',
                r'["\']apikey["\']\s*:\s*["\']([a-zA-Z0-9_\-]{16,})["\']',
                r'(?i)x-api-key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']',
            ],
            'Secret Key': [
                r'(?i)secret[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']',
                r'["\']secret["\']\s*:\s*["\']([a-zA-Z0-9_\-]{16,})["\']',
                r'(?i)app[_-]?secret["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']',
            ],
            'Access Token': [
                r'(?i)access[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']',
                r'(?i)auth[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']',
                r'["\']token["\']\s*:\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']',
            ],
            'Bearer Token': [
                r'(?i)bearer["\']?\s+["\']?([a-zA-Z0-9_\-\.]{30,})["\']?',
                r'(?i)authorization:\s*["\']bearer\s+([a-zA-Z0-9_\-\.]+)["\']',
            ],
            'JWT Token': [
                r'eyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}',
            ],
            'Private Key (RSA/SSH)': [
                r'-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----',
                r'-----BEGIN OPENSSH PRIVATE KEY-----',
            ],
            'AWS Access Key': [
                r'AKIA[0-9A-Z]{16}',
                r'(?i)aws[_-]?access[_-]?key[_-]?id["\']?\s*[:=]\s*["\']([A-Z0-9]{20})["\']',
            ],
            'AWS Secret Key': [
                r'(?i)aws[_-]?secret[_-]?access[_-]?key["\']?\s*[:=]\s*["\']([A-Za-z0-9/+=]{40})["\']',
            ],
            'Google API Key': [
                r'AIza[0-9A-Za-z_\-]{35}',
            ],
            'Database URL': [
                r'mongodb(?:\+srv)?://[^\s"\'<>]+',
                r'mysql://[^\s"\'<>]+',
                r'postgres(?:ql)?://[^\s"\'<>]+',
                r'redis://[^\s"\'<>]+',
            ],
            'OAuth Client Secret': [
                r'(?i)client[_-]?secret["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
                r'(?i)oauth[_-]?secret["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
            ],
        }

        # Comprehensive endpoint patterns
        self.endpoint_patterns = [
            r'["\'`](/(?:api|v\d+)/[a-zA-Z0-9_/\-{}:?=&]+)["\'`]',
            r'["\'`](/[a-zA-Z][a-zA-Z0-9_\-]*/[a-zA-Z0-9_/\-{}:?=&]+)["\'`]',
            r'url:\s*["\'`](/[a-zA-Z0-9_/\-{}:?=&]+)["\'`]',
            r'path:\s*["\'`](/[a-zA-Z0-9_/\-{}:?=&]+)["\'`]',
            r'endpoint:\s*["\'`](/[a-zA-Z0-9_/\-{}:?=&]+)["\'`]',
        ]

    def _create_output_directory(self):
        parsed = urlparse(self.scan_url)
        domain = parsed.netloc.replace('www.', '')
        folder_name = re.sub(r'[^\w\-.]', '_', domain)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = f"{folder_name}_{timestamp}"
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        Path(os.path.join(output_dir, "downloaded_js")).mkdir(exist_ok=True)

        print(f"\n{'='*80}")
        print(f"Output: {output_dir}/")
        print(f"{'='*80}\n")

        return output_dir

    def _extract_base_domain(self, netloc):
        parts = netloc.split('.')
        return '.'.join(parts[-2:]) if len(parts) >= 2 else netloc

    def _is_internal_domain(self, url):
        parsed = urlparse(url)
        url_domain = parsed.netloc
        return url_domain == self.base_domain or url_domain.endswith('.' + self.base_domain)

    def _clean_url(self, url):
        parsed = urlparse(url)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))

    def _is_js_file(self, url):
        return self._clean_url(url).endswith('.js')

    def _add_js_file(self, url):
        if self._is_internal_domain(url) and self._is_js_file(url):
            clean = self._clean_url(url)
            if clean not in self.js_files:
                self.js_files.add(clean)
                if self.verbose:
                    print(f"          → New JS: {clean}")

    def _is_valid_endpoint(self, endpoint):
        if not endpoint or len(endpoint) < 2 or not endpoint.startswith('/'):
            return False

        skip = ['.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg',
                '.woff', '.ttf', '.ico', '/static/', '/assets/', '/images/']

        return not any(p in endpoint.lower() for p in skip) and len(endpoint) < 250 and re.search(r'[a-zA-Z]', endpoint)

    def _is_valid_secret(self, secret_type, value):
        if not value or len(value) < 8:
            return False

        skip = ['placeholder', 'example', 'test', 'demo', 'null', 'undefined',
                'localhost', '127.0.0.1', 'xxx', 'password', 'username', 'email']

        return not any(s in value.lower() for s in skip)

    def extract_js_from_js_content(self, base_url, content):
        """Extract JS file references from JS content (imports, dynamic chunks, etc.)"""
        found_files = set()
        
        # Pattern 1: import() statements
        # Matches: import("./file.js"), import('./file.js'), import(`./file.js`)
        import_patterns = [
            r'import\s*\(\s*["\']([^"\']+\.js)["\']',
            r'import\s*\(\s*`([^`]+\.js)`',
        ]
        
        # Pattern 2: ES6 import statements
        # Matches: import x from "./file.js"
        es6_import = r'import\s+.*?\s+from\s+["\']([^"\']+\.js)["\']'
        
        # Pattern 3: require statements
        # Matches: require("./file.js")
        require_pattern = r'require\s*\(\s*["\']([^"\']+\.js)["\']'
        
        # Pattern 4: Webpack chunks with hashes
        # Matches: "assets/chunk.abc123.js", "chunk.abc123def456.js"
        chunk_patterns = [
            r'["\']([^"\']*?assets/[a-zA-Z0-9_\-\.]+\.[a-f0-9]{8,}\.[a-f0-9]{8}\.js)["\']',
            r'["\']([^"\']*?[a-zA-Z0-9_\-]+\.[a-f0-9]{8,}\.js)["\']',
            r'["\']([^"\']*?assets/[a-zA-Z0-9_\-]+\.js)["\']',
        ]
        
        # Pattern 5: General JS file references
        # Matches: "./file.js", "/assets/file.js"
        general_patterns = [
            r'["\'](\./[a-zA-Z0-9_\-/]+\.js)["\']',
            r'["\'](\.\./[a-zA-Z0-9_\-/]+\.js)["\']',
            r'["\'](/[a-zA-Z0-9_\-/]+\.js)["\']',
        ]
        
        all_patterns = import_patterns + [es6_import, require_pattern] + chunk_patterns + general_patterns
        
        for pattern in all_patterns:
            for match in re.finditer(pattern, content):
                js_file = match.group(1)
                
                # Skip external URLs (we only want internal files)
                if js_file.startswith('http://') or js_file.startswith('https://'):
                    parsed = urlparse(js_file)
                    if not (parsed.netloc == self.base_domain or parsed.netloc.endswith('.' + self.base_domain)):
                        continue
                    full_url = js_file
                else:
                    # Resolve relative URLs
                    full_url = self._resolve_js_url(base_url, js_file)
                
                if full_url and self._is_internal_domain(full_url) and self._is_js_file(full_url):
                    clean = self._clean_url(full_url)
                    if clean not in self.js_files:
                        found_files.add(clean)
        
        return found_files

    def _resolve_js_url(self, base_url, js_file):
        """Resolve relative JS URL to absolute URL"""
        try:
            # Handle absolute paths
            if js_file.startswith('/'):
                parsed = urlparse(base_url)
                return f"{parsed.scheme}://{parsed.netloc}{js_file}"
            
            # Handle relative paths (./file.js or ../file.js)
            if js_file.startswith('./') or js_file.startswith('../'):
                return urljoin(base_url, js_file)
            
            # Handle files without path prefix (assume same directory as base)
            base_dir = '/'.join(base_url.split('/')[:-1])
            return f"{base_dir}/{js_file}"
        except Exception as e:
            if self.verbose:
                print(f"          ⚠ Error resolving URL {js_file}: {e}")
            return None

    def _detect_http_method(self, endpoint, context):
        """Detect HTTP method from context"""
        context_lower = context.lower()

        # Check for explicit method definitions
        method_patterns = [
            (r'\.post\s*\(', 'POST'),
            (r'\.get\s*\(', 'GET'),
            (r'\.put\s*\(', 'PUT'),
            (r'\.delete\s*\(', 'DELETE'),
            (r'\.patch\s*\(', 'PATCH'),
            (r'method:\s*["\']post["\']', 'POST'),
            (r'method:\s*["\']get["\']', 'GET'),
            (r'method:\s*["\']put["\']', 'PUT'),
            (r'method:\s*["\']delete["\']', 'DELETE'),
            (r'method:\s*["\']patch["\']', 'PATCH'),
            (r'type:\s*["\']post["\']', 'POST'),
            (r'type:\s*["\']get["\']', 'GET'),
        ]

        for pattern, method in method_patterns:
            if re.search(pattern, context_lower):
                return method

        # Infer from endpoint name
        if any(word in endpoint.lower() for word in ['create', 'add', 'register', 'signup', 'login', 'upload']):
            return 'POST'
        elif any(word in endpoint.lower() for word in ['update', 'edit', 'modify']):
            return 'PUT'
        elif any(word in endpoint.lower() for word in ['delete', 'remove']):
            return 'DELETE'

        return 'GET'

    def _detect_content_type(self, context):
        """Detect content type from context"""
        context_lower = context.lower()

        if 'application/json' in context_lower or '"json"' in context_lower:
            return 'application/json'
        elif 'multipart/form-data' in context_lower or 'formdata' in context_lower:
            return 'multipart/form-data'
        elif 'application/x-www-form-urlencoded' in context_lower:
            return 'application/x-www-form-urlencoded'

        # Default to JSON for POST/PUT, none for GET
        return 'application/json'

    def _extract_parameters(self, endpoint, context):
        """Extract all types of parameters"""
        params = {
            'path_params': [],
            'query_params': [],
            'body_params': [],
            'all_params': []
        }

        # Path parameters: {id}, :id
        path_params = re.findall(r'[{:]([a-zA-Z0-9_]+)[}]?', endpoint)
        params['path_params'] = list(set(path_params))

        # Query parameters: ?id=1&name=test
        query_params = re.findall(r'[?&]([a-zA-Z0-9_]+)=', endpoint)
        params['query_params'] = list(set(query_params))

        # Body parameters from context
        body_patterns = [
            r'data:\s*\{([^}]+)\}',
            r'body:\s*\{([^}]+)\}',
            r'payload:\s*\{([^}]+)\}',
            r'params:\s*\{([^}]+)\}',
        ]

        for pattern in body_patterns:
            matches = re.findall(pattern, context)
            for match in matches:
                # Extract field names
                fields = re.findall(r'([a-zA-Z0-9_]+)\s*:', match)
                params['body_params'].extend(fields)

        params['body_params'] = list(set(params['body_params']))

        # All unique parameters
        all_params = set(params['path_params'] + params['query_params'] + params['body_params'])
        params['all_params'] = sorted(list(all_params))

        return params

    def _generate_sample_value(self, param_name):
        """Generate sample value based on parameter name"""
        param_lower = param_name.lower()

        if 'id' in param_lower:
            return 1
        elif 'uuid' in param_lower:
            return "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        elif 'email' in param_lower:
            return "user@example.com"
        elif 'phone' in param_lower:
            return "+1234567890"
        elif 'name' in param_lower:
            return "John Doe"
        elif 'password' in param_lower or 'pwd' in param_lower:
            return "SecurePass123!"
        elif 'token' in param_lower:
            return "sample_token_here"
        elif 'key' in param_lower:
            return "sample_key_here"
        elif 'date' in param_lower:
            return "2024-01-01"
        elif 'time' in param_lower:
            return "12:00:00"
        elif 'amount' in param_lower or 'price' in param_lower:
            return 100.00
        elif 'url' in param_lower:
            return "https://example.com"
        elif 'status' in param_lower:
            return "active"
        elif 'type' in param_lower:
            return "standard"
        elif 'count' in param_lower or 'num' in param_lower:
            return 10
        elif 'page' in param_lower:
            return 1
        elif 'limit' in param_lower or 'size' in param_lower:
            return 20
        else:
            return f"sample_{param_name}"

    def _generate_sample_request(self, endpoint_data):
        """Generate complete sample request"""
        endpoint = endpoint_data['endpoint']
        method = endpoint_data['method']
        params = endpoint_data['params']
        content_type = endpoint_data['content_type']

        # Build URL
        url = endpoint

        # Replace path parameters
        for param in params['path_params']:
            url = re.sub(f'[{{:]{param}[}}]?', str(self._generate_sample_value(param)), url)

        # Add query parameters
        if params['query_params']:
            query_parts = [f"{p}={self._generate_sample_value(p)}" for p in params['query_params']]
            separator = '&' if '?' in url else '?'
            url = f"{url}{separator}{'&'.join(query_parts)}"

        # Build request body
        body = None
        if method in ['POST', 'PUT', 'PATCH'] and params['body_params']:
            if content_type == 'application/json':
                body = {p: self._generate_sample_value(p) for p in params['body_params']}
            elif content_type == 'application/x-www-form-urlencoded':
                body = '&'.join([f"{p}={self._generate_sample_value(p)}" for p in params['body_params']])

        # Build complete URL with base
        if self.endpoint_base_url:
            full_url = f"{self.endpoint_base_url.rstrip('/')}{url}"

            # Add auth params
            if self.auth_params:
                separator = '&' if '?' in full_url else '?'
                full_url = f"{full_url}{separator}{self.auth_params}"
        else:
            full_url = url

        return {
            'url': full_url,
            'method': method,
            'headers': {
                'Content-Type': content_type
            } if content_type else {},
            'body': body,
            'curl': self._generate_curl_command(full_url, method, content_type, body)
        }

    def _generate_curl_command(self, url, method, content_type, body):
        """Generate curl command"""
        cmd = f"curl -X {method} \"{url}\""

        if content_type:
            cmd += f" \\\n  -H \"Content-Type: {content_type}\""

        if body:
            if isinstance(body, dict):
                cmd += f" \\\n  -d '{json.dumps(body)}'"
            else:
                cmd += f" \\\n  -d '{body}'"

        return cmd

    async def download_js_with_browser(self, page, url):
        """Download JS file using browser"""
        try:
            response = await page.goto(url, wait_until='networkidle', timeout=30000)

            if response and response.status == 200:
                content = await page.content()
                if '<script>' in content:
                    scripts = re.findall(r'<script[^>]*>(.*?)</script>', content, re.DOTALL)
                    if scripts:
                        content = scripts[0]

                try:
                    direct_content = await response.text()
                    if direct_content and len(direct_content) > len(content):
                        content = direct_content
                except:
                    pass

                self.js_content_cache[url] = content

                filename = url.split('/')[-1].replace('?', '_').replace(':', '_')
                filepath = os.path.join(self.output_dir, "downloaded_js", filename)
                with open(filepath, 'w', encoding='utf-8', errors='ignore') as f:
                    f.write(content)

                return True
            else:
                if self.verbose:
                    print(f"          ✗ Status {response.status if response else 'timeout'}")
                return False

        except Exception as e:
            if self.verbose:
                print(f"          ✗ Error: {str(e)[:40]}")
            return False

    async def extract_js_from_page(self, page):
        scripts = await page.query_selector_all('script[src]')
        for script in scripts:
            src = await script.get_attribute('src')
            if src:
                self._add_js_file(urljoin(page.url, src))

        content = await page.content()
        for url in re.findall(r'https?://[^\s<>"\']+\.js', content):
            self._add_js_file(url)

    async def crawl_page(self, page, url, depth=0):
        if depth > self.max_depth or url in self.visited_urls:
            return

        self.visited_urls.add(url)
        if depth == 0 or self.verbose:
            print(f"[Depth {depth:02d}] {url}")

        try:
            response = await page.goto(url, wait_until='networkidle', timeout=30000)
            if not response or response.status >= 400:
                return

            await page.wait_for_timeout(2000)
            await self.extract_js_from_page(page)

            if depth < self.max_depth:
                links = await page.query_selector_all('a[href]')
                hrefs = []

                for link in links[:150]:
                    try:
                        href = await link.get_attribute('href')
                        if href:
                            full_url = urljoin(page.url, href)
                            if self._is_internal_domain(full_url):
                                skip_ext = ('.pdf', '.zip', '.png', '.jpg')
                                if not full_url.endswith(skip_ext) and full_url not in self.visited_urls:
                                    hrefs.append(full_url)
                    except:
                        continue

                for href in hrefs[:40]:
                    await self.crawl_page(page, href, depth + 1)
        except:
            pass

    async def deep_crawl(self):
        print(f"\n{'='*80}")
        print(f"PHASE 1: DEEP CRAWLING")
        print(f"{'='*80}\n")

        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=['--no-sandbox', '--disable-setuid-sandbox']
            )

            context = await browser.new_context(
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            )

            page = await context.new_page()
            page.on('request', lambda req: self._add_js_file(req.url))

            await self.crawl_page(page, self.scan_url)
            await browser.close()

        print(f"\n{'='*80}")
        print(f"Found: {len(self.js_files)} JS files from HTML crawl")
        print(f"{'='*80}\n")

    async def download_all_js(self):
        """Download JS files that haven't been downloaded yet"""
        to_download = [url for url in self.js_files if url not in self.js_content_cache]
        
        if not to_download:
            return
        
        print(f"\n{'='*80}")
        print(f"DOWNLOADING: {len(to_download)} new JS files")
        print(f"{'='*80}\n")

        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=['--no-sandbox', '--disable-setuid-sandbox']
            )

            context = await browser.new_context(
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            )

            page = await context.new_page()

            for i, url in enumerate(sorted(to_download), 1):
                print(f"[{i:03d}/{len(to_download):03d}] {url}")
                await self.download_js_with_browser(page, url)

            await browser.close()

        print(f"\n{'='*80}")
        print(f"Total cached: {len(self.js_content_cache)}/{len(self.js_files)}")
        print(f"{'='*80}\n")

    def analyze_content(self, url, content):
        """Deep analysis of JS content"""
        secrets_found = 0
        endpoints_found = 0
        js_refs_found = 0

        # Beautify for better analysis
        try:
            opts = jsbeautifier.default_options()
            opts.indent_size = 2
            beautified = jsbeautifier.beautify(content, opts)
        except:
            beautified = content

        for analysis_content in [content, beautified]:
            # Find secrets
            for secret_type, patterns in self.secret_patterns.items():
                for pattern in patterns:
                    for match in re.finditer(pattern, analysis_content, re.IGNORECASE):
                        secret_value = match.group(1) if match.groups() else match.group(0)

                        if self._is_valid_secret(secret_type, secret_value):
                            start = max(0, match.start() - 100)
                            end = min(len(analysis_content), match.end() + 100)
                            context = analysis_content[start:end].replace('\n', ' ').strip()

                            self.secrets.append({
                                'type': secret_type,
                                'value': secret_value,
                                'file': url,
                                'context': context
                            })
                            secrets_found += 1

            # Find endpoints with comprehensive analysis
            for pattern in self.endpoint_patterns:
                for match in re.finditer(pattern, analysis_content):
                    endpoint = match.group(1) if match.groups() else match.group(0)

                    if self._is_valid_endpoint(endpoint):
                        # Get surrounding context for analysis
                        start = max(0, match.start() - 500)
                        end = min(len(analysis_content), match.end() + 500)
                        context = analysis_content[start:end]

                        # Detect HTTP method
                        method = self._detect_http_method(endpoint, context)

                        # Detect content type
                        content_type = self._detect_content_type(context) if method in ['POST', 'PUT', 'PATCH'] else None

                        # Extract parameters
                        params = self._extract_parameters(endpoint, context)

                        endpoint_data = {
                            'endpoint': endpoint,
                            'file': url,
                            'method': method,
                            'content_type': content_type,
                            'params': params,
                            'has_params': len(params['all_params']) > 0,
                            'context_snippet': context[:200].replace('\n', ' ').strip()
                        }

                        self.endpoints.append(endpoint_data)
                        endpoints_found += 1

        # Extract referenced JS files (RECURSIVE DISCOVERY)
        if url not in self.processed_js_files:
            new_js_files = self.extract_js_from_js_content(url, content)
            for js_file in new_js_files:
                self.js_files.add(js_file)
                js_refs_found += 1
            self.processed_js_files.add(url)

        return secrets_found, endpoints_found, js_refs_found

    def analyze_all_downloaded(self):
        """Analyze all downloaded JS files"""
        to_analyze = [url for url in self.js_content_cache.keys() if url not in self.processed_js_files]
        
        if not to_analyze:
            return
        
        print(f"\n{'='*80}")
        print(f"ANALYZING: {len(to_analyze)} JS files")
        print(f"{'='*80}\n")

        total_js_refs = 0
        for i, url in enumerate(sorted(to_analyze), 1):
            content = self.js_content_cache[url]
            secrets, endpoints, js_refs = self.analyze_content(url, content)
            total_js_refs += js_refs
            print(f"[{i:03d}/{len(to_analyze):03d}] {url}")
            print(f"          ✓ Secrets: {secrets}, Endpoints: {endpoints}, JS Refs: {js_refs}")

        print(f"\n{'='*80}")
        print(f"Found {total_js_refs} new JS file references")
        print(f"{'='*80}\n")

    def generate_samples(self):
        print(f"\n{'='*80}")
        print(f"PHASE 4: GENERATING SAMPLES")
        print(f"{'='*80}\n")

        # Deduplicate endpoints
        unique = {}
        for ep in self.endpoints:
            key = (ep['endpoint'], ep['method'])
            if key not in unique:
                unique[key] = ep

        print(f"Unique endpoints: {len(unique)}")

        # Generate samples
        for (endpoint, method), ep_data in unique.items():
            sample = self._generate_sample_request(ep_data)

            self.sample_requests.append({
                **ep_data,
                'sample': sample
            })

            self.complete_urls.append(sample['url'])

        print(f"Generated: {len(self.sample_requests)} sample requests\n")

    def save_results(self):
        # JS files
        with open(os.path.join(self.output_dir, "01_js_files.txt"), 'w') as f:
            f.write(f"JS FILES: {len(self.js_files)}\n{'='*80}\n\n")
            for url in sorted(self.js_files):
                downloaded = "✓" if url in self.js_content_cache else "✗"
                f.write(f"[{downloaded}] {url}\n")

        # Secrets
        unique_secrets = []
        seen = set()
        for s in self.secrets:
            key = (s['type'], s['value'])
            if key not in seen:
                seen.add(key)
                unique_secrets.append(s)

        if unique_secrets:
            with open(os.path.join(self.output_dir, "02_secrets.txt"), 'w') as f:
                f.write(f"SECRETS FOUND: {len(unique_secrets)}\n{'='*80}\n\n")
                by_type = defaultdict(list)
                for s in unique_secrets:
                    by_type[s['type']].append(s)

                for stype in sorted(by_type.keys()):
                    f.write(f"\n{stype.upper()} ({len(by_type[stype])})\n{'-'*80}\n")
                    for s in by_type[stype]:
                        f.write(f"Value: {s['value']}\n")
                        f.write(f"File: {s['file']}\n")
                        f.write(f"Context: {s['context'][:200]}...\n\n")

            with open(os.path.join(self.output_dir, "02_secrets.json"), 'w') as f:
                json.dump(unique_secrets, f, indent=2)

        # Endpoints detailed
        if self.sample_requests:
            with open(os.path.join(self.output_dir, "03_endpoints_detailed.txt"), 'w') as f:
                f.write(f"ENDPOINTS WITH FULL ANALYSIS: {len(self.sample_requests)}\n{'='*80}\n\n")

                for req in sorted(self.sample_requests, key=lambda x: (x['method'], x['endpoint'])):
                    f.write(f"\n{'='*80}\n")
                    f.write(f"Endpoint: {req['endpoint']}\n")
                    f.write(f"Method: {req['method']}\n")
                    f.write(f"Content-Type: {req['content_type'] or 'N/A'}\n")
                    f.write(f"File: {req['file']}\n")

                    if req['params']['path_params']:
                        f.write(f"Path Parameters: {', '.join(req['params']['path_params'])}\n")
                    if req['params']['query_params']:
                        f.write(f"Query Parameters: {', '.join(req['params']['query_params'])}\n")
                    if req['params']['body_params']:
                        f.write(f"Body Parameters: {', '.join(req['params']['body_params'])}\n")

                    f.write(f"\nSample URL:\n{req['sample']['url']}\n")

                    if req['sample']['body']:
                        f.write(f"\nSample Body:\n")
                        if isinstance(req['sample']['body'], dict):
                            f.write(json.dumps(req['sample']['body'], indent=2))
                        else:
                            f.write(req['sample']['body'])
                        f.write("\n")

                    f.write(f"\n{'-'*80}\n")

            with open(os.path.join(self.output_dir, "03_endpoints_detailed.json"), 'w') as f:
                json.dump(self.sample_requests, f, indent=2)

        # Endpoints by method
        if self.sample_requests:
            by_method = defaultdict(list)
            for req in self.sample_requests:
                by_method[req['method']].append(req)

            with open(os.path.join(self.output_dir, "04_endpoints_by_method.txt"), 'w') as f:
                f.write(f"ENDPOINTS GROUPED BY HTTP METHOD\n{'='*80}\n\n")

                for method in sorted(by_method.keys()):
                    f.write(f"\n{method} ({len(by_method[method])} endpoints)\n{'-'*80}\n")
                    for req in sorted(by_method[method], key=lambda x: x['endpoint']):
                        f.write(f"{req['endpoint']}")
                        if req['params']['all_params']:
                            f.write(f" [{', '.join(req['params']['all_params'])}]")
                        f.write("\n")

        # Complete URLs
        if self.complete_urls:
            with open(os.path.join(self.output_dir, "05_complete_urls.txt"), 'w') as f:
                f.write(f"COMPLETE URLs: {len(self.complete_urls)}\n{'='*80}\n\n")
                for url in sorted(set(self.complete_urls)):
                    f.write(f"{url}\n")

        # cURL commands
        if self.sample_requests:
            with open(os.path.join(self.output_dir, "06_curl_commands.sh"), 'w') as f:
                f.write("#!/bin/bash\n\n")
                f.write(f"# Generated curl commands\n")
                f.write(f"# Total: {len(self.sample_requests)} endpoints\n\n")

                for req in self.sample_requests:
                    f.write(f"# {req['method']} {req['endpoint']}\n")
                    f.write(f"{req['sample']['curl']}\n\n")

            os.chmod(os.path.join(self.output_dir, "06_curl_commands.sh"), 0o755)

        # Postman collection
        if self.sample_requests:
            postman = {
                "info": {
                    "name": f"API Collection - {self.base_domain}",
                    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
                },
                "item": []
            }

            by_method = defaultdict(list)
            for req in self.sample_requests:
                by_method[req['method']].append(req)

            for method, requests in by_method.items():
                folder = {
                    "name": method,
                    "item": []
                }

                for req in requests:
                    item = {
                        "name": req['endpoint'],
                        "request": {
                            "method": req['method'],
                            "header": [{"key": k, "value": v} for k, v in req['sample']['headers'].items()],
                            "url": req['sample']['url']
                        }
                    }

                    if req['sample']['body']:
                        item['request']['body'] = {
                            "mode": "raw",
                            "raw": json.dumps(req['sample']['body'], indent=2) if isinstance(req['sample']['body'], dict) else req['sample']['body']
                        }

                    folder['item'].append(item)

                postman['item'].append(folder)

            with open(os.path.join(self.output_dir, "07_postman_collection.json"), 'w') as f:
                json.dump(postman, f, indent=2)

        # Summary
        with open(os.path.join(self.output_dir, "00_SUMMARY.txt"), 'w') as f:
            f.write(f"COMPREHENSIVE SCAN SUMMARY\n{'='*80}\n")
            f.write(f"Target: {self.scan_url}\n")
            f.write(f"Endpoint Base: {self.endpoint_base_url}\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"{'='*80}\n")
            f.write(f"RESULTS:\n")
            f.write(f"{'='*80}\n")
            f.write(f"JS Files Found: {len(self.js_files)}\n")
            f.write(f"JS Files Downloaded: {len(self.js_content_cache)}\n")
            f.write(f"Secrets Found: {len(unique_secrets)}\n")
            f.write(f"Unique Endpoints: {len(self.sample_requests)}\n")
            f.write(f"Complete URLs: {len(set(self.complete_urls))}\n\n")

            if unique_secrets:
                f.write(f"SECRET TYPES:\n{'-'*80}\n")
                by_type = defaultdict(int)
                for s in unique_secrets:
                    by_type[s['type']] += 1
                for stype, count in sorted(by_type.items()):
                    f.write(f"  {stype}: {count}\n")
                f.write("\n")

            if self.sample_requests:
                f.write(f"HTTP METHODS:\n{'-'*80}\n")
                by_method = defaultdict(int)
                for req in self.sample_requests:
                    by_method[req['method']] += 1
                for method, count in sorted(by_method.items()):
                    f.write(f"  {method}: {count}\n")
                f.write("\n")

                f.write(f"ENDPOINTS WITH PARAMETERS:\n{'-'*80}\n")
                with_params = sum(1 for req in self.sample_requests if req['has_params'])
                f.write(f"  With Parameters: {with_params}\n")
                f.write(f"  Without Parameters: {len(self.sample_requests) - with_params}\n")

        print(f"{'='*80}")
        print(f"FINAL RESULTS")
        print(f"{'='*80}")
        print(f"Output: {self.output_dir}/")
        print(f"JS Files: {len(self.js_files)} ({len(self.js_content_cache)} downloaded)")
        print(f"Secrets: {len(unique_secrets)}")
        print(f"Endpoints: {len(self.sample_requests)}")
        print(f"Complete URLs: {len(set(self.complete_urls))}")
        print(f"{'='*80}\n")
        print(f"Files Generated:")
        print(f"  00_SUMMARY.txt - Overview")
        print(f"  01_js_files.txt - All JS files")
        print(f"  02_secrets.txt/.json - Secrets found")
        print(f"  03_endpoints_detailed.txt/.json - Full endpoint analysis")
        print(f"  04_endpoints_by_method.txt - Grouped by HTTP method")
        print(f"  05_complete_urls.txt - All URLs")
        print(f"  06_curl_commands.sh - Ready-to-use cURL commands")
        print(f"  07_postman_collection.json - Import to Postman")
        print(f"  downloaded_js/ - All JS files")
        print(f"{'='*80}\n")

    async def run(self):
        start = datetime.now()

        print(f"\n{'#'*80}")
        print(f"#{'ADVANCED JS SECURITY SCANNER WITH RECURSIVE DISCOVERY':^78}#")
        print(f"#{'100% Automation - Complete Analysis':^78}#")
        print(f"{'#'*80}\n")

        # Phase 1: Initial crawl
        await self.deep_crawl()
        
        # Phase 2-N: Recursive download and analysis
        max_passes = 5
        for pass_num in range(1, max_passes + 1):
            print(f"\n{'#'*80}")
            print(f"# PASS {pass_num}/{max_passes}")
            print(f"{'#'*80}")
            
            initial_js_count = len(self.js_files)
            
            # Download new JS files
            await self.download_all_js()
            
            # Analyze them (which discovers more JS files)
            self.analyze_all_downloaded()
            
            new_js_count = len(self.js_files)
            newly_found = new_js_count - initial_js_count
            
            print(f"\n{'='*80}")
            print(f"Pass {pass_num} Summary:")
            print(f"  New JS files discovered: {newly_found}")
            print(f"  Total JS files: {new_js_count}")
            print(f"  Downloaded: {len(self.js_content_cache)}")
            print(f"  Analyzed: {len(self.processed_js_files)}")
            print(f"{'='*80}\n")
            
            # Stop if no new files found
            if newly_found == 0:
                print(f"✓ No new JS files found. Recursive discovery complete!\n")
                break
        
        # Final phase: Generate samples
        self.generate_samples()
        self.save_results()

        print(f"\n{'='*80}")
        print(f"SCAN COMPLETE!")
        print(f"Total Time: {datetime.now() - start}")
        print(f"{'='*80}\n")

def main():
    parser = argparse.ArgumentParser(
        description='Advanced JS Security Scanner with Recursive Discovery',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example:
  python3 advanced_js_scanner.py https://example.com https://api.example.com \\
    --auth "uid=123&key=abc&type=2"

Features:
  ✓ Recursive JS file discovery (finds imports within JS files)
  ✓ HTTP method detection (GET, POST, PUT, DELETE, PATCH)
  ✓ Content-Type detection (JSON, form-data, urlencoded)
  ✓ Parameter extraction (path, query, body)
  ✓ Sample request generation
  ✓ cURL command generation
  ✓ Postman collection export
  ✓ Secret detection (API keys, tokens, credentials)
  ✓ Complete endpoint analysis
  ✓ No duplicate processing
        """
    )

    parser.add_argument('scan_url', help='URL to scan')
    parser.add_argument('endpoint_base', help='Base URL for endpoints')
    parser.add_argument('-d', '--depth', type=int, default=11, help='Max crawl depth (default: 11)')
    parser.add_argument('--auth', help='Auth parameters (e.g., "uid=123&key=abc")')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    scanner = AdvancedJSScanner(
        args.scan_url,
        args.endpoint_base,
        max_depth=args.depth,
        auth_params=args.auth,
        verbose=args.verbose
    )

    asyncio.run(scanner.run())

if __name__ == "__main__":
    main()
