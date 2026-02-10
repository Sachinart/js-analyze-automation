#!/usr/bin/env python3
"""
EndpointHunter - Burp-Style Passive Endpoint & Parameter Discovery
Intercepts ALL network traffic + deep JS analysis + recursive crawling
Outputs: GET urls, POST urls, curl commands, full endpoint map
"""

import asyncio
import re
import json
import argparse
import os
import sys
import hashlib
from pathlib import Path
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs, urlencode, quote
from datetime import datetime
from collections import defaultdict, OrderedDict

try:
    from playwright.async_api import async_playwright
except ImportError:
    print("[!] playwright not installed. Run: pip install playwright && playwright install chromium")
    sys.exit(1)

try:
    import jsbeautifier
    HAS_BEAUTIFIER = True
except ImportError:
    HAS_BEAUTIFIER = False


# ─────────────────────────────────────────────────────────────────────────────
# Color helpers
# ─────────────────────────────────────────────────────────────────────────────
class C:
    R = "\033[91m"
    G = "\033[92m"
    Y = "\033[93m"
    B = "\033[94m"
    M = "\033[95m"
    CY = "\033[96m"
    W = "\033[97m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    END = "\033[0m"


def banner():
    print(f"""{C.CY}
 ╔═══════════════════════════════════════════════════════════════════╗
 ║  {C.BOLD}EndpointHunter v2.0{C.END}{C.CY} — Burp-Style Passive Endpoint Discovery   ║
 ║  Network Intercept + JS Analysis + Recursive Deep Crawl         ║
 ╚═══════════════════════════════════════════════════════════════════╝{C.END}
""")


# ─────────────────────────────────────────────────────────────────────────────
# Main Scanner
# ─────────────────────────────────────────────────────────────────────────────
class EndpointHunter:

    def __init__(self, target_url, max_depth=10, auth_params=None, verbose=False,
                 headless=True, timeout=60, max_pages=500):
        self.target_url = target_url.rstrip("/")
        self.max_depth = max_depth
        self.auth_params = auth_params or ""
        self.verbose = verbose
        self.headless = headless
        self.timeout = timeout
        self.max_pages = max_pages

        parsed = urlparse(self.target_url)
        self.scheme = parsed.scheme
        self.base_domain = self._get_base_domain(parsed.netloc)
        self.origin = f"{parsed.scheme}://{parsed.netloc}"

        # ── Data stores ──
        self.visited_pages = set()
        self.discovered_pages = set()  # pages to visit
        self.js_files = set()
        self.js_content_cache = {}
        self.analyzed_js = set()

        # Network-intercepted requests (the gold — like Burp's HTTP history)
        self.intercepted_requests = []  # raw request objects
        self.intercepted_urls = set()

        # Final organized results
        self.get_endpoints = OrderedDict()   # url -> {params, source, ...}
        self.post_endpoints = OrderedDict()  # url -> {params, body, headers, ...}
        self.other_endpoints = OrderedDict() # PUT/DELETE/PATCH etc

        # From JS static analysis
        self.js_extracted_endpoints = []
        self.js_extracted_secrets = []

        # Output
        self.output_dir = self._create_output_dir()

        # Secret patterns
        self.secret_patterns = {
            'API Key': [r'(?i)(?:api[_-]?key|apikey)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']'],
            'Secret/Token': [
                r'(?i)(?:secret|token|auth)[_-]?(?:key)?["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']',
            ],
            'Bearer Token': [r'(?i)bearer\s+([a-zA-Z0-9_\-\.]{30,})'],
            'JWT': [r'eyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}'],
            'AWS Key': [r'AKIA[0-9A-Z]{16}'],
            'Google API Key': [r'AIza[0-9A-Za-z_\-]{35}'],
            'Private Key': [r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'],
            'Database URL': [r'(?:mongodb(?:\+srv)?|mysql|postgres(?:ql)?|redis)://[^\s"\'<>]+'],
            'Password in URL': [r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{4,})["\']'],
        }

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _get_base_domain(self, netloc):
        parts = netloc.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return netloc

    def _is_same_scope(self, url):
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            return domain == urlparse(self.target_url).netloc or \
                   domain.endswith("." + self.base_domain) or \
                   self.base_domain in domain
        except:
            return False

    def _create_output_dir(self):
        domain = urlparse(self.target_url).netloc.replace("www.", "")
        safe = re.sub(r'[^\w\-.]', '_', domain)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        d = f"hunt_{safe}_{ts}"
        Path(d).mkdir(parents=True, exist_ok=True)
        Path(os.path.join(d, "js_files")).mkdir(exist_ok=True)
        return d

    def _normalize_url(self, url):
        """Normalize URL: keep scheme, host, path, sorted query params"""
        try:
            parsed = urlparse(url)
            # Sort query params for dedup
            params = parse_qs(parsed.query, keep_blank_values=True)
            sorted_query = urlencode(
                {k: v[0] if len(v) == 1 else v for k, v in sorted(params.items())},
                doseq=True
            )
            return urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                '', sorted_query, ''
            ))
        except:
            return url

    def _url_signature(self, url):
        """Create a structural signature for dedup — replaces numeric path segments with {id}"""
        parsed = urlparse(url)
        path_parts = parsed.path.split("/")
        sig_parts = []
        for part in path_parts:
            if re.match(r'^\d+$', part):
                sig_parts.append("{id}")
            elif re.match(r'^[a-f0-9]{8,}$', part, re.I):
                sig_parts.append("{hash}")
            else:
                sig_parts.append(part)
        sig_path = "/".join(sig_parts)

        # For query params, keep keys but replace values with placeholder
        params = parse_qs(parsed.query, keep_blank_values=True)
        sig_params = "&".join(f"{k}=*" for k in sorted(params.keys()))

        return f"{parsed.netloc}{sig_path}?{sig_params}" if sig_params else f"{parsed.netloc}{sig_path}"

    def _log(self, msg, level="info"):
        colors = {"info": C.CY, "ok": C.G, "warn": C.Y, "err": C.R, "dim": C.DIM}
        c = colors.get(level, C.W)
        print(f"  {c}{msg}{C.END}")

    def _vlog(self, msg):
        if self.verbose:
            print(f"  {C.DIM}{msg}{C.END}")

    # ── Network Interception (THE KEY — like Burp proxy) ─────────────────────

    def _on_request(self, request):
        """Intercept every network request the browser makes"""
        url = request.url
        method = request.method
        headers = dict(request.headers) if request.headers else {}
        post_data = request.post_data

        # Skip data URIs, blobs, chrome-extension, etc.
        if not url.startswith("http"):
            return

        # Skip obvious static assets for endpoint collection
        skip_ext = ('.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff',
                    '.woff2', '.ttf', '.eot', '.mp4', '.mp3', '.webp', '.avif')
        parsed = urlparse(url)
        if any(parsed.path.lower().endswith(ext) for ext in skip_ext):
            return

        # Record JS files
        if parsed.path.endswith('.js'):
            if self._is_same_scope(url):
                clean = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))
                self.js_files.add(clean)
            return  # don't record .js as endpoints

        # Skip CSS
        if parsed.path.endswith('.css'):
            return

        # Store the intercepted request
        req_data = {
            'url': url,
            'method': method.upper(),
            'headers': headers,
            'post_data': post_data,
            'parsed': parsed,
        }
        self.intercepted_requests.append(req_data)
        self.intercepted_urls.add(url)

    def _on_response(self, response):
        """Capture response details for richer context"""
        url = response.url
        # Track content types to identify API responses
        content_type = response.headers.get('content-type', '')
        if 'application/json' in content_type:
            self._vlog(f"[API-JSON] {response.request.method} {url}")

    # ── Page Crawling ────────────────────────────────────────────────────────

    async def _extract_links_from_page(self, page):
        """Extract all navigable links, form actions, JS triggers from the page DOM"""
        links = set()

        try:
            # 1. <a href>
            anchors = await page.eval_on_selector_all(
                'a[href]',
                '(els) => els.map(e => e.href).filter(h => h && h.startsWith("http"))'
            )
            links.update(anchors)

            # 2. <form action>
            forms = await page.eval_on_selector_all(
                'form[action]',
                '''(els) => els.map(e => ({
                    action: e.action,
                    method: (e.method || "GET").toUpperCase(),
                    inputs: Array.from(e.querySelectorAll("input,select,textarea")).map(i => ({
                        name: i.name || i.id || "",
                        type: i.type || "text",
                        value: i.value || ""
                    })).filter(i => i.name)
                }))'''
            )
            for form in forms:
                if form.get('action'):
                    links.add(form['action'])
                    # Record form as POST endpoint
                    if form['method'] == 'POST':
                        self._record_form_endpoint(form)

            # 3. <iframe src>
            iframes = await page.eval_on_selector_all(
                'iframe[src]',
                '(els) => els.map(e => e.src).filter(s => s && s.startsWith("http"))'
            )
            links.update(iframes)

            # 4. data-href, data-url, data-src attributes
            data_urls = await page.evaluate('''() => {
                const urls = [];
                document.querySelectorAll("[data-href],[data-url],[data-src],[data-link]").forEach(el => {
                    ["data-href","data-url","data-src","data-link"].forEach(attr => {
                        const v = el.getAttribute(attr);
                        if (v && (v.startsWith("http") || v.startsWith("/"))) urls.push(v);
                    });
                });
                return urls;
            }''')
            for u in data_urls:
                if u.startswith("/"):
                    u = urljoin(page.url, u)
                links.add(u)

            # 5. onclick handlers with URLs
            onclick_urls = await page.evaluate('''() => {
                const urls = [];
                document.querySelectorAll("[onclick]").forEach(el => {
                    const oc = el.getAttribute("onclick");
                    const m = oc.match(/(?:location|window\\.location|href)\\s*=\\s*['"](.*?)['"]/);
                    if (m) urls.push(m[1]);
                    const m2 = oc.match(/(?:navigate|goto|open)\\s*\\(['"](.*?)['"]/);
                    if (m2) urls.push(m2[1]);
                });
                return urls;
            }''')
            for u in onclick_urls:
                if u.startswith("/"):
                    u = urljoin(page.url, u)
                if u.startswith("http"):
                    links.add(u)

            # 6. Extract URLs from inline scripts
            inline_scripts = await page.eval_on_selector_all(
                'script:not([src])',
                '(els) => els.map(e => e.textContent)'
            )
            for script_text in inline_scripts:
                if script_text:
                    self._extract_urls_from_text(script_text, page.url, links)

            # 7. Extract URLs from the full page HTML
            html = await page.content()
            self._extract_urls_from_text(html, page.url, links)

        except Exception as e:
            self._vlog(f"Link extraction error: {e}")

        return links

    def _extract_urls_from_text(self, text, base_url, link_set):
        """Extract URLs and API endpoints from raw text/JS content"""

        # Full URLs
        for m in re.finditer(r'https?://[^\s"\'<>\)\]\}\\]+', text):
            url = m.group(0).rstrip(',;.')
            link_set.add(url)

        # Relative paths that look like pages or API endpoints
        # /path/to/thing, /api/v1/users, /all?type=X
        for m in re.finditer(r'["\'](/[a-zA-Z][a-zA-Z0-9_/\-\.]*(?:\?[a-zA-Z0-9_=&%\+\-\.]*)?)["\']', text):
            path = m.group(1)
            if not any(path.endswith(ext) for ext in ('.js', '.css', '.png', '.jpg', '.svg', '.ico', '.woff', '.woff2')):
                full = urljoin(base_url, path)
                link_set.add(full)

        # Template literal paths: `/api/users/${id}`
        for m in re.finditer(r'`(/[a-zA-Z][a-zA-Z0-9_/${\}/\-\.]*(?:\?[^`]*)?)`', text):
            path = m.group(1)
            # Replace ${...} with placeholder
            path = re.sub(r'\$\{[^}]+\}', '1', path)
            if not any(path.endswith(ext) for ext in ('.js', '.css', '.png', '.jpg')):
                full = urljoin(base_url, path)
                link_set.add(full)

        # String concatenation patterns: "/api/" + version + "/users"
        # We just extract the static parts
        for m in re.finditer(r'["\'](/(?:api|v\d+|auth|user|admin|app|data|search|config)[a-zA-Z0-9_/\-]*)["\']', text):
            path = m.group(1)
            full = urljoin(base_url, path)
            link_set.add(full)

    def _record_form_endpoint(self, form):
        """Record a form as a POST endpoint"""
        url = form['action']
        params = {inp['name']: inp.get('value', '') for inp in form.get('inputs', []) if inp['name']}
        key = self._normalize_url(url)

        if key not in self.post_endpoints:
            self.post_endpoints[key] = {
                'url': url,
                'method': form['method'],
                'params': params,
                'content_type': 'application/x-www-form-urlencoded',
                'source': 'html_form',
            }

    async def _interact_with_page(self, page):
        """Simulate user interactions to trigger dynamic requests"""
        try:
            # Scroll to bottom to trigger lazy loading
            await page.evaluate('''async () => {
                const delay = ms => new Promise(r => setTimeout(r, ms));
                const height = document.body.scrollHeight;
                const step = Math.max(300, height / 10);
                for (let y = 0; y < height; y += step) {
                    window.scrollTo(0, y);
                    await delay(200);
                }
                window.scrollTo(0, 0);
            }''')
            await page.wait_for_timeout(1500)

            # Click tabs / navigation items to trigger API calls
            tab_selectors = [
                '[role="tab"]', '.tab', '.nav-item', '.nav-link',
                '[data-toggle="tab"]', '.menu-item', '.category',
                'button[data-type]', 'a[data-type]',
                '[class*="tab"]', '[class*="filter"]',
            ]
            for selector in tab_selectors:
                try:
                    elements = await page.query_selector_all(selector)
                    for el in elements[:8]:  # limit clicks per selector
                        try:
                            visible = await el.is_visible()
                            if visible:
                                await el.click(timeout=2000)
                                await page.wait_for_timeout(800)
                        except:
                            pass
                except:
                    pass

            # Trigger any pagination
            pagination_selectors = [
                'a[href*="page="]', 'button[data-page]', '.pagination a',
                '[class*="pager"] a', '[class*="next"]',
            ]
            for selector in pagination_selectors:
                try:
                    elements = await page.query_selector_all(selector)
                    for el in elements[:3]:
                        try:
                            visible = await el.is_visible()
                            if visible:
                                await el.click(timeout=2000)
                                await page.wait_for_timeout(800)
                        except:
                            pass
                except:
                    pass

        except Exception as e:
            self._vlog(f"Interaction error: {e}")

    async def _crawl_page(self, page, url, depth=0):
        """Visit a page, intercept traffic, extract links, recurse"""
        if depth > self.max_depth:
            return
        if url in self.visited_pages:
            return
        if len(self.visited_pages) >= self.max_pages:
            return
        if not self._is_same_scope(url):
            return

        # Skip obvious non-page URLs
        parsed = urlparse(url)
        skip_ext = ('.pdf', '.zip', '.tar', '.gz', '.exe', '.dmg',
                    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.mp4', '.mp3')
        if any(parsed.path.lower().endswith(ext) for ext in skip_ext):
            return

        self.visited_pages.add(url)

        depth_indicator = "│ " * depth + "├─"
        print(f"  {C.B}{depth_indicator}{C.END} {C.W}[{len(self.visited_pages):03d}] depth={depth}{C.END} {url[:100]}")

        try:
            response = await page.goto(url, wait_until='domcontentloaded', timeout=self.timeout * 1000)
            if not response:
                return

            # Wait for network to settle (catches XHR/fetch calls)
            try:
                await page.wait_for_load_state('networkidle', timeout=10000)
            except:
                pass

            await page.wait_for_timeout(1500)

            # Interact with the page to trigger dynamic content
            await self._interact_with_page(page)

            # Extract JS file references
            scripts = await page.query_selector_all('script[src]')
            for s in scripts:
                src = await s.get_attribute('src')
                if src:
                    full = urljoin(page.url, src)
                    if self._is_same_scope(full):
                        clean = urlunparse((urlparse(full).scheme, urlparse(full).netloc,
                                          urlparse(full).path, '', '', ''))
                        self.js_files.add(clean)

            # Extract all links from the page
            links = await self._extract_links_from_page(page)

            # Filter & queue new pages
            new_pages = set()
            for link in links:
                if self._is_same_scope(link) and link not in self.visited_pages:
                    new_pages.add(link)

            # Recurse into discovered pages
            for link in sorted(new_pages):
                if len(self.visited_pages) >= self.max_pages:
                    break
                await self._crawl_page(page, link, depth + 1)

        except Exception as e:
            self._vlog(f"Crawl error on {url}: {str(e)[:60]}")

    # ── JS Analysis ──────────────────────────────────────────────────────────

    async def _download_js_files(self, page):
        """Download all discovered JS files"""
        to_download = [u for u in self.js_files if u not in self.js_content_cache]
        if not to_download:
            return

        print(f"\n  {C.Y}Downloading {len(to_download)} JS files...{C.END}")

        for i, url in enumerate(sorted(to_download), 1):
            try:
                resp = await page.goto(url, wait_until='load', timeout=15000)
                if resp and resp.status == 200:
                    content = await resp.text()
                    self.js_content_cache[url] = content

                    # Save to disk
                    fname = re.sub(r'[^\w\-.]', '_', url.split('/')[-1])[:100]
                    fpath = os.path.join(self.output_dir, "js_files", fname)
                    with open(fpath, 'w', encoding='utf-8', errors='ignore') as f:
                        f.write(content)

                    if self.verbose:
                        print(f"    [{i:03d}] ✓ {url[:80]}")
            except:
                pass

        print(f"  {C.G}Downloaded: {len(self.js_content_cache)}/{len(self.js_files)}{C.END}")

    def _analyze_js_content(self, url, content):
        """Deep JS analysis: endpoints, params, secrets, more JS refs"""
        if url in self.analyzed_js:
            return 0
        self.analyzed_js.add(url)

        # Optionally beautify
        if HAS_BEAUTIFIER:
            try:
                opts = jsbeautifier.default_options()
                opts.indent_size = 2
                content = jsbeautifier.beautify(content, opts)
            except:
                pass

        found = 0

        # ── Extract endpoints with context ──

        # API-style paths
        ep_patterns = [
            r'["\'`](/(?:api|v\d+|auth|graphql|rest|rpc)/[a-zA-Z0-9_/\-{}:?=&\.\+%]+)["\'`]',
            r'["\'`](/[a-zA-Z][a-zA-Z0-9_\-]*/[a-zA-Z0-9_/\-{}:?=&\.\+%]+)["\'`]',
            r'(?:url|path|endpoint|href|action|route|api)\s*[:=]\s*["\'`](/[a-zA-Z0-9_/\-{}:?=&\.\+%]+)["\'`]',
            r'(?:fetch|axios|ajax|\$\.(?:get|post|put|delete))\s*\(\s*["\'`](/[a-zA-Z0-9_/\-{}:?=&\.\+%]+)["\'`]',
            r'(?:fetch|axios|ajax|\$\.(?:get|post|put|delete))\s*\(\s*["\'`](https?://[^\s"\'`]+)["\'`]',
            # Query-param style: "/path?key=val"
            r'["\'`](/[a-zA-Z][a-zA-Z0-9_/\-]*\?[a-zA-Z0-9_=&%\+\-\.]+)["\'`]',
            # Template literals with variable substitution
            r'`(/[a-zA-Z][a-zA-Z0-9_/${\}/\-\.]*(?:\?[^`]*)?)`',
        ]

        for pattern in ep_patterns:
            for m in re.finditer(pattern, content):
                endpoint = m.group(1)

                # Skip static assets
                if any(endpoint.lower().endswith(ext) for ext in
                       ('.js', '.css', '.png', '.jpg', '.gif', '.svg', '.ico', '.woff')):
                    continue

                # Clean template literals
                endpoint = re.sub(r'\$\{[^}]+\}', '1', endpoint)

                # Get surrounding context (1000 chars each side)
                start = max(0, m.start() - 1000)
                end = min(len(content), m.end() + 1000)
                context = content[start:end]

                # Detect method
                method = self._detect_method(endpoint, context)

                # Detect content type
                ct = self._detect_content_type(context) if method in ('POST', 'PUT', 'PATCH') else None

                # Extract params
                params = self._extract_params(endpoint, context)

                # Build full URL
                if endpoint.startswith("http"):
                    full_url = endpoint
                else:
                    full_url = self.origin + endpoint

                self.js_extracted_endpoints.append({
                    'endpoint': endpoint,
                    'full_url': full_url,
                    'method': method,
                    'content_type': ct,
                    'params': params,
                    'source_js': url,
                })
                found += 1

        # ── Extract secrets ──
        for sec_type, patterns in self.secret_patterns.items():
            for pattern in patterns:
                for m in re.finditer(pattern, content, re.I):
                    val = m.group(1) if m.groups() else m.group(0)
                    if val and len(val) >= 8:
                        skip = ('placeholder', 'example', 'test', 'xxx', 'null', 'undefined', 'localhost')
                        if not any(s in val.lower() for s in skip):
                            start = max(0, m.start() - 80)
                            end = min(len(content), m.end() + 80)
                            ctx = content[start:end].replace('\n', ' ').strip()
                            self.js_extracted_secrets.append({
                                'type': sec_type,
                                'value': val,
                                'file': url,
                                'context': ctx[:300],
                            })

        # ── Find more JS file references ──
        js_ref_patterns = [
            r'import\s*\(\s*["\']([^"\']+\.js)["\']',
            r'import\s+.*?\s+from\s+["\']([^"\']+\.js)["\']',
            r'require\s*\(\s*["\']([^"\']+\.js)["\']',
            r'["\']([^"\']*?[a-zA-Z0-9_\-]+\.[a-f0-9]{6,}\.js)["\']',
            r'["\']([^"\']*?assets/[a-zA-Z0-9_\-\.]+\.js)["\']',
            r'["\'](\./[a-zA-Z0-9_\-/]+\.js)["\']',
            r'["\'](/[a-zA-Z0-9_\-/]+\.js)["\']',
        ]
        for pattern in js_ref_patterns:
            for m in re.finditer(pattern, content):
                ref = m.group(1)
                if ref.startswith('http'):
                    if self._is_same_scope(ref):
                        clean = urlunparse((urlparse(ref).scheme, urlparse(ref).netloc,
                                          urlparse(ref).path, '', '', ''))
                        self.js_files.add(clean)
                else:
                    try:
                        full = urljoin(url, ref)
                        if self._is_same_scope(full):
                            clean = urlunparse((urlparse(full).scheme, urlparse(full).netloc,
                                              urlparse(full).path, '', '', ''))
                            self.js_files.add(clean)
                    except:
                        pass

        return found

    def _detect_method(self, endpoint, context):
        ctx = context.lower()
        checks = [
            (r'\.post\s*\(', 'POST'), (r'\.put\s*\(', 'PUT'), (r'\.delete\s*\(', 'DELETE'),
            (r'\.patch\s*\(', 'PATCH'), (r'\.get\s*\(', 'GET'),
            (r'method\s*[:=]\s*["\']post', 'POST'), (r'method\s*[:=]\s*["\']put', 'PUT'),
            (r'method\s*[:=]\s*["\']delete', 'DELETE'), (r'method\s*[:=]\s*["\']patch', 'PATCH'),
            (r'method\s*[:=]\s*["\']get', 'GET'),
        ]
        for pat, meth in checks:
            if re.search(pat, ctx):
                return meth

        # Infer from endpoint name
        ep_lower = endpoint.lower()
        if any(w in ep_lower for w in ('create', 'add', 'register', 'login', 'signup', 'upload', 'submit', 'save')):
            return 'POST'
        if any(w in ep_lower for w in ('update', 'edit', 'modify')):
            return 'PUT'
        if any(w in ep_lower for w in ('delete', 'remove', 'destroy')):
            return 'DELETE'

        return 'GET'

    def _detect_content_type(self, context):
        ctx = context.lower()
        if 'multipart/form-data' in ctx or 'formdata' in ctx:
            return 'multipart/form-data'
        if 'application/x-www-form-urlencoded' in ctx:
            return 'application/x-www-form-urlencoded'
        return 'application/json'

    def _extract_params(self, endpoint, context):
        params = {'path': [], 'query': [], 'body': []}

        # Path params: {id}, :id
        params['path'] = list(set(re.findall(r'[{:]([a-zA-Z0-9_]+)[}]?', endpoint)))

        # Query params
        if '?' in endpoint:
            q = endpoint.split('?', 1)[1]
            params['query'] = list(set(re.findall(r'([a-zA-Z0-9_]+)=', q)))

        # Body params from context
        for pat in [r'(?:data|body|payload|params)\s*[:=]\s*\{([^}]{1,500})\}',
                    r'JSON\.stringify\s*\(\s*\{([^}]{1,500})\}']:
            for m in re.findall(pat, context, re.I):
                fields = re.findall(r'([a-zA-Z0-9_]+)\s*:', m)
                params['body'].extend(fields)

        params['body'] = list(set(params['body']))
        params['all'] = sorted(set(params['path'] + params['query'] + params['body']))
        return params

    # ── Process all intercepted requests ─────────────────────────────────────

    def _process_intercepted(self):
        """Organize all intercepted requests into GET/POST/OTHER"""
        seen_sigs = set()

        for req in self.intercepted_requests:
            url = req['url']
            method = req['method']

            if not self._is_same_scope(url):
                continue

            sig = f"{method}:{self._url_signature(url)}"
            if sig in seen_sigs:
                continue
            seen_sigs.add(sig)

            parsed = req['parsed']
            query_params = parse_qs(parsed.query, keep_blank_values=True)

            entry = {
                'url': url,
                'method': method,
                'path': parsed.path,
                'query_params': {k: v[0] if len(v) == 1 else v for k, v in query_params.items()},
                'headers': req['headers'],
                'post_data': req['post_data'],
                'source': 'network_intercept',
            }

            if method == 'GET':
                self.get_endpoints[url] = entry
            elif method == 'POST':
                self.post_endpoints[url] = entry
            else:
                self.other_endpoints[url] = entry

    def _process_js_endpoints(self):
        """Merge JS-extracted endpoints into GET/POST"""
        seen_sigs = set()
        # Collect existing sigs
        for url in self.get_endpoints:
            seen_sigs.add(f"GET:{self._url_signature(url)}")
        for url in self.post_endpoints:
            seen_sigs.add(f"POST:{self._url_signature(url)}")
        for url in self.other_endpoints:
            m = self.other_endpoints[url]['method']
            seen_sigs.add(f"{m}:{self._url_signature(url)}")

        for ep in self.js_extracted_endpoints:
            full_url = ep['full_url']
            method = ep['method']

            sig = f"{method}:{self._url_signature(full_url)}"
            if sig in seen_sigs:
                continue
            seen_sigs.add(sig)

            # Add auth params if configured
            if self.auth_params:
                separator = '&' if '?' in full_url else '?'
                full_url = f"{full_url}{separator}{self.auth_params}"

            parsed = urlparse(full_url)
            query_params = parse_qs(parsed.query, keep_blank_values=True)

            entry = {
                'url': full_url,
                'method': method,
                'path': ep['endpoint'],
                'query_params': {k: v[0] if len(v) == 1 else v for k, v in query_params.items()},
                'body_params': ep['params'].get('body', []),
                'content_type': ep.get('content_type'),
                'source': f"js_analysis:{ep['source_js']}",
            }

            if method == 'GET':
                self.get_endpoints[full_url] = entry
            elif method == 'POST':
                self.post_endpoints[full_url] = entry
            else:
                self.other_endpoints[full_url] = entry

    # ── cURL generation ──────────────────────────────────────────────────────

    def _make_curl(self, entry):
        url = entry['url']
        method = entry['method']
        cmd = f'curl -s -o /dev/null -w "%{{http_code}}" -X {method}'
        cmd += f' "{url}"'

        # Add Content-Type for POST/PUT/PATCH
        if method in ('POST', 'PUT', 'PATCH'):
            ct = entry.get('content_type', 'application/json')
            cmd += f' \\\n  -H "Content-Type: {ct}"'

            post_data = entry.get('post_data')
            body_params = entry.get('body_params', [])

            if post_data:
                cmd += f" \\\n  -d '{post_data}'"
            elif body_params:
                body = {p: self._sample_val(p) for p in body_params}
                cmd += f" \\\n  -d '{json.dumps(body)}'"

        return cmd

    def _make_curl_verbose(self, entry):
        """Full verbose curl for verification"""
        url = entry['url']
        method = entry['method']
        cmd = f'curl -v -X {method} "{url}"'

        if method in ('POST', 'PUT', 'PATCH'):
            ct = entry.get('content_type', 'application/json')
            cmd += f' \\\n  -H "Content-Type: {ct}"'

            post_data = entry.get('post_data')
            body_params = entry.get('body_params', [])

            if post_data:
                cmd += f" \\\n  -d '{post_data}'"
            elif body_params:
                body = {p: self._sample_val(p) for p in body_params}
                cmd += f" \\\n  -d '{json.dumps(body)}'"

        return cmd

    def _sample_val(self, name):
        n = name.lower()
        if 'id' in n: return 1
        if 'email' in n: return "test@example.com"
        if 'pass' in n or 'pwd' in n: return "Test123!"
        if 'name' in n: return "test"
        if 'page' in n: return 1
        if 'limit' in n or 'size' in n: return 20
        if 'type' in n: return "default"
        if 'token' in n: return "TOKEN_HERE"
        if 'url' in n: return "https://example.com"
        if 'date' in n: return "2024-01-01"
        if 'phone' in n: return "+1234567890"
        return f"test_{name}"

    # ── Save Results ─────────────────────────────────────────────────────────

    def _save_results(self):
        od = self.output_dir

        # ── GET endpoints ──
        get_file = os.path.join(od, "GET_endpoints.txt")
        with open(get_file, 'w') as f:
            f.write(f"# GET Endpoints — {len(self.get_endpoints)} found\n")
            f.write(f"# Target: {self.target_url}\n")
            f.write(f"# Date: {datetime.now().isoformat()}\n")
            f.write(f"# {'='*76}\n\n")
            for url in sorted(self.get_endpoints.keys()):
                f.write(f"{url}\n")

        # ── POST endpoints ──
        post_file = os.path.join(od, "POST_endpoints.txt")
        with open(post_file, 'w') as f:
            f.write(f"# POST Endpoints — {len(self.post_endpoints)} found\n")
            f.write(f"# Target: {self.target_url}\n")
            f.write(f"# Date: {datetime.now().isoformat()}\n")
            f.write(f"# {'='*76}\n\n")
            for url, entry in sorted(self.post_endpoints.items()):
                f.write(f"{url}\n")
                if entry.get('body_params'):
                    f.write(f"  Body Params: {', '.join(entry['body_params'])}\n")
                if entry.get('post_data'):
                    f.write(f"  Post Data: {entry['post_data'][:200]}\n")
                if entry.get('content_type'):
                    f.write(f"  Content-Type: {entry['content_type']}\n")
                f.write("\n")

        # ── OTHER (PUT/DELETE/PATCH) endpoints ──
        if self.other_endpoints:
            other_file = os.path.join(od, "OTHER_endpoints.txt")
            with open(other_file, 'w') as f:
                f.write(f"# PUT/DELETE/PATCH Endpoints — {len(self.other_endpoints)} found\n")
                f.write(f"# {'='*76}\n\n")
                for url, entry in sorted(self.other_endpoints.items()):
                    f.write(f"[{entry['method']}] {url}\n")

        # ── ALL endpoints in one file ──
        all_file = os.path.join(od, "ALL_endpoints.txt")
        with open(all_file, 'w') as f:
            f.write(f"# All Endpoints — Target: {self.target_url}\n")
            f.write(f"# GET: {len(self.get_endpoints)} | POST: {len(self.post_endpoints)} | OTHER: {len(self.other_endpoints)}\n")
            f.write(f"# {'='*76}\n\n")

            if self.get_endpoints:
                f.write(f"# ── GET ({len(self.get_endpoints)}) ──\n")
                for url in sorted(self.get_endpoints.keys()):
                    f.write(f"{url}\n")
                f.write("\n")

            if self.post_endpoints:
                f.write(f"# ── POST ({len(self.post_endpoints)}) ──\n")
                for url in sorted(self.post_endpoints.keys()):
                    f.write(f"{url}\n")
                f.write("\n")

            if self.other_endpoints:
                f.write(f"# ── OTHER ({len(self.other_endpoints)}) ──\n")
                for url, entry in sorted(self.other_endpoints.items()):
                    f.write(f"[{entry['method']}] {url}\n")

        # ── cURL — GET ──
        curl_get_file = os.path.join(od, "curl_GET.sh")
        with open(curl_get_file, 'w') as f:
            f.write("#!/bin/bash\n")
            f.write(f"# GET endpoint verification — {len(self.get_endpoints)} endpoints\n")
            f.write('# Usage: bash curl_GET.sh | grep -E "^[0-9]"\n\n')
            for url, entry in sorted(self.get_endpoints.items()):
                curl = self._make_curl(entry)
                f.write(f"echo \"Testing: {entry.get('path', url[:80])}\"\n")
                f.write(f"{curl}\n")
                f.write('echo ""\n\n')
        os.chmod(curl_get_file, 0o755)

        # ── cURL — POST ──
        curl_post_file = os.path.join(od, "curl_POST.sh")
        with open(curl_post_file, 'w') as f:
            f.write("#!/bin/bash\n")
            f.write(f"# POST endpoint verification — {len(self.post_endpoints)} endpoints\n\n")
            for url, entry in sorted(self.post_endpoints.items()):
                curl = self._make_curl(entry)
                f.write(f"echo \"Testing: {entry.get('path', url[:80])}\"\n")
                f.write(f"{curl}\n")
                f.write('echo ""\n\n')
        os.chmod(curl_post_file, 0o755)

        # ── cURL verbose (all) ──
        curl_all_file = os.path.join(od, "curl_ALL_verbose.sh")
        with open(curl_all_file, 'w') as f:
            f.write("#!/bin/bash\n")
            f.write("# All endpoints — verbose curl for verification\n\n")
            all_entries = list(self.get_endpoints.items()) + \
                          list(self.post_endpoints.items()) + \
                          list(self.other_endpoints.items())
            for url, entry in sorted(all_entries, key=lambda x: x[0]):
                f.write(f"# [{entry['method']}] {entry.get('path', '')}\n")
                f.write(f"{self._make_curl_verbose(entry)}\n\n")
        os.chmod(curl_all_file, 0o755)

        # ── Secrets ──
        if self.js_extracted_secrets:
            unique_secrets = []
            seen = set()
            for s in self.js_extracted_secrets:
                key = (s['type'], s['value'])
                if key not in seen:
                    seen.add(key)
                    unique_secrets.append(s)

            sec_file = os.path.join(od, "SECRETS.txt")
            with open(sec_file, 'w') as f:
                f.write(f"# Secrets Found: {len(unique_secrets)}\n")
                f.write(f"# {'='*76}\n\n")
                for s in unique_secrets:
                    f.write(f"[{s['type']}]\n")
                    f.write(f"  Value: {s['value']}\n")
                    f.write(f"  File: {s['file']}\n")
                    f.write(f"  Context: {s['context'][:200]}\n\n")

            with open(os.path.join(od, "SECRETS.json"), 'w') as f:
                json.dump(unique_secrets, f, indent=2)

        # ── JS files list ──
        js_file = os.path.join(od, "JS_files.txt")
        with open(js_file, 'w') as f:
            f.write(f"# JS Files: {len(self.js_files)}\n\n")
            for u in sorted(self.js_files):
                dl = "✓" if u in self.js_content_cache else "✗"
                f.write(f"[{dl}] {u}\n")

        # ── Postman Collection ──
        self._save_postman_collection()

        # ── Summary ──
        n_secrets = len(set((s['type'], s['value']) for s in self.js_extracted_secrets))
        summary_file = os.path.join(od, "SUMMARY.txt")
        with open(summary_file, 'w') as f:
            f.write(f"{'='*80}\n")
            f.write(f" EndpointHunter Scan Summary\n")
            f.write(f"{'='*80}\n")
            f.write(f" Target:       {self.target_url}\n")
            f.write(f" Date:         {datetime.now().isoformat()}\n")
            f.write(f" Max Depth:    {self.max_depth}\n")
            f.write(f" Pages Visited:{len(self.visited_pages)}\n")
            f.write(f"{'='*80}\n")
            f.write(f" GET endpoints:    {len(self.get_endpoints)}\n")
            f.write(f" POST endpoints:   {len(self.post_endpoints)}\n")
            f.write(f" OTHER endpoints:  {len(self.other_endpoints)}\n")
            f.write(f" JS files found:   {len(self.js_files)}\n")
            f.write(f" JS downloaded:    {len(self.js_content_cache)}\n")
            f.write(f" Secrets found:    {n_secrets}\n")
            f.write(f" Network requests: {len(self.intercepted_requests)}\n")
            f.write(f"{'='*80}\n")

    def _save_postman_collection(self):
        postman = {
            "info": {
                "name": f"EndpointHunter - {self.base_domain}",
                "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
            },
            "item": []
        }

        # GET folder
        get_folder = {"name": "GET", "item": []}
        for url, entry in sorted(self.get_endpoints.items()):
            get_folder["item"].append({
                "name": entry.get('path', url[:60]),
                "request": {"method": "GET", "url": url}
            })
        postman["item"].append(get_folder)

        # POST folder
        post_folder = {"name": "POST", "item": []}
        for url, entry in sorted(self.post_endpoints.items()):
            item = {
                "name": entry.get('path', url[:60]),
                "request": {
                    "method": "POST",
                    "url": url,
                    "header": [{"key": "Content-Type", "value": entry.get('content_type', 'application/json')}],
                }
            }
            body_params = entry.get('body_params', [])
            post_data = entry.get('post_data')
            if post_data:
                item["request"]["body"] = {"mode": "raw", "raw": post_data}
            elif body_params:
                body = {p: self._sample_val(p) for p in body_params}
                item["request"]["body"] = {"mode": "raw", "raw": json.dumps(body, indent=2)}
            post_folder["item"].append(item)
        postman["item"].append(post_folder)

        # OTHER folder
        if self.other_endpoints:
            other_folder = {"name": "PUT/DELETE/PATCH", "item": []}
            for url, entry in sorted(self.other_endpoints.items()):
                other_folder["item"].append({
                    "name": f"[{entry['method']}] {entry.get('path', url[:60])}",
                    "request": {"method": entry['method'], "url": url}
                })
            postman["item"].append(other_folder)

        with open(os.path.join(self.output_dir, "postman_collection.json"), 'w') as f:
            json.dump(postman, f, indent=2)

    # ── Main Run ─────────────────────────────────────────────────────────────

    async def run(self):
        start = datetime.now()
        banner()

        print(f"  {C.BOLD}Target:{C.END}    {self.target_url}")
        print(f"  {C.BOLD}Max Depth:{C.END} {self.max_depth}")
        print(f"  {C.BOLD}Max Pages:{C.END} {self.max_pages}")
        print(f"  {C.BOLD}Output:{C.END}    {self.output_dir}/")
        print()

        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=self.headless,
                args=['--no-sandbox', '--disable-setuid-sandbox',
                      '--disable-blink-features=AutomationControlled']
            )
            context = await browser.new_context(
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                           '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                viewport={'width': 1920, 'height': 1080},
            )
            page = await context.new_page()

            # ── Hook into ALL network requests (like Burp proxy) ──
            page.on('request', self._on_request)
            page.on('response', self._on_response)

            # ── Phase 1: Deep crawl ──
            print(f"\n  {C.BOLD}{C.Y}═══ Phase 1: Deep Crawl + Network Intercept ═══{C.END}\n")
            self.discovered_pages.add(self.target_url)
            await self._crawl_page(page, self.target_url, depth=0)

            print(f"\n  {C.G}Pages visited: {len(self.visited_pages)}{C.END}")
            print(f"  {C.G}Network requests intercepted: {len(self.intercepted_requests)}{C.END}")
            print(f"  {C.G}JS files found: {len(self.js_files)}{C.END}")

            # ── Phase 2: Recursive JS download & analysis ──
            print(f"\n  {C.BOLD}{C.Y}═══ Phase 2: JS Download & Recursive Analysis ═══{C.END}\n")

            for pass_num in range(1, 6):
                initial_count = len(self.js_files)

                await self._download_js_files(page)

                # Analyze all un-analyzed JS
                to_analyze = [u for u in self.js_content_cache if u not in self.analyzed_js]
                total_eps = 0
                for url in to_analyze:
                    n = self._analyze_js_content(url, self.js_content_cache[url])
                    total_eps += n

                new_js = len(self.js_files) - initial_count

                print(f"  {C.CY}Pass {pass_num}: analyzed {len(to_analyze)} JS files, "
                      f"found {total_eps} endpoints, {new_js} new JS refs{C.END}")

                if new_js == 0:
                    print(f"  {C.G}✓ No more JS files to discover{C.END}")
                    break

            await browser.close()

        # ── Phase 3: Organize & deduplicate ──
        print(f"\n  {C.BOLD}{C.Y}═══ Phase 3: Processing & Deduplication ═══{C.END}\n")
        self._process_intercepted()
        self._process_js_endpoints()

        # ── Phase 4: Save ──
        print(f"\n  {C.BOLD}{C.Y}═══ Phase 4: Saving Results ═══{C.END}\n")
        self._save_results()

        elapsed = datetime.now() - start
        n_secrets = len(set((s['type'], s['value']) for s in self.js_extracted_secrets))

        print(f"""
  {C.BOLD}{C.G}{'═'*60}
  SCAN COMPLETE
  {'═'*60}{C.END}
  {C.W}Output Dir:      {C.CY}{self.output_dir}/{C.END}
  {C.W}Pages Crawled:   {C.G}{len(self.visited_pages)}{C.END}
  {C.W}Network Reqs:    {C.G}{len(self.intercepted_requests)}{C.END}
  {C.W}JS Files:        {C.G}{len(self.js_files)} ({len(self.js_content_cache)} downloaded){C.END}
  {C.W}GET Endpoints:   {C.G}{len(self.get_endpoints)}{C.END}
  {C.W}POST Endpoints:  {C.R}{len(self.post_endpoints)}{C.END}
  {C.W}OTHER Endpoints: {C.Y}{len(self.other_endpoints)}{C.END}
  {C.W}Secrets:         {C.R}{n_secrets}{C.END}
  {C.W}Time:            {C.CY}{elapsed}{C.END}
  {C.BOLD}{C.G}{'═'*60}{C.END}

  {C.BOLD}Files:{C.END}
  {C.DIM}├── GET_endpoints.txt      — All GET URLs (one per line)
  ├── POST_endpoints.txt     — All POST URLs + params
  ├── OTHER_endpoints.txt    — PUT/DELETE/PATCH
  ├── ALL_endpoints.txt      — Everything combined
  ├── curl_GET.sh            — cURL verify GET endpoints
  ├── curl_POST.sh           — cURL verify POST endpoints
  ├── curl_ALL_verbose.sh    — Verbose cURL all endpoints
  ├── postman_collection.json— Import to Postman/Burp
  ├── SECRETS.txt            — Leaked secrets/keys
  ├── SECRETS.json           — Secrets (JSON)
  ├── JS_files.txt           — All JS files found
  ├── SUMMARY.txt            — Scan summary
  └── js_files/              — Downloaded JS source{C.END}
""")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description='EndpointHunter — Burp-Style Passive Endpoint Discovery',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 endpoint_hunter.py https://target.com
  python3 endpoint_hunter.py https://target.com -d 15 --auth "token=abc123"
  python3 endpoint_hunter.py https://target.com --max-pages 1000 -v

What it does (like Burp passive spider):
  ✓ Intercepts ALL network requests (XHR, fetch, websocket, etc.)
  ✓ Deep recursive page crawling with interaction (clicks tabs, scrolls)
  ✓ JS file discovery + recursive import chain analysis
  ✓ Endpoint extraction from JS source (API routes, fetch calls)
  ✓ Secret/key/token detection
  ✓ GET/POST/PUT/DELETE separation into individual files
  ✓ cURL commands for verification
  ✓ Postman collection export
        """
    )

    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('-d', '--depth', type=int, default=10, help='Max crawl depth (default: 10)')
    parser.add_argument('--auth', help='Auth query params (e.g., "uid=123&key=abc")')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--max-pages', type=int, default=500, help='Max pages to visit (default: 500)')
    parser.add_argument('--timeout', type=int, default=60, help='Page timeout in seconds (default: 60)')
    parser.add_argument('--show-browser', action='store_true', help='Show browser window (non-headless)')

    args = parser.parse_args()

    scanner = EndpointHunter(
        target_url=args.url,
        max_depth=args.depth,
        auth_params=args.auth,
        verbose=args.verbose,
        headless=not args.show_browser,
        timeout=args.timeout,
        max_pages=args.max_pages,
    )

    asyncio.run(scanner.run())


if __name__ == "__main__":
    main()
