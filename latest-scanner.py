#!/usr/bin/env python3
"""
EndpointHunter v3.0 — SPA-Aware Burp-Style Endpoint Discovery
Handles Nuxt/Vue/React SPAs, intercepts all traffic, extracts client-side routes
"""

import asyncio
import re
import json
import argparse
import os
import sys
import traceback
from pathlib import Path
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs, urlencode
from datetime import datetime
from collections import defaultdict, OrderedDict

try:
    from playwright.async_api import async_playwright
except ImportError:
    print("[!] pip install playwright && playwright install chromium")
    sys.exit(1)

try:
    import jsbeautifier
    HAS_BEAUTIFIER = True
except ImportError:
    HAS_BEAUTIFIER = False


class C:
    R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; B = "\033[94m"
    M = "\033[95m"; CY = "\033[96m"; W = "\033[97m"; DIM = "\033[2m"
    BOLD = "\033[1m"; END = "\033[0m"


def banner():
    print(f"""{C.CY}
 ╔═══════════════════════════════════════════════════════════════════╗
 ║  {C.BOLD}EndpointHunter v3.0{C.END}{C.CY} — SPA-Aware Endpoint Discovery          ║
 ║  Network Intercept · JS Route Extraction · Deep Interaction      ║
 ╚═══════════════════════════════════════════════════════════════════╝{C.END}
""")


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
        self.origin = f"{parsed.scheme}://{parsed.netloc}"
        self.netloc = parsed.netloc
        self.base_domain = self._get_base_domain(parsed.netloc)

        # Data stores
        self.visited_pages = set()
        self.js_files = set()
        self.js_content_cache = {}
        self.analyzed_js = set()

        # Network intercept (Burp-style HTTP history)
        self.intercepted_requests = []
        self.intercepted_urls = set()
        self.api_calls = []  # JSON API calls specifically

        # SPA routes discovered from JS
        self.spa_routes = set()

        # Final results
        self.get_endpoints = OrderedDict()
        self.post_endpoints = OrderedDict()
        self.other_endpoints = OrderedDict()

        # JS analysis
        self.js_extracted_endpoints = []
        self.js_extracted_secrets = []

        # URL patterns seen (for dedup)
        self.seen_signatures = set()

        self.output_dir = self._create_output_dir()

        self.secret_patterns = {
            'API Key': [r'(?i)(?:api[_-]?key|apikey)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']'],
            'Secret/Token': [r'(?i)(?:secret|token|auth)[_-]?(?:key)?["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']'],
            'Bearer Token': [r'(?i)bearer\s+([a-zA-Z0-9_\-\.]{30,})'],
            'JWT': [r'eyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}'],
            'AWS Key': [r'AKIA[0-9A-Z]{16}'],
            'Google API Key': [r'AIza[0-9A-Za-z_\-]{35}'],
            'Private Key': [r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'],
            'Database URL': [r'(?:mongodb(?:\+srv)?|mysql|postgres(?:ql)?|redis)://[^\s"\'<>]+'],
        }

    def _get_base_domain(self, netloc):
        parts = netloc.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else netloc

    def _is_same_scope(self, url):
        try:
            parsed = urlparse(url)
            return parsed.netloc == self.netloc or \
                   parsed.netloc.endswith("." + self.base_domain)
        except:
            return False

    def _create_output_dir(self):
        domain = self.netloc.replace("www.", "")
        safe = re.sub(r'[^\w\-.]', '_', domain)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        d = f"hunt_{safe}_{ts}"
        Path(d).mkdir(parents=True, exist_ok=True)
        Path(os.path.join(d, "js_files")).mkdir(exist_ok=True)
        return d

    def _url_signature(self, method, url):
        """Structural signature for dedup — replaces IDs with placeholders"""
        parsed = urlparse(url)
        parts = parsed.path.split("/")
        sig = []
        for p in parts:
            if re.match(r'^\d+$', p):
                sig.append("{N}")
            elif re.match(r'^[a-f0-9]{8,}$', p, re.I):
                sig.append("{HASH}")
            else:
                sig.append(p)
        sig_path = "/".join(sig)
        param_keys = "&".join(sorted(parse_qs(parsed.query, keep_blank_values=True).keys()))
        return f"{method}:{parsed.netloc}{sig_path}?{param_keys}"

    def _log(self, msg, level="info"):
        colors = {"info": C.CY, "ok": C.G, "warn": C.Y, "err": C.R, "dim": C.DIM}
        print(f"  {colors.get(level, C.W)}{msg}{C.END}")

    def _vlog(self, msg):
        if self.verbose:
            print(f"  {C.DIM}{msg}{C.END}")

    # ─── Network Interception ────────────────────────────────────────────────

    def _on_request(self, request):
        """Intercept every network request — handles binary post_data safely"""
        url = request.url
        method = request.method

        if not url.startswith("http"):
            return

        # ── Skip out-of-scope domains (CDN, analytics, third-party) ──
        if not self._is_same_scope(url):
            return

        # Skip static assets
        parsed = urlparse(url)
        skip_ext = ('.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff',
                    '.woff2', '.ttf', '.eot', '.mp4', '.mp3', '.webp', '.avif',
                    '.css', '.map')
        if any(parsed.path.lower().endswith(ext) for ext in skip_ext):
            return

        # ── SAFE post_data extraction (fixes the UnicodeDecodeError) ──
        post_data = None
        try:
            post_data = request.post_data
        except Exception:
            # Binary body (gzip, protobuf, etc.) — try raw bytes
            try:
                raw = request.post_data_buffer
                if raw:
                    post_data = f"<binary:{len(raw)}bytes>"
            except Exception:
                post_data = None

        # Record JS files separately
        if parsed.path.endswith('.js'):
            if self._is_same_scope(url):
                clean = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))
                self.js_files.add(clean)
            return

        req_data = {
            'url': url,
            'method': method.upper(),
            'post_data': post_data,
            'path': parsed.path,
            'query': parsed.query,
        }
        self.intercepted_requests.append(req_data)
        self.intercepted_urls.add(url)

    def _on_response(self, response):
        """Track API (JSON) responses — deduped, in-scope only"""
        try:
            url = response.url
            method = response.request.method.upper()

            # Skip out-of-scope domains
            if not self._is_same_scope(url):
                return

            content_type = response.headers.get('content-type', '')
            if 'application/json' in content_type:
                # Dedup key: method + URL (ignore query param values, keep keys)
                parsed = urlparse(url)
                param_keys = "&".join(sorted(parse_qs(parsed.query).keys()))
                dedup_key = f"{method}:{parsed.netloc}{parsed.path}?{param_keys}"

                if not hasattr(self, '_api_log_seen'):
                    self._api_log_seen = {}

                count = self._api_log_seen.get(dedup_key, 0)
                self._api_log_seen[dedup_key] = count + 1

                self.api_calls.append({
                    'url': url,
                    'method': method,
                    'status': response.status,
                })

                # Only print first 2 occurrences, then suppress
                if count < 2:
                    self._vlog(f"[API] {method} {url}")
                elif count == 2:
                    self._vlog(f"[API] {method} {url} (suppressing further duplicates)")
        except Exception:
            pass

    # ─── SPA Route Extraction from JS Bundles ────────────────────────────────

    def _extract_spa_routes(self, content, source_url=""):
        """Extract Vue/Nuxt/React router routes from JS content"""
        routes = set()

        # ── Nuxt 3 / Vue Router route definitions ──
        # path: "/all", path: "/detail/helpCenter"
        for m in re.finditer(r'path\s*:\s*["\'](/[a-zA-Z0-9_/\-:?{}]*)["\']', content):
            route = m.group(1)
            if len(route) > 1 and not route.endswith('.js'):
                routes.add(route)

        # ── Nuxt 3 payload/manifest route entries ──
        # "all", "detail-helpCenter", "auth", etc. in route arrays
        for m in re.finditer(r'(?:name|route)\s*:\s*["\']([a-zA-Z][a-zA-Z0-9_\-]*)["\']', content):
            name = m.group(1)
            # Convert Nuxt route names to paths: "detail-helpCenter" → "/detail/helpCenter"
            path = "/" + name.replace("-", "/").replace("_", "/")
            if len(path) > 1:
                routes.add(path)

        # ── Direct path strings that look like routes ──
        # "/all", "/detail/helpCenter", "/promotion", "/vip"
        for m in re.finditer(r'["\'](/[a-z][a-zA-Z0-9]*(?:/[a-zA-Z0-9_\-]*)*)["\']', content):
            path = m.group(1)
            # Filter out clearly non-route paths
            if any(path.endswith(ext) for ext in ('.js', '.css', '.png', '.json', '.svg', '.ico')):
                continue
            if any(seg in path for seg in ('/node_modules/', '/__', '/assets/', '/static/')):
                continue
            if len(path) > 1 and len(path) < 100:
                routes.add(path)

        # ── Nuxt _payload.json / builds manifest ──
        for m in re.finditer(r'"(/[a-zA-Z][a-zA-Z0-9_/\-]*)"', content):
            path = m.group(1)
            if not any(path.endswith(ext) for ext in ('.js', '.css', '.png', '.json', '.map')):
                if len(path) > 1 and len(path) < 80:
                    routes.add(path)

        # ── Query parameter patterns: ?type=X&page=Y ──
        for m in re.finditer(r'["\'](/[a-zA-Z][a-zA-Z0-9_/\-]*\?[a-zA-Z0-9_=&%\+\-\.]+)["\']', content):
            routes.add(m.group(1))

        # ── Route with dynamic segments: /detail/:id, /game/:slug ──
        for m in re.finditer(r'["\'](/[a-zA-Z][a-zA-Z0-9_/]*(?:/:[a-zA-Z0-9_]+)+)["\']', content):
            route = m.group(1)
            # Replace :param with sample value
            resolved = re.sub(r':([a-zA-Z0-9_]+)', '1', route)
            routes.add(resolved)
            routes.add(route)  # keep template too

        # ── API endpoint patterns ──
        api_patterns = [
            r'["\'`](/api/[a-zA-Z0-9_/\-{}:?=&\.\+%]+)["\'`]',
            r'(?:url|path|endpoint|baseURL)\s*[:=]\s*["\'`](/[a-zA-Z0-9_/\-{}:?=&\.\+%]+)["\'`]',
            r'(?:fetch|axios|post|get|put|delete|patch|request)\s*\(\s*["\'`](/[a-zA-Z0-9_/\-{}:?=&\.\+%]+)["\'`]',
            r'(?:fetch|axios|post|get|put|delete|patch|request)\s*\(\s*["\'`](https?://[^\s"\'`]+)["\'`]',
            # Concatenated API paths: baseUrl + "/game/list"
            r'\+\s*["\'](/[a-zA-Z0-9_/\-]+)["\']',
        ]
        for pat in api_patterns:
            for m in re.finditer(pat, content):
                ep = m.group(1)
                ep = re.sub(r'\$\{[^}]+\}', '1', ep)  # resolve template literals
                if not any(ep.endswith(ext) for ext in ('.js', '.css', '.png')):
                    routes.add(ep)

        # ── Common query parameter names (to build full URLs later) ──
        # Look for patterns like: params.type, query.page, ?type=
        self._query_param_patterns = getattr(self, '_query_param_patterns', set())
        for m in re.finditer(r'(?:params|query)\s*[\.\[]\s*["\']?([a-zA-Z0-9_]+)', content):
            self._query_param_patterns.add(m.group(1))
        for m in re.finditer(r'[?&]([a-zA-Z0-9_]+)=', content):
            self._query_param_patterns.add(m.group(1))

        return routes

    def _expand_routes_with_params(self):
        """Generate full URLs from routes + discovered query params"""
        expanded = set()

        # Common parameter values to try
        param_values = {
            'type': ['IsNew', 'IsHot', 'IsRecommend', 'all', 'slot', 'live', 'sport', 'fish', 'chess'],
            'page': ['1'],
            'id': ['1'],
            'tab': ['1', '2', '3'],
            'category': ['all', 'hot', 'new'],
            'sort': ['new', 'hot', 'popular'],
            'lang': ['en', 'zh'],
            'status': ['active', 'all'],
        }

        for route in list(self.spa_routes):
            expanded.add(route)

            # If route has no query params, try adding common ones
            if '?' not in route:
                # Check if any discovered param names are associated with this route pattern
                route_lower = route.lower()

                # For list/category pages, add type & page params
                if any(word in route_lower for word in ('all', 'list', 'game', 'slot', 'category', 'search')):
                    for type_val in param_values.get('type', []):
                        expanded.add(f"{route}?type={type_val}&page=1")
                    expanded.add(f"{route}?page=1")

                # For detail pages, add id param
                if any(word in route_lower for word in ('detail', 'info', 'view', 'show')):
                    expanded.add(f"{route}?id=1")

        return expanded

    # ─── Page Interaction (trigger SPA navigation & API calls) ────────────────

    async def _extract_all_links(self, page):
        """Extract links from DOM — handles SPA frameworks"""
        links = set()
        try:
            # Standard <a href>
            hrefs = await page.evaluate('''() => {
                return Array.from(document.querySelectorAll('a[href]'))
                    .map(a => a.href)
                    .filter(h => h && h.startsWith('http'));
            }''')
            links.update(hrefs)

            # Vue router-link / nuxt-link (rendered as <a> but also check data attrs)
            vue_links = await page.evaluate('''() => {
                const links = [];
                // NuxtLink / router-link
                document.querySelectorAll('[to], [href]').forEach(el => {
                    const to = el.getAttribute('to') || el.getAttribute('href');
                    if (to && to.startsWith('/')) links.push(to);
                });
                // data-* attributes
                document.querySelectorAll('[data-href],[data-url],[data-to],[data-link],[data-path]').forEach(el => {
                    ['data-href','data-url','data-to','data-link','data-path'].forEach(attr => {
                        const v = el.getAttribute(attr);
                        if (v && (v.startsWith('/') || v.startsWith('http'))) links.push(v);
                    });
                });
                return links;
            }''')
            for link in vue_links:
                if link.startswith('/'):
                    links.add(self.origin + link)
                elif link.startswith('http'):
                    links.add(link)

            # Extract URLs from onclick, @click handlers
            click_urls = await page.evaluate('''() => {
                const urls = [];
                document.querySelectorAll('[onclick]').forEach(el => {
                    const oc = el.getAttribute('onclick') || '';
                    const m = oc.match(/['"](\\/[^'"]+)['"]/g);
                    if (m) m.forEach(u => urls.push(u.replace(/['"]/g, '')));
                });
                return urls;
            }''')
            for u in click_urls:
                if u.startswith('/'):
                    links.add(self.origin + u)

            # Inline script URLs
            scripts = await page.evaluate('''() => {
                return Array.from(document.querySelectorAll('script:not([src])'))
                    .map(s => s.textContent).filter(Boolean);
            }''')
            for script in scripts:
                for m in re.finditer(r'["\'](/[a-zA-Z][a-zA-Z0-9_/\-]*(?:\?[^"\']*)?)["\']', script):
                    path = m.group(1)
                    if not any(path.endswith(ext) for ext in ('.js', '.css', '.png', '.svg')):
                        links.add(self.origin + path)

        except Exception as e:
            self._vlog(f"Link extraction error: {e}")

        return links

    async def _deep_interact(self, page):
        """Aggressively interact with page to trigger SPA navigation & API calls"""
        try:
            # ── 1. Scroll fully (lazy loading) ──
            await page.evaluate('''async () => {
                const delay = ms => new Promise(r => setTimeout(r, ms));
                for (let i = 0; i < 10; i++) {
                    window.scrollBy(0, window.innerHeight);
                    await delay(300);
                }
                window.scrollTo(0, 0);
            }''')
            await page.wait_for_timeout(1000)

            # ── 2. Click navigation items / tabs / filters ──
            click_selectors = [
                # Navigation
                'nav a', '.nav a', '.nav-item', '.nav-link', '.menu-item a',
                'header a', '.header a', '.sidebar a',
                # Tabs & filters
                '[role="tab"]', '.tab', '.tab-item', '[data-toggle="tab"]',
                '[class*="tab"]', '[class*="filter"]', '[class*="category"]',
                # Buttons that trigger content
                'button[data-type]', 'a[data-type]', '[data-category]',
                '[class*="sort"]', '[class*="type"]',
                # Pagination
                '.pagination a', '.pagination button', '[class*="pager"] a',
                'a[href*="page="]', 'button[data-page]',
                '[class*="page"]  a', '[class*="next"]', '[class*="more"]',
                # Vue/Nuxt specific
                '.nuxt-link-active', '[class*="router"]',
                # Game/content cards (clicking might navigate)
                '.game-item a', '.card a', '[class*="card"] a',
                '[class*="game"] a', '[class*="item"] a',
                # Footer links
                'footer a',
            ]

            clicked = set()
            for selector in click_selectors:
                try:
                    elements = await page.query_selector_all(selector)
                    for el in elements[:15]:
                        try:
                            # Get a unique identifier
                            tag_info = await page.evaluate('''(el) => {
                                const href = el.getAttribute('href') || el.getAttribute('to') || '';
                                const text = (el.textContent || '').trim().substring(0, 30);
                                return href + '|' + text;
                            }''', el)

                            if tag_info in clicked:
                                continue
                            clicked.add(tag_info)

                            visible = await el.is_visible()
                            if not visible:
                                continue

                            # Check if it's a navigation link
                            href = await page.evaluate('(el) => el.getAttribute("href") || el.getAttribute("to") || ""', el)
                            if href and href.startswith('/'):
                                # This is a SPA route — record it
                                self.spa_routes.add(href)
                                full_url = self.origin + href
                                if full_url not in self.visited_pages:
                                    self.visited_pages.add(full_url)

                            # Click it to trigger API calls
                            await el.click(timeout=3000)
                            await page.wait_for_timeout(800)

                            # Record current URL (SPA might have changed it)
                            current = page.url
                            if current and self._is_same_scope(current):
                                self.intercepted_urls.add(current)
                                parsed = urlparse(current)
                                if parsed.path != '/':
                                    self.spa_routes.add(parsed.path + ('?' + parsed.query if parsed.query else ''))

                        except Exception:
                            pass
                except Exception:
                    pass

            # ── 3. Extract URLs from the current DOM after all interactions ──
            try:
                all_urls = await page.evaluate('''() => {
                    const urls = new Set();
                    // All anchor hrefs
                    document.querySelectorAll('a').forEach(a => {
                        if (a.href) urls.add(a.href);
                        const to = a.getAttribute('to');
                        if (to) urls.add(to);
                    });
                    // All URLs in text content of script tags
                    document.querySelectorAll('script').forEach(s => {
                        const text = s.textContent || '';
                        const matches = text.match(/["']\\/[a-zA-Z][^"'\\s]{1,80}["']/g);
                        if (matches) matches.forEach(m => urls.add(m.replace(/["']/g, '')));
                    });
                    return Array.from(urls);
                }''')
                for u in all_urls:
                    if u.startswith('/') and len(u) > 1:
                        if not any(u.endswith(ext) for ext in ('.js', '.css', '.png', '.svg', '.ico')):
                            self.spa_routes.add(u)
                    elif u.startswith('http') and self._is_same_scope(u):
                        self.intercepted_urls.add(u)
                        parsed = urlparse(u)
                        if parsed.path and parsed.path != '/':
                            self.spa_routes.add(parsed.path + ('?' + parsed.query if parsed.query else ''))
            except Exception:
                pass

        except Exception as e:
            self._vlog(f"Interaction error: {e}")

    async def _navigate_spa_route(self, page, route):
        """Navigate to a SPA route by changing the URL directly"""
        full_url = self.origin + route if route.startswith('/') else route
        if full_url in self.visited_pages:
            return

        self.visited_pages.add(full_url)

        try:
            # For SPAs, we navigate using the router or direct URL
            await page.goto(full_url, wait_until='domcontentloaded', timeout=15000)
            try:
                await page.wait_for_load_state('networkidle', timeout=8000)
            except:
                pass
            await page.wait_for_timeout(1500)

            # Extract more links from this page
            links = await self._extract_all_links(page)
            for link in links:
                if self._is_same_scope(link):
                    parsed = urlparse(link)
                    if parsed.path and parsed.path != '/':
                        route_path = parsed.path + ('?' + parsed.query if parsed.query else '')
                        self.spa_routes.add(route_path)

        except Exception as e:
            self._vlog(f"SPA nav error {route}: {str(e)[:50]}")

    # ─── JS Analysis ─────────────────────────────────────────────────────────

    async def _download_js_files(self, page):
        """Download all discovered JS files"""
        to_download = [u for u in self.js_files if u not in self.js_content_cache]
        if not to_download:
            return

        self._log(f"Downloading {len(to_download)} JS files...", "warn")

        for i, url in enumerate(sorted(to_download), 1):
            try:
                resp = await page.goto(url, wait_until='load', timeout=15000)
                if resp and resp.status == 200:
                    content = await resp.text()
                    self.js_content_cache[url] = content

                    fname = re.sub(r'[^\w\-.]', '_', url.split('/')[-1])[:100]
                    fpath = os.path.join(self.output_dir, "js_files", fname)
                    with open(fpath, 'w', encoding='utf-8', errors='ignore') as f:
                        f.write(content)

                    self._vlog(f"  [{i:03d}] ✓ {url[:80]}")
            except Exception:
                pass

        self._log(f"Downloaded: {len(self.js_content_cache)}/{len(self.js_files)}", "ok")

    async def _fetch_nuxt_manifest(self, page):
        """Try to fetch Nuxt build manifest which lists all routes and chunks"""
        manifest_paths = [
            '/_nuxt/builds/latest.json',
            '/_payload.json',
            '/__nuxt_island/',
        ]

        for path in manifest_paths:
            try:
                url = self.origin + path
                resp = await page.goto(url, wait_until='load', timeout=8000)
                if resp and resp.status == 200:
                    content = await resp.text()
                    self._vlog(f"Found manifest: {path}")
                    # Extract all referenced JS chunks
                    for m in re.finditer(r'["\'](/[^"\']*\.js)["\']', content):
                        js_url = self.origin + m.group(1)
                        self.js_files.add(js_url)
                    # Extract route info
                    routes = self._extract_spa_routes(content, url)
                    self.spa_routes.update(routes)
            except Exception:
                pass

        # Also try to find the Nuxt build meta JSON from intercepted requests
        for req in self.intercepted_requests:
            if '_nuxt/builds/meta' in req['url']:
                try:
                    resp = await page.goto(req['url'], wait_until='load', timeout=8000)
                    if resp and resp.status == 200:
                        content = await resp.text()
                        for m in re.finditer(r'["\'](/[^"\']*\.js)["\']', content):
                            self.js_files.add(self.origin + m.group(1))
                except Exception:
                    pass

    def _analyze_js_content(self, url, content):
        """Analyze JS: routes, endpoints, secrets, more JS refs"""
        if url in self.analyzed_js:
            return 0
        self.analyzed_js.add(url)

        if HAS_BEAUTIFIER:
            try:
                opts = jsbeautifier.default_options()
                opts.indent_size = 2
                content = jsbeautifier.beautify(content, opts)
            except:
                pass

        # ── Extract SPA routes ──
        routes = self._extract_spa_routes(content, url)
        self.spa_routes.update(routes)

        # ── Extract API endpoints with context ──
        found = 0
        ep_patterns = [
            r'["\'`](/api/[a-zA-Z0-9_/\-{}:?=&\.\+%]+)["\'`]',
            r'["\'`](/[a-zA-Z][a-zA-Z0-9_\-]*/[a-zA-Z0-9_/\-{}:?=&\.\+%]+)["\'`]',
            r'(?:url|path|endpoint|baseURL|href)\s*[:=]\s*["\'`](/[a-zA-Z0-9_/\-{}:?=&\.\+%]+)["\'`]',
            r'(?:fetch|axios|post|get|put|delete|patch|request|\$http)\s*[\.(]\s*["\'`](/[a-zA-Z0-9_/\-{}:?=&\.\+%]+)["\'`]',
            r'(?:fetch|axios|post|get|put|delete|patch|request|\$http)\s*[\.(]\s*["\'`](https?://[^\s"\'`]+)["\'`]',
            r'\+\s*["\'](/api/[a-zA-Z0-9_/\-]+)["\']',
            r'["\'`](/[a-zA-Z][a-zA-Z0-9_/\-]*\?[a-zA-Z0-9_=&%\+\-\.]+)["\'`]',
        ]

        for pat in ep_patterns:
            for m in re.finditer(pat, content):
                endpoint = m.group(1)
                if any(endpoint.lower().endswith(ext) for ext in
                       ('.js', '.css', '.png', '.jpg', '.gif', '.svg', '.ico', '.woff', '.map', '.json')):
                    continue

                endpoint = re.sub(r'\$\{[^}]+\}', '1', endpoint)  # resolve template literals

                # Context
                start = max(0, m.start() - 800)
                end = min(len(content), m.end() + 800)
                context = content[start:end]

                method = self._detect_method(endpoint, context)
                ct = self._detect_content_type(context) if method in ('POST', 'PUT', 'PATCH') else None
                params = self._extract_params(endpoint, context)

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

        # ── Secrets ──
        for sec_type, patterns in self.secret_patterns.items():
            for pattern in patterns:
                for m in re.finditer(pattern, content, re.I):
                    val = m.group(1) if m.groups() else m.group(0)
                    if val and len(val) >= 8:
                        skip = ('placeholder', 'example', 'test', 'xxx', 'null', 'undefined')
                        if not any(s in val.lower() for s in skip):
                            ctx_start = max(0, m.start() - 80)
                            ctx_end = min(len(content), m.end() + 80)
                            self.js_extracted_secrets.append({
                                'type': sec_type,
                                'value': val,
                                'file': url,
                                'context': content[ctx_start:ctx_end].replace('\n', ' ')[:300],
                            })

        # ── Find more JS file references ──
        js_ref_patterns = [
            r'import\s*\(\s*["\']([^"\']+\.js)["\']',
            r'import\s+.*?\s+from\s+["\']([^"\']+\.js)["\']',
            r'require\s*\(\s*["\']([^"\']+\.js)["\']',
            r'["\']([^"\']*?[a-zA-Z0-9_\-]+\.[a-f0-9]{6,}\.js)["\']',
            r'["\']([^"\']*?_nuxt/[a-zA-Z0-9_\-/\.]+\.js)["\']',
            r'["\']([^"\']*?assets/[a-zA-Z0-9_\-\.]+\.js)["\']',
            r'["\'](/[a-zA-Z0-9_\-/]+\.js)["\']',
            # Webpack chunk loading
            r'["\']((?:https?://)?[^"\']*?\.chunk\.js)["\']',
            r'["\']([^"\']+\.module\.js)["\']',
        ]
        for pat in js_ref_patterns:
            for m in re.finditer(pat, content):
                ref = m.group(1)
                if ref.startswith('http'):
                    if self._is_same_scope(ref):
                        parsed = urlparse(ref)
                        self.js_files.add(urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', '')))
                else:
                    try:
                        full = urljoin(url, ref)
                        if self._is_same_scope(full):
                            parsed = urlparse(full)
                            self.js_files.add(urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', '')))
                    except:
                        pass

        return found

    def _detect_method(self, endpoint, context):
        ctx = context.lower()
        for pat, meth in [
            (r'\.post\s*\(', 'POST'), (r'\.put\s*\(', 'PUT'), (r'\.delete\s*\(', 'DELETE'),
            (r'\.patch\s*\(', 'PATCH'), (r'\.get\s*\(', 'GET'),
            (r'method\s*[:=]\s*["\']post', 'POST'), (r'method\s*[:=]\s*["\']put', 'PUT'),
            (r'method\s*[:=]\s*["\']delete', 'DELETE'), (r'method\s*[:=]\s*["\']get', 'GET'),
        ]:
            if re.search(pat, ctx):
                return meth

        ep_lower = endpoint.lower()
        if any(w in ep_lower for w in ('create', 'add', 'register', 'login', 'signup', 'upload', 'submit', 'save')):
            return 'POST'
        if any(w in ep_lower for w in ('update', 'edit', 'modify')):
            return 'PUT'
        if any(w in ep_lower for w in ('delete', 'remove')):
            return 'DELETE'
        return 'GET'

    def _detect_content_type(self, context):
        ctx = context.lower()
        if 'multipart/form-data' in ctx or 'formdata' in ctx:
            return 'multipart/form-data'
        if 'urlencoded' in ctx:
            return 'application/x-www-form-urlencoded'
        return 'application/json'

    def _extract_params(self, endpoint, context):
        params = {'path': [], 'query': [], 'body': [], 'all': []}
        params['path'] = list(set(re.findall(r'[{:]([a-zA-Z0-9_]+)[}]?', endpoint)))
        if '?' in endpoint:
            q = endpoint.split('?', 1)[1]
            params['query'] = list(set(re.findall(r'([a-zA-Z0-9_]+)=', q)))
        for pat in [r'(?:data|body|payload|params)\s*[:=]\s*\{([^}]{1,500})\}']:
            for m in re.findall(pat, context, re.I):
                params['body'].extend(re.findall(r'([a-zA-Z0-9_]+)\s*:', m))
        params['body'] = list(set(params['body']))
        params['all'] = sorted(set(params['path'] + params['query'] + params['body']))
        return params

    # ─── Process & Organize ──────────────────────────────────────────────────

    def _process_all(self):
        """Organize everything into GET/POST/OTHER"""

        # 1. Process network-intercepted requests
        for req in self.intercepted_requests:
            url = req['url']
            method = req['method']
            if not self._is_same_scope(url):
                continue

            sig = self._url_signature(method, url)
            if sig in self.seen_signatures:
                continue
            self.seen_signatures.add(sig)

            parsed = urlparse(url)
            entry = {
                'url': url,
                'method': method,
                'path': parsed.path,
                'query_params': dict(parse_qs(parsed.query, keep_blank_values=True)),
                'post_data': req.get('post_data'),
                'source': 'network',
            }

            if method == 'GET':
                self.get_endpoints[url] = entry
            elif method == 'POST':
                self.post_endpoints[url] = entry
            else:
                self.other_endpoints[url] = entry

        # 2. Process JS-extracted endpoints
        for ep in self.js_extracted_endpoints:
            url = ep['full_url']
            method = ep['method']

            if self.auth_params and '?' in url:
                url += '&' + self.auth_params
            elif self.auth_params:
                url += '?' + self.auth_params

            sig = self._url_signature(method, url)
            if sig in self.seen_signatures:
                continue
            self.seen_signatures.add(sig)

            parsed = urlparse(url)
            entry = {
                'url': url,
                'method': method,
                'path': ep['endpoint'],
                'query_params': dict(parse_qs(parsed.query, keep_blank_values=True)),
                'body_params': ep['params'].get('body', []),
                'content_type': ep.get('content_type'),
                'source': f"js:{ep['source_js']}",
            }

            if method == 'GET':
                self.get_endpoints[url] = entry
            elif method == 'POST':
                self.post_endpoints[url] = entry
            else:
                self.other_endpoints[url] = entry

        # 3. Process SPA routes as GET endpoints
        expanded_routes = self._expand_routes_with_params()
        for route in expanded_routes:
            if route.startswith('/'):
                url = self.origin + route
            elif route.startswith('http'):
                url = route
            else:
                continue

            if not self._is_same_scope(url):
                continue

            sig = self._url_signature('GET', url)
            if sig in self.seen_signatures:
                continue
            self.seen_signatures.add(sig)

            parsed = urlparse(url)
            entry = {
                'url': url,
                'method': 'GET',
                'path': parsed.path + ('?' + parsed.query if parsed.query else ''),
                'query_params': dict(parse_qs(parsed.query, keep_blank_values=True)),
                'source': 'spa_route',
            }
            self.get_endpoints[url] = entry

        # 4. Add all unique intercepted URLs that are in scope
        for url in self.intercepted_urls:
            if not self._is_same_scope(url):
                continue
            parsed = urlparse(url)
            if any(parsed.path.endswith(ext) for ext in ('.js', '.css', '.png', '.jpg', '.svg', '.ico', '.woff')):
                continue

            sig = self._url_signature('GET', url)
            if sig in self.seen_signatures:
                continue
            self.seen_signatures.add(sig)

            entry = {
                'url': url,
                'method': 'GET',
                'path': parsed.path,
                'query_params': dict(parse_qs(parsed.query, keep_blank_values=True)),
                'source': 'intercepted',
            }
            self.get_endpoints[url] = entry

    # ─── cURL Generation ─────────────────────────────────────────────────────

    def _sample_val(self, name):
        n = name.lower()
        if 'id' in n: return 1
        if 'email' in n: return "test@example.com"
        if 'pass' in n: return "Test123!"
        if 'name' in n: return "test"
        if 'page' in n: return 1
        if 'limit' in n or 'size' in n: return 20
        if 'type' in n: return "default"
        if 'token' in n: return "TOKEN_HERE"
        return f"test_{name}"

    def _make_curl(self, entry, verbose=False):
        url = entry['url']
        method = entry['method']
        v = '-v' if verbose else '-s -o /dev/null -w "%{http_code}"'
        cmd = f'curl {v} -X {method} "{url}"'

        if method in ('POST', 'PUT', 'PATCH'):
            ct = entry.get('content_type', 'application/json')
            cmd += f' \\\n  -H "Content-Type: {ct}"'

            post_data = entry.get('post_data')
            body_params = entry.get('body_params', [])

            if post_data and not post_data.startswith('<binary'):
                # Escape single quotes in post data
                safe_data = post_data.replace("'", "'\\''")
                cmd += f" \\\n  -d '{safe_data}'"
            elif body_params:
                body = {p: self._sample_val(p) for p in body_params}
                cmd += f" \\\n  -d '{json.dumps(body)}'"
            else:
                cmd += " \\\n  -d '{}'"

        return cmd

    # ─── Save Results ────────────────────────────────────────────────────────

    def _save_results(self):
        od = self.output_dir

        # ── GET endpoints (one URL per line) ──
        with open(os.path.join(od, "GET_endpoints.txt"), 'w') as f:
            f.write(f"# GET Endpoints — {len(self.get_endpoints)} found\n")
            f.write(f"# Target: {self.target_url}\n")
            f.write(f"# {datetime.now().isoformat()}\n")
            f.write(f"# {'='*76}\n\n")
            for url in sorted(self.get_endpoints.keys()):
                f.write(f"{url}\n")

        # ── POST endpoints ──
        with open(os.path.join(od, "POST_endpoints.txt"), 'w') as f:
            f.write(f"# POST Endpoints — {len(self.post_endpoints)} found\n")
            f.write(f"# Target: {self.target_url}\n")
            f.write(f"# {datetime.now().isoformat()}\n")
            f.write(f"# {'='*76}\n\n")
            for url, entry in sorted(self.post_endpoints.items()):
                f.write(f"{url}\n")
                if entry.get('body_params'):
                    f.write(f"  Body: {', '.join(entry['body_params'])}\n")
                if entry.get('post_data') and not str(entry.get('post_data', '')).startswith('<binary'):
                    f.write(f"  Data: {str(entry['post_data'])[:200]}\n")
                if entry.get('content_type'):
                    f.write(f"  Type: {entry['content_type']}\n")
                f.write("\n")

        # ── OTHER endpoints ──
        if self.other_endpoints:
            with open(os.path.join(od, "OTHER_endpoints.txt"), 'w') as f:
                f.write(f"# PUT/DELETE/PATCH — {len(self.other_endpoints)}\n\n")
                for url, entry in sorted(self.other_endpoints.items()):
                    f.write(f"[{entry['method']}] {url}\n")

        # ── ALL endpoints combined ──
        with open(os.path.join(od, "ALL_endpoints.txt"), 'w') as f:
            f.write(f"# All Endpoints — {self.target_url}\n")
            f.write(f"# GET: {len(self.get_endpoints)} | POST: {len(self.post_endpoints)} | OTHER: {len(self.other_endpoints)}\n\n")

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

        # ── SPA Routes (raw) ──
        with open(os.path.join(od, "SPA_routes.txt"), 'w') as f:
            f.write(f"# Client-Side (SPA) Routes Discovered — {len(self.spa_routes)}\n")
            f.write(f"# These are Vue/Nuxt/React router paths found in JS bundles\n\n")
            for route in sorted(self.spa_routes):
                f.write(f"{self.origin}{route}\n")

        # ── cURL GET ──
        curl_get = os.path.join(od, "curl_GET.sh")
        with open(curl_get, 'w') as f:
            f.write("#!/bin/bash\n")
            f.write(f"# GET endpoint verification — {len(self.get_endpoints)} endpoints\n")
            f.write('# Run: bash curl_GET.sh 2>/dev/null\n\n')
            for url, entry in sorted(self.get_endpoints.items()):
                curl = self._make_curl(entry)
                f.write(f"echo \"[GET] {entry.get('path', url[:80])}\"\n")
                f.write(f"{curl}\n")
                f.write('echo ""\n\n')
        os.chmod(curl_get, 0o755)

        # ── cURL POST ──
        curl_post = os.path.join(od, "curl_POST.sh")
        with open(curl_post, 'w') as f:
            f.write("#!/bin/bash\n")
            f.write(f"# POST endpoint verification — {len(self.post_endpoints)} endpoints\n\n")
            for url, entry in sorted(self.post_endpoints.items()):
                curl = self._make_curl(entry)
                f.write(f"echo \"[POST] {entry.get('path', url[:80])}\"\n")
                f.write(f"{curl}\n")
                f.write('echo ""\n\n')
        os.chmod(curl_post, 0o755)

        # ── cURL ALL verbose ──
        curl_all = os.path.join(od, "curl_ALL_verbose.sh")
        with open(curl_all, 'w') as f:
            f.write("#!/bin/bash\n")
            f.write("# All endpoints — verbose cURL for verification\n\n")
            all_entries = list(self.get_endpoints.items()) + \
                          list(self.post_endpoints.items()) + \
                          list(self.other_endpoints.items())
            for url, entry in sorted(all_entries, key=lambda x: x[0]):
                f.write(f"# [{entry['method']}] {entry.get('path', '')}\n")
                f.write(f"{self._make_curl(entry, verbose=True)}\n\n")
        os.chmod(curl_all, 0o755)

        # ── Secrets ──
        if self.js_extracted_secrets:
            unique = []
            seen = set()
            for s in self.js_extracted_secrets:
                key = (s['type'], s['value'])
                if key not in seen:
                    seen.add(key)
                    unique.append(s)

            with open(os.path.join(od, "SECRETS.txt"), 'w') as f:
                f.write(f"# Secrets Found: {len(unique)}\n\n")
                for s in unique:
                    f.write(f"[{s['type']}] {s['value']}\n  File: {s['file']}\n  Context: {s['context'][:200]}\n\n")

            with open(os.path.join(od, "SECRETS.json"), 'w') as f:
                json.dump(unique, f, indent=2)

        # ── JS files list ──
        with open(os.path.join(od, "JS_files.txt"), 'w') as f:
            f.write(f"# JS Files: {len(self.js_files)}\n\n")
            for u in sorted(self.js_files):
                dl = "✓" if u in self.js_content_cache else "✗"
                f.write(f"[{dl}] {u}\n")

        # ── API calls observed (deduped) ──
        with open(os.path.join(od, "API_calls.txt"), 'w') as f:
            seen_api = OrderedDict()
            for call in self.api_calls:
                key = f"{call['method']} {call['url']}"
                if key not in seen_api:
                    seen_api[key] = call

            f.write(f"# Unique API Calls (JSON responses) — {len(seen_api)}\n\n")
            for key, call in seen_api.items():
                f.write(f"[{call['method']}] [{call['status']}] {call['url']}\n")

        # ── Postman collection ──
        postman = {
            "info": {
                "name": f"EndpointHunter - {self.netloc}",
                "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
            },
            "item": []
        }
        for method, endpoints in [("GET", self.get_endpoints), ("POST", self.post_endpoints)]:
            folder = {"name": method, "item": []}
            for url, entry in sorted(endpoints.items()):
                item = {"name": entry.get('path', url[:60]), "request": {"method": method, "url": url}}
                if method == 'POST':
                    item['request']['header'] = [{"key": "Content-Type", "value": entry.get('content_type', 'application/json')}]
                    pd = entry.get('post_data')
                    bp = entry.get('body_params', [])
                    if pd and not str(pd).startswith('<binary'):
                        item['request']['body'] = {"mode": "raw", "raw": pd}
                    elif bp:
                        item['request']['body'] = {"mode": "raw", "raw": json.dumps({p: self._sample_val(p) for p in bp})}
                folder['item'].append(item)
            postman['item'].append(folder)

        with open(os.path.join(od, "postman_collection.json"), 'w') as f:
            json.dump(postman, f, indent=2)

        # ── Summary ──
        n_secrets = len(set((s['type'], s['value']) for s in self.js_extracted_secrets))
        with open(os.path.join(od, "SUMMARY.txt"), 'w') as f:
            f.write(f"{'='*80}\n EndpointHunter v3.0 Scan Summary\n{'='*80}\n")
            f.write(f" Target:          {self.target_url}\n")
            f.write(f" Date:            {datetime.now().isoformat()}\n")
            f.write(f" Pages Visited:   {len(self.visited_pages)}\n")
            f.write(f" SPA Routes:      {len(self.spa_routes)}\n")
            f.write(f" GET endpoints:   {len(self.get_endpoints)}\n")
            f.write(f" POST endpoints:  {len(self.post_endpoints)}\n")
            f.write(f" OTHER endpoints: {len(self.other_endpoints)}\n")
            f.write(f" JS files:        {len(self.js_files)} ({len(self.js_content_cache)} downloaded)\n")
            f.write(f" Secrets:         {n_secrets}\n")
            f.write(f" Network reqs:    {len(self.intercepted_requests)}\n")
            f.write(f" API calls:       {len(self.api_calls)}\n")
            f.write(f"{'='*80}\n")

    # ─── Main Execution ──────────────────────────────────────────────────────

    async def run(self):
        start = datetime.now()
        banner()

        print(f"  {C.BOLD}Target:{C.END}    {self.target_url}")
        print(f"  {C.BOLD}Depth:{C.END}     {self.max_depth}")
        print(f"  {C.BOLD}Max Pages:{C.END} {self.max_pages}")
        print(f"  {C.BOLD}Output:{C.END}    {self.output_dir}/")

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

            # Hook network interception
            page.on('request', self._on_request)
            page.on('response', self._on_response)

            # ══════════════════════════════════════════════════════════════
            # Phase 1: Initial page load + deep interaction
            # ══════════════════════════════════════════════════════════════
            print(f"\n  {C.BOLD}{C.Y}═══ Phase 1: Initial Load + Deep Interaction ═══{C.END}\n")

            try:
                await page.goto(self.target_url, wait_until='domcontentloaded', timeout=self.timeout * 1000)
                try:
                    await page.wait_for_load_state('networkidle', timeout=15000)
                except:
                    pass
                await page.wait_for_timeout(3000)
            except Exception as e:
                self._log(f"Initial load error: {e}", "err")

            self.visited_pages.add(self.target_url)

            # Deep interact with homepage
            self._log("Interacting with homepage (clicking tabs, scrolling, pagination)...")
            await self._deep_interact(page)

            # Extract links
            links = await self._extract_all_links(page)
            for link in links:
                if self._is_same_scope(link):
                    parsed = urlparse(link)
                    if parsed.path and parsed.path != '/':
                        self.spa_routes.add(parsed.path + ('?' + parsed.query if parsed.query else ''))

            self._log(f"Network requests captured: {len(self.intercepted_requests)}", "ok")
            self._log(f"SPA routes found: {len(self.spa_routes)}", "ok")
            self._log(f"JS files found: {len(self.js_files)}", "ok")

            # ══════════════════════════════════════════════════════════════
            # Phase 2: Fetch Nuxt/Vue manifest & download ALL JS
            # ══════════════════════════════════════════════════════════════
            print(f"\n  {C.BOLD}{C.Y}═══ Phase 2: JS Discovery & Download ═══{C.END}\n")

            # Try Nuxt manifest
            await self._fetch_nuxt_manifest(page)

            # Also grab all JS from intercepted requests
            for req in self.intercepted_requests:
                url = req['url']
                parsed = urlparse(url)
                if parsed.path.endswith('.js') and self._is_same_scope(url):
                    self.js_files.add(urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', '')))

            # Recursive JS download & analysis
            for pass_num in range(1, 6):
                initial_count = len(self.js_files)
                await self._download_js_files(page)

                to_analyze = [u for u in self.js_content_cache if u not in self.analyzed_js]
                total_eps = 0
                for url in to_analyze:
                    n = self._analyze_js_content(url, self.js_content_cache[url])
                    total_eps += n

                new_js = len(self.js_files) - initial_count
                self._log(f"Pass {pass_num}: analyzed {len(to_analyze)} JS, "
                          f"found {total_eps} endpoints, {len(self.spa_routes)} routes, "
                          f"{new_js} new JS refs", "info")

                if new_js == 0:
                    self._log("No more JS files to discover ✓", "ok")
                    break

            # ══════════════════════════════════════════════════════════════
            # Phase 3: Visit discovered SPA routes
            # ══════════════════════════════════════════════════════════════
            print(f"\n  {C.BOLD}{C.Y}═══ Phase 3: Visiting SPA Routes ═══{C.END}\n")

            # Navigate back to homepage first
            try:
                await page.goto(self.target_url, wait_until='domcontentloaded', timeout=15000)
                await page.wait_for_timeout(2000)
            except:
                pass

            # Visit key SPA routes to trigger their API calls
            routes_to_visit = sorted(self.spa_routes)
            # Prioritize interesting routes
            priority_keywords = ['all', 'game', 'slot', 'live', 'sport', 'vip', 'promotion',
                                 'help', 'detail', 'user', 'account', 'wallet', 'deposit',
                                 'withdraw', 'history', 'record', 'rank', 'agent', 'referral']
            priority_routes = [r for r in routes_to_visit
                              if any(kw in r.lower() for kw in priority_keywords)]
            other_routes = [r for r in routes_to_visit if r not in priority_routes]
            ordered_routes = priority_routes + other_routes

            visited_count = 0
            for route in ordered_routes[:100]:  # Cap at 100 SPA routes
                if visited_count >= self.max_pages:
                    break

                full_url = self.origin + route if route.startswith('/') else route
                if full_url in self.visited_pages:
                    continue

                self._log(f"[{visited_count+1:03d}] Visiting: {route[:80]}", "dim")
                await self._navigate_spa_route(page, route)
                visited_count += 1

            self._log(f"Visited {visited_count} SPA routes", "ok")
            self._log(f"Total network requests: {len(self.intercepted_requests)}", "ok")

            await browser.close()

        # ══════════════════════════════════════════════════════════════
        # Phase 4: Process & Save
        # ══════════════════════════════════════════════════════════════
        print(f"\n  {C.BOLD}{C.Y}═══ Phase 4: Processing & Saving ═══{C.END}\n")
        self._process_all()
        self._save_results()

        elapsed = datetime.now() - start
        n_secrets = len(set((s['type'], s['value']) for s in self.js_extracted_secrets))

        print(f"""
  {C.BOLD}{C.G}{'═'*60}
  SCAN COMPLETE
  {'═'*60}{C.END}
  {C.W}Output:          {C.CY}{self.output_dir}/{C.END}
  {C.W}Pages Visited:   {C.G}{len(self.visited_pages)}{C.END}
  {C.W}SPA Routes:      {C.G}{len(self.spa_routes)}{C.END}
  {C.W}Network Reqs:    {C.G}{len(self.intercepted_requests)}{C.END}
  {C.W}API Calls:       {C.M}{len(self.api_calls)}{C.END}
  {C.W}JS Files:        {C.G}{len(self.js_files)} ({len(self.js_content_cache)} downloaded){C.END}
  {C.W}GET Endpoints:   {C.G}{len(self.get_endpoints)}{C.END}
  {C.W}POST Endpoints:  {C.R}{len(self.post_endpoints)}{C.END}
  {C.W}OTHER Endpoints: {C.Y}{len(self.other_endpoints)}{C.END}
  {C.W}Secrets:         {C.R}{n_secrets}{C.END}
  {C.W}Time:            {C.CY}{elapsed}{C.END}
  {C.BOLD}{C.G}{'═'*60}{C.END}

  {C.BOLD}Files:{C.END}
  {C.DIM}├── GET_endpoints.txt       — GET URLs (one per line)
  ├── POST_endpoints.txt      — POST URLs + params + body
  ├── OTHER_endpoints.txt     — PUT/DELETE/PATCH
  ├── ALL_endpoints.txt       — Everything combined
  ├── SPA_routes.txt          — Client-side routes from JS
  ├── API_calls.txt           — Observed JSON API calls
  ├── curl_GET.sh             — cURL verify GET
  ├── curl_POST.sh            — cURL verify POST
  ├── curl_ALL_verbose.sh     — Verbose cURL all
  ├── postman_collection.json — Import to Postman/Burp
  ├── SECRETS.txt / .json     — Leaked secrets
  ├── JS_files.txt            — JS file inventory
  ├── SUMMARY.txt             — Scan summary
  └── js_files/               — Downloaded JS source{C.END}
""")


def main():
    parser = argparse.ArgumentParser(
        description='EndpointHunter v3.0 — SPA-Aware Endpoint Discovery',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 endpoint_hunter.py https://mgc88.cc/
  python3 endpoint_hunter.py https://target.com -d 15 -v
  python3 endpoint_hunter.py https://target.com --auth "token=abc" --max-pages 1000

Key improvements over v2:
  ✓ SPA-aware (Nuxt/Vue/React) — extracts client-side routes from JS bundles
  ✓ Visits discovered SPA routes to trigger API calls
  ✓ Clicks tabs, filters, pagination to discover dynamic endpoints
  ✓ Fixed binary post_data crash (UnicodeDecodeError)
  ✓ Nuxt manifest parsing for complete route & chunk discovery
  ✓ API_calls.txt — all JSON API responses observed
  ✓ SPA_routes.txt — client-side routes extracted from JS
        """
    )

    parser.add_argument('url', help='Target URL')
    parser.add_argument('-d', '--depth', type=int, default=10, help='Max depth (default: 10)')
    parser.add_argument('--auth', help='Auth query params (e.g., "uid=123&key=abc")')
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('--max-pages', type=int, default=500, help='Max pages (default: 500)')
    parser.add_argument('--timeout', type=int, default=60, help='Timeout secs (default: 60)')
    parser.add_argument('--show-browser', action='store_true', help='Show browser')

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
