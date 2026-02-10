#!/usr/bin/env python3
"""
EndpointHunter v4.0 — SPA Chunk-First Endpoint Discovery
Strategy: Download ALL JS chunks → extract routes+params together → build complete URLs
One unique URL per route+param structure (no duplicates)
"""

import asyncio
import re
import json
import argparse
import os
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs, urlencode
from datetime import datetime
from collections import OrderedDict

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
 ║  {C.BOLD}EndpointHunter v4.0{C.END}{C.CY} — Chunk-First SPA Endpoint Discovery    ║
 ║  ALL JS Chunks · Route+Param Pairing · Complete URL Builder      ║
 ╚═══════════════════════════════════════════════════════════════════╝{C.END}
""")


class EndpointHunter:

    def __init__(self, target_url, max_depth=10, auth_params=None, verbose=False,
                 headless=True, timeout=60, max_pages=300):
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

        # Track ALL domains the site uses (CDN, API, etc.)
        self.asset_domains = set()  # CDN domains serving JS chunks
        self.asset_domains.add(self.netloc)

        # JS
        self.js_urls = set()
        self.js_content = {}       # url -> content
        self.analyzed_js = set()

        # Network intercept
        self.intercepted = []
        self.api_log_seen = {}

        # Discovered data
        self.raw_routes = set()           # /path only
        self.raw_api_endpoints = set()    # /api/... paths
        self.route_param_pairs = []       # [{route, params, method, context}]
        self.query_param_names = set()    # all param names found globally

        # Final output — ONE url per structural signature
        self.get_endpoints = OrderedDict()
        self.post_endpoints = OrderedDict()
        self.other_endpoints = OrderedDict()

        self.secrets = []
        self.output_dir = self._create_output_dir()

        self.secret_patterns = {
            'API Key': [r'(?i)(?:api[_-]?key|apikey)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']'],
            'Secret/Token': [r'(?i)(?:secret|token|auth)[_-]?(?:key)?["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']'],
            'Bearer': [r'(?i)bearer\s+([a-zA-Z0-9_\-\.]{30,})'],
            'JWT': [r'eyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}'],
            'AWS Key': [r'AKIA[0-9A-Z]{16}'],
            'Private Key': [r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'],
            'DB URL': [r'(?:mongodb(?:\+srv)?|mysql|postgres(?:ql)?|redis)://[^\s"\'<>]+'],
        }

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _get_base_domain(self, netloc):
        parts = netloc.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else netloc

    def _is_target_scope(self, url):
        """Is this URL on the target domain (for endpoints)?"""
        try:
            return urlparse(url).netloc == self.netloc
        except:
            return False

    def _is_asset_scope(self, url):
        """Is this URL on a known asset/CDN domain (for JS files)?"""
        try:
            netloc = urlparse(url).netloc
            return netloc in self.asset_domains or netloc == self.netloc
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

    def _sig(self, method, path, param_keys):
        """Structural signature for dedup: method + path_template + sorted_param_keys"""
        # Normalize path: replace numeric segments with {N}
        parts = path.split("/")
        norm = []
        for p in parts:
            if re.match(r'^\d+$', p):
                norm.append("{N}")
            elif re.match(r'^[a-f0-9]{8,}$', p, re.I):
                norm.append("{H}")
            else:
                norm.append(p)
        norm_path = "/".join(norm)
        keys = ",".join(sorted(param_keys)) if param_keys else ""
        return f"{method}|{norm_path}|{keys}"

    def _log(self, msg, level="info"):
        colors = {"info": C.CY, "ok": C.G, "warn": C.Y, "err": C.R, "dim": C.DIM}
        print(f"  {colors.get(level, C.W)}{msg}{C.END}")

    def _vlog(self, msg):
        if self.verbose:
            print(f"    {C.DIM}{msg}{C.END}")

    # ── Network Interception ─────────────────────────────────────────────────

    def _on_request(self, request):
        url = request.url
        if not url.startswith("http"):
            return

        parsed = urlparse(url)

        # Detect CDN domains serving JS/assets for this site
        if parsed.path.endswith('.js') and ('_nuxt' in url or 'chunk' in url or 'assets' in url):
            self.asset_domains.add(parsed.netloc)
            clean = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))
            self.js_urls.add(clean)
            return

        # Only record endpoints on the TARGET domain
        if not self._is_target_scope(url):
            return

        # Skip static
        skip_ext = ('.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff',
                    '.woff2', '.ttf', '.eot', '.mp4', '.mp3', '.webp', '.css', '.map')
        if any(parsed.path.lower().endswith(ext) for ext in skip_ext):
            return

        # Also record JS on target domain
        if parsed.path.endswith('.js'):
            self.js_urls.add(urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', '')))
            return

        # Safe post_data
        post_data = None
        try:
            post_data = request.post_data
        except Exception:
            try:
                raw = request.post_data_buffer
                post_data = f"<binary:{len(raw)}b>" if raw else None
            except:
                pass

        method = request.method.upper()
        self.intercepted.append({
            'url': url, 'method': method, 'post_data': post_data,
            'path': parsed.path, 'query': parsed.query,
        })

    def _on_response(self, response):
        try:
            url = response.url
            if not self._is_target_scope(url):
                return
            ct = response.headers.get('content-type', '')
            if 'application/json' not in ct:
                return

            method = response.request.method.upper()
            parsed = urlparse(url)
            pkeys = ",".join(sorted(parse_qs(parsed.query).keys()))
            dedup = f"{method}:{parsed.path}:{pkeys}"

            count = self.api_log_seen.get(dedup, 0)
            self.api_log_seen[dedup] = count + 1
            if count < 2:
                self._vlog(f"[API] {method} {url[:120]}")
            elif count == 2:
                self._vlog(f"[API] {method} {parsed.path} (suppressing dupes)")
        except:
            pass

    # ── Phase 1: Load page, intercept traffic, discover CDN domain ───────────

    async def _phase1_load_and_intercept(self, page):
        """Load the target, interact heavily, capture all network + discover CDN"""
        print(f"\n  {C.BOLD}{C.Y}═══ Phase 1: Load Target + Intercept Traffic ═══{C.END}\n")

        try:
            await page.goto(self.target_url, wait_until='domcontentloaded', timeout=self.timeout * 1000)
            try:
                await page.wait_for_load_state('networkidle', timeout=15000)
            except:
                pass
            await page.wait_for_timeout(3000)
        except Exception as e:
            self._log(f"Load error: {e}", "err")

        # ── Discover the CDN domain from <script> tags and <link> tags ──
        try:
            srcs = await page.evaluate('''() => {
                const urls = [];
                document.querySelectorAll('script[src]').forEach(s => urls.push(s.src));
                document.querySelectorAll('link[href]').forEach(l => urls.push(l.href));
                return urls;
            }''')
            for src in srcs:
                parsed = urlparse(src)
                if parsed.path.endswith('.js'):
                    self.asset_domains.add(parsed.netloc)
                    self.js_urls.add(urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', '')))
        except:
            pass

        self._log(f"Asset domains detected: {self.asset_domains}", "ok")
        self._log(f"JS files found: {len(self.js_urls)}", "ok")

        # ── Heavy interaction to trigger API calls ──
        self._log("Interacting with page (scroll, click tabs/nav/filters)...")
        await self._interact(page)

        # ── Extract all links from DOM ──
        await self._extract_dom_links(page)

        self._log(f"Network requests captured: {len(self.intercepted)}", "ok")
        self._log(f"Routes found from DOM: {len(self.raw_routes)}", "ok")

    async def _interact(self, page):
        """Click everything interactive to trigger API calls"""
        try:
            # Scroll
            await page.evaluate('''async () => {
                for (let i = 0; i < 15; i++) {
                    window.scrollBy(0, window.innerHeight);
                    await new Promise(r => setTimeout(r, 250));
                }
                window.scrollTo(0, 0);
            }''')
            await page.wait_for_timeout(1000)

            # Click selectors
            selectors = [
                'nav a', '.nav a', '.nav-item', '.nav-link', 'header a',
                '.sidebar a', '[role="tab"]', '.tab', '.tab-item',
                '[class*="tab"]', '[class*="filter"]', '[class*="category"]',
                '[class*="menu"] a', '[class*="nav"] a',
                'button[data-type]', '[data-category]', '[class*="sort"]',
                '.pagination a', '.pagination button', '[class*="page"] a',
                'a[href*="page="]', '[class*="next"]', '[class*="more"]',
                'footer a', '.game-item a', '.card a', '[class*="card"] a',
            ]

            clicked = set()
            for sel in selectors:
                try:
                    els = await page.query_selector_all(sel)
                    for el in els[:12]:
                        try:
                            ident = await page.evaluate(
                                '(el) => (el.getAttribute("href")||"") + "|" + (el.textContent||"").trim().slice(0,20)', el)
                            if ident in clicked:
                                continue
                            clicked.add(ident)
                            if not await el.is_visible():
                                continue

                            # Capture href/to as route
                            href = await page.evaluate(
                                '(el) => el.getAttribute("href") || el.getAttribute("to") || ""', el)
                            if href and href.startswith('/') and not href.endswith(('.js', '.css', '.png')):
                                self.raw_routes.add(href)

                            await el.click(timeout=2500)
                            await page.wait_for_timeout(600)

                            # Record URL after SPA navigation
                            cur = page.url
                            if self._is_target_scope(cur):
                                p = urlparse(cur)
                                route = p.path + ('?' + p.query if p.query else '')
                                self.raw_routes.add(route)
                        except:
                            pass
                except:
                    pass
        except Exception as e:
            self._vlog(f"Interact error: {e}")

    async def _extract_dom_links(self, page):
        """Extract all link-like things from DOM"""
        try:
            results = await page.evaluate('''() => {
                const links = new Set();
                // <a href>, <a to> (Vue/Nuxt)
                document.querySelectorAll('a[href], [to]').forEach(el => {
                    const v = el.getAttribute('href') || el.getAttribute('to') || '';
                    if (v.startsWith('/') || v.startsWith('http')) links.add(v);
                });
                // data attributes
                document.querySelectorAll('[data-href],[data-url],[data-to],[data-path],[data-link]').forEach(el => {
                    for (const attr of ['data-href','data-url','data-to','data-path','data-link']) {
                        const v = el.getAttribute(attr);
                        if (v && (v.startsWith('/') || v.startsWith('http'))) links.add(v);
                    }
                });
                // inline scripts
                document.querySelectorAll('script:not([src])').forEach(s => {
                    const t = s.textContent || '';
                    const ms = t.match(/["']\\/[a-zA-Z][^"'\\s]{1,120}["']/g);
                    if (ms) ms.forEach(m => links.add(m.replace(/["']/g, '')));
                });
                return Array.from(links);
            }''')

            for link in results:
                if link.startswith('/'):
                    if not any(link.endswith(ext) for ext in ('.js', '.css', '.png', '.svg', '.ico', '.json')):
                        self.raw_routes.add(link)
                elif link.startswith('http') and self._is_target_scope(link):
                    p = urlparse(link)
                    route = p.path + ('?' + p.query if p.query else '')
                    if not any(route.endswith(ext) for ext in ('.js', '.css', '.png', '.svg', '.ico')):
                        self.raw_routes.add(route)
        except Exception as e:
            self._vlog(f"DOM link error: {e}")

    # ── Phase 2: Download ALL JS chunks (including CDN) ──────────────────────

    async def _phase2_download_all_js(self, page):
        """Download every JS file — from target AND CDN domains"""
        print(f"\n  {C.BOLD}{C.Y}═══ Phase 2: Download ALL JS Chunks ═══{C.END}\n")

        # First, try to get the Nuxt build manifest to find ALL chunks
        await self._discover_nuxt_chunks(page)

        self._log(f"Total JS files to download: {len(self.js_urls)}", "info")

        # Download in passes (JS files can reference more JS files)
        for pass_num in range(1, 6):
            to_dl = [u for u in self.js_urls if u not in self.js_content]
            if not to_dl:
                break

            self._log(f"Pass {pass_num}: downloading {len(to_dl)} JS files...", "warn")

            for i, url in enumerate(sorted(to_dl), 1):
                try:
                    resp = await page.goto(url, wait_until='load', timeout=12000)
                    if resp and resp.status == 200:
                        content = await resp.text()
                        if content and len(content) > 10:
                            self.js_content[url] = content

                            # Save
                            fname = re.sub(r'[^\w\-.]', '_', url.split('/')[-1])[:120]
                            with open(os.path.join(self.output_dir, "js_files", fname), 'w',
                                      encoding='utf-8', errors='ignore') as f:
                                f.write(content)

                            # Find more JS refs inside this file
                            self._find_js_refs(url, content)

                            if self.verbose and i % 10 == 0:
                                print(f"    {C.DIM}[{i}/{len(to_dl)}] downloaded...{C.END}")
                except:
                    pass

            new_count = len([u for u in self.js_urls if u not in self.js_content])
            self._log(f"Pass {pass_num} done. Cached: {len(self.js_content)}. Remaining: {new_count}", "ok")
            if new_count == 0:
                break

        self._log(f"Total JS downloaded: {len(self.js_content)}/{len(self.js_urls)}", "ok")

    async def _discover_nuxt_chunks(self, page):
        """Parse Nuxt build manifest to find ALL JS chunk URLs"""
        # The CDN domain is where _nuxt lives
        cdn_origins = set()
        for domain in self.asset_domains:
            for scheme in ['https']:
                cdn_origins.add(f"{scheme}://{domain}")

        # Try manifest endpoints
        manifest_paths = [
            '/_nuxt/builds/latest.json',
            '/_payload.json',
        ]

        # Also check intercepted requests for build meta URLs
        for req in self.intercepted:
            if '_nuxt/builds/meta' in req['url']:
                try:
                    resp = await page.goto(req['url'], wait_until='load', timeout=8000)
                    if resp and resp.status == 200:
                        text = await resp.text()
                        self._extract_chunk_urls_from_json(text, req['url'])
                except:
                    pass

        # Check the Nuxt build meta from all known CDN domains too
        for req_data in list(self.intercepted):
            url = req_data['url']
            if '_nuxt' in url and url.endswith('.json'):
                try:
                    resp = await page.goto(url, wait_until='load', timeout=8000)
                    if resp and resp.status == 200:
                        text = await resp.text()
                        self._extract_chunk_urls_from_json(text, url)
                except:
                    pass

        for cdn_origin in cdn_origins:
            for path in manifest_paths:
                try:
                    url = cdn_origin + path
                    resp = await page.goto(url, wait_until='load', timeout=8000)
                    if resp and resp.status == 200:
                        text = await resp.text()
                        self._extract_chunk_urls_from_json(text, url)
                        self._vlog(f"Found manifest: {url}")
                except:
                    pass

        # Brute-find JS chunk patterns from HTML source
        try:
            await page.goto(self.target_url, wait_until='domcontentloaded', timeout=15000)
            html = await page.content()
            # Find all JS references in HTML
            for m in re.finditer(r'(?:src|href)\s*=\s*["\']((?:https?://)?[^"\']*\.js(?:\?[^"\']*)?)["\']', html):
                js_ref = m.group(1)
                if js_ref.startswith('//'):
                    js_ref = 'https:' + js_ref
                elif js_ref.startswith('/'):
                    # Could be on any CDN origin
                    for cdn in cdn_origins:
                        self.js_urls.add(cdn + js_ref.split('?')[0])
                    self.js_urls.add(self.origin + js_ref.split('?')[0])
                elif js_ref.startswith('http'):
                    self.js_urls.add(js_ref.split('?')[0])
        except:
            pass

        self._log(f"After manifest scan: {len(self.js_urls)} JS files known", "ok")

    def _extract_chunk_urls_from_json(self, text, base_url):
        """Extract JS chunk URLs from Nuxt manifest JSON"""
        parsed_base = urlparse(base_url)
        base_origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

        # Find all .js references
        for m in re.finditer(r'["\']([^"\']*\.(?:js|mjs))["\']', text):
            ref = m.group(1)
            if ref.startswith('http'):
                self.js_urls.add(ref.split('?')[0])
            elif ref.startswith('/'):
                self.js_urls.add(base_origin + ref.split('?')[0])
            elif ref.startswith('./') or not ref.startswith('.'):
                # Relative to base
                base_dir = '/'.join(base_url.split('/')[:-1])
                full = base_dir + '/' + ref.lstrip('./')
                self.js_urls.add(full.split('?')[0])

    def _find_js_refs(self, base_url, content):
        """Find references to other JS files within JS content"""
        parsed_base = urlparse(base_url)
        base_origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

        patterns = [
            r'import\s*\(\s*["\']([^"\']+\.js)["\']',
            r'import\s+.*?\s+from\s+["\']([^"\']+\.js)["\']',
            r'["\']([^"\']*?[a-zA-Z0-9_\-]+\.[a-f0-9]{6,}\.js)["\']',
            r'["\']([^"\']*?_nuxt/[^\s"\']*\.js)["\']',
            r'["\']([^"\']*?assets/[^\s"\']*\.js)["\']',
            r'["\'](/[a-zA-Z0-9_\-/.]+\.js)["\']',
            # Webpack/Vite chunk patterns
            r'["\']((?:\./|\.\./)[\w\-/]+\.js)["\']',
            r'["\']([a-zA-Z0-9_\-]+\.[a-f0-9]{6,8}\.js)["\']',
        ]

        for pat in patterns:
            for m in re.finditer(pat, content):
                ref = m.group(1)
                if ref.startswith('http'):
                    p = urlparse(ref)
                    if p.netloc in self.asset_domains:
                        self.js_urls.add(ref.split('?')[0])
                elif ref.startswith('/'):
                    self.js_urls.add(base_origin + ref)
                else:
                    base_dir = '/'.join(base_url.split('/')[:-1])
                    full = base_dir + '/' + ref.lstrip('./')
                    self.js_urls.add(full.split('?')[0])

    # ── Phase 3: Analyze ALL JS — extract routes + params TOGETHER ───────────

    def _phase3_analyze_js(self):
        """The core: analyze every JS file, extract route+param pairs"""
        print(f"\n  {C.BOLD}{C.Y}═══ Phase 3: Deep JS Analysis (Routes + Params) ═══{C.END}\n")

        total_routes = 0
        total_apis = 0

        for url, content in self.js_content.items():
            if url in self.analyzed_js:
                continue
            self.analyzed_js.add(url)

            # Optionally beautify
            if HAS_BEAUTIFIER and len(content) < 2_000_000:
                try:
                    opts = jsbeautifier.default_options()
                    opts.indent_size = 2
                    content = jsbeautifier.beautify(content, opts)
                except:
                    pass

            r, a = self._analyze_single_js(url, content)
            total_routes += r
            total_apis += a

        self._log(f"Routes extracted: {total_routes}", "ok")
        self._log(f"API endpoints extracted: {total_apis}", "ok")
        self._log(f"Query param names found: {self.query_param_names}", "ok")

    def _analyze_single_js(self, url, content):
        """Analyze one JS file — find routes, API endpoints, params, secrets"""
        route_count = 0
        api_count = 0

        # ══════════════════════════════════════════════════════════════
        # 1. ROUTE + PARAM EXTRACTION (the key improvement)
        # ══════════════════════════════════════════════════════════════

        # ── Vue Router / Nuxt path definitions ──
        # Match: path: "/detail/helpCenter", path: "/all", path: "/roulette"
        for m in re.finditer(r'path\s*:\s*["\'](/[a-zA-Z0-9_/\-:.*?]*)["\']', content):
            route = m.group(1)
            if len(route) < 2 or route.endswith(('.js', '.css', '.png', '.json')):
                continue

            # Get wide context around this route to find associated params
            ctx_start = max(0, m.start() - 2000)
            ctx_end = min(len(content), m.end() + 2000)
            context = content[ctx_start:ctx_end]

            # Extract query params from context
            params = self._extract_params_from_context(context)

            # Resolve dynamic segments: /detail/:id → /detail/1
            resolved = self._resolve_dynamic(route)

            self.raw_routes.add(resolved)
            if params:
                self.route_param_pairs.append({
                    'route': resolved,
                    'raw_route': route,
                    'params': params,
                    'method': 'GET',
                    'source': url,
                })
            route_count += 1

        # ── Nuxt route name → path conversion ──
        # name: "detail-helpCenter", name: "all", name: "roulette"
        for m in re.finditer(r'(?:name|component)\s*:\s*["\']([a-zA-Z][a-zA-Z0-9_\-]+)["\']', content):
            name = m.group(1)
            # Skip common non-route names
            if name in ('default', 'index', 'error', 'layout', 'app', 'head', 'body',
                        'script', 'style', 'template', 'slot', 'transition'):
                continue
            # Convert name to path: "detail-helpCenter" → "/detail/helpCenter"
            path = "/" + name.replace("---", "/").replace("--", "/").replace("-", "/")
            # Also try keeping hyphens for some
            path_hyphen = "/" + name

            ctx_start = max(0, m.start() - 2000)
            ctx_end = min(len(content), m.end() + 2000)
            context = content[ctx_start:ctx_end]
            params = self._extract_params_from_context(context)

            self.raw_routes.add(path)
            self.raw_routes.add(path_hyphen)
            if params:
                self.route_param_pairs.append({
                    'route': path, 'params': params, 'method': 'GET', 'source': url,
                })
            route_count += 1

        # ── Direct path strings with query params ──
        # "/all?type=IsNew&page=1", "/roulette?page=1&name=f"
        for m in re.finditer(r'["\'`](/[a-zA-Z][a-zA-Z0-9_/\-]*\?[a-zA-Z0-9_=&%\+\-\.]+)["\'`]', content):
            full_path = m.group(1)
            path_part = full_path.split('?')[0]
            query_part = full_path.split('?')[1] if '?' in full_path else ''

            params = {}
            for kv in query_part.split('&'):
                if '=' in kv:
                    k, v = kv.split('=', 1)
                    params[k] = v

            self.raw_routes.add(path_part)
            if params:
                self.route_param_pairs.append({
                    'route': path_part, 'params': params, 'method': 'GET', 'source': url,
                })
            route_count += 1

        # ── All /path strings that look like routes ──
        for m in re.finditer(r'["\'](/[a-z][a-zA-Z0-9]*(?:/[a-zA-Z0-9_\-]*)*)["\']', content):
            path = m.group(1)
            if any(path.endswith(ext) for ext in ('.js', '.css', '.png', '.json', '.svg', '.ico', '.map')):
                continue
            if any(seg in path for seg in ('node_modules', '__', 'assets/', 'static/', '_nuxt')):
                continue
            if len(path) > 1 and len(path) < 80:
                self.raw_routes.add(path)
                route_count += 1

        # ══════════════════════════════════════════════════════════════
        # 2. API ENDPOINTS
        # ══════════════════════════════════════════════════════════════

        api_patterns = [
            (r'["\'`](/api/[a-zA-Z0-9_/\-{}:?=&\.\+%]+)["\'`]', None),
            (r'\.post\s*\(\s*["\'`](/[a-zA-Z0-9_/\-{}:?=&]+)["\'`]', 'POST'),
            (r'\.get\s*\(\s*["\'`](/[a-zA-Z0-9_/\-{}:?=&]+)["\'`]', 'GET'),
            (r'\.put\s*\(\s*["\'`](/[a-zA-Z0-9_/\-{}:?=&]+)["\'`]', 'PUT'),
            (r'\.delete\s*\(\s*["\'`](/[a-zA-Z0-9_/\-{}:?=&]+)["\'`]', 'DELETE'),
            (r'\.patch\s*\(\s*["\'`](/[a-zA-Z0-9_/\-{}:?=&]+)["\'`]', 'PATCH'),
            (r'(?:fetch|axios|request|\$http)\s*\(\s*["\'`](/[a-zA-Z0-9_/\-{}:?=&]+)["\'`]', None),
            (r'(?:url|endpoint|baseURL|apiUrl)\s*[:=]\s*["\'`](/api[a-zA-Z0-9_/\-{}:?=&]*)["\']', None),
            (r'\+\s*["\'](/api/[a-zA-Z0-9_/\-]+)["\']', None),
        ]

        for pat, forced_method in api_patterns:
            for m in re.finditer(pat, content):
                endpoint = m.group(1)
                endpoint = re.sub(r'\$\{[^}]+\}', '1', endpoint)

                if any(endpoint.endswith(ext) for ext in ('.js', '.css', '.png')):
                    continue

                ctx_start = max(0, m.start() - 1000)
                ctx_end = min(len(content), m.end() + 1000)
                context = content[ctx_start:ctx_end]

                method = forced_method or self._detect_method(endpoint, context)
                params = self._extract_params_from_context(context)
                body_params = self._extract_body_params(context) if method in ('POST', 'PUT', 'PATCH') else []

                self.raw_api_endpoints.add(endpoint)
                self.route_param_pairs.append({
                    'route': endpoint,
                    'params': params,
                    'body_params': body_params,
                    'method': method,
                    'source': url,
                })
                api_count += 1

        # ══════════════════════════════════════════════════════════════
        # 3. GLOBAL QUERY PARAM NAMES
        # ══════════════════════════════════════════════════════════════

        # query.page, params.type, route.query.id, etc.
        for m in re.finditer(r'(?:query|params|searchParams)\s*[\.\[]\s*["\']?(\w+)', content):
            name = m.group(1)
            if name not in ('length', 'toString', 'constructor', 'prototype', 'value',
                           'key', 'default', 'get', 'set', 'has', 'delete'):
                self.query_param_names.add(name)

        # ?param= patterns
        for m in re.finditer(r'[?&]([a-zA-Z_]\w{0,20})=', content):
            self.query_param_names.add(m.group(1))

        # ══════════════════════════════════════════════════════════════
        # 4. SECRETS
        # ══════════════════════════════════════════════════════════════
        for sec_type, patterns in self.secret_patterns.items():
            for pat in patterns:
                for m in re.finditer(pat, content, re.I):
                    val = m.group(1) if m.groups() else m.group(0)
                    if val and len(val) >= 8:
                        skip = ('placeholder', 'example', 'test', 'xxx', 'null', 'undefined', 'localhost')
                        if not any(s in val.lower() for s in skip):
                            cs = max(0, m.start() - 60)
                            ce = min(len(content), m.end() + 60)
                            self.secrets.append({
                                'type': sec_type, 'value': val, 'file': url,
                                'context': content[cs:ce].replace('\n', ' ')[:250],
                            })

        return route_count, api_count

    def _extract_params_from_context(self, context):
        """Extract query parameter names+sample values from surrounding JS context"""
        params = {}

        # Direct query strings: ?type=IsNew&page=1
        for m in re.finditer(r'[?&]([a-zA-Z_]\w{0,20})=([a-zA-Z0-9_\-\.%+]*)', context):
            k, v = m.group(1), m.group(2)
            if k not in params:
                params[k] = v if v else self._guess_param_value(k)

        # Object properties used as query: { type: "IsNew", page: 1 }
        # params: { type: xxx, page: xxx }
        for m in re.finditer(r'(?:query|params|searchParams)\s*[:=]?\s*\{([^}]{1,800})\}', context):
            obj = m.group(1)
            for km in re.finditer(r'([a-zA-Z_]\w{0,20})\s*:', obj):
                k = km.group(1)
                if k not in ('type', 'default', 'required', 'validator') or k == 'type':
                    # Try to find the value
                    val_match = re.search(rf'{re.escape(k)}\s*:\s*["\'`]?([a-zA-Z0-9_\-\.]+)', obj)
                    val = val_match.group(1) if val_match else self._guess_param_value(k)
                    if k not in params:
                        params[k] = val

        # route.query.xxx patterns
        for m in re.finditer(r'(?:route|router|query|params)\s*\.\s*(?:query\s*\.\s*)?([a-zA-Z_]\w{0,20})', context):
            k = m.group(1)
            if k not in ('push', 'replace', 'go', 'back', 'forward', 'resolve',
                        'value', 'path', 'name', 'hash', 'matched', 'fullPath',
                        'params', 'query', 'meta', 'redirectedFrom'):
                if k not in params:
                    params[k] = self._guess_param_value(k)

        # Also record globally
        self.query_param_names.update(params.keys())

        return params

    def _extract_body_params(self, context):
        """Extract POST body parameter names"""
        params = []
        for pat in [r'(?:data|body|payload)\s*[:=]\s*\{([^}]{1,800})\}',
                    r'JSON\.stringify\s*\(\s*\{([^}]{1,800})\}']:
            for m in re.findall(pat, context, re.I):
                for km in re.finditer(r'([a-zA-Z_]\w{0,20})\s*:', m):
                    params.append(km.group(1))
        return list(set(params))

    def _resolve_dynamic(self, route):
        """Resolve dynamic route segments: /detail/:id → /detail/1"""
        route = re.sub(r':([a-zA-Z_]\w*)', lambda m: str(self._guess_param_value(m.group(1))), route)
        route = re.sub(r'\{([a-zA-Z_]\w*)\}', lambda m: str(self._guess_param_value(m.group(1))), route)
        # Remove Nuxt catch-all: /path/(.*) or /path/*
        route = re.sub(r'/\(\.\*\)$', '', route)
        route = re.sub(r'/\*$', '', route)
        return route

    def _detect_method(self, endpoint, context):
        ctx = context.lower()
        for pat, meth in [
            (r'\.post\s*\(', 'POST'), (r'\.put\s*\(', 'PUT'), (r'\.delete\s*\(', 'DELETE'),
            (r'\.patch\s*\(', 'PATCH'), (r'method\s*[:=]\s*["\']post', 'POST'),
            (r'method\s*[:=]\s*["\']put', 'PUT'), (r'method\s*[:=]\s*["\']delete', 'DELETE'),
        ]:
            if re.search(pat, ctx):
                return meth
        ep = endpoint.lower()
        if any(w in ep for w in ('create', 'add', 'register', 'login', 'signup', 'upload', 'submit', 'save')):
            return 'POST'
        if any(w in ep for w in ('update', 'edit', 'modify')):
            return 'PUT'
        if any(w in ep for w in ('delete', 'remove')):
            return 'DELETE'
        return 'GET'

    def _guess_param_value(self, name):
        """Generate ONE sample value for a parameter"""
        n = name.lower()
        if n in ('id', 'uid', 'gid', 'pid'): return 1
        if n == 'page': return 1
        if n == 'type': return 'IsNew'
        if n == 'name': return 'test'
        if n in ('limit', 'size', 'pageSize', 'per_page'): return 20
        if n == 'sort': return 'new'
        if n in ('status', 'state'): return 'active'
        if n in ('lang', 'language', 'locale'): return 'en'
        if n in ('category', 'cat'): return 'all'
        if n == 'tab': return 1
        if n in ('keyword', 'search', 'q'): return 'test'
        if n == 'email': return 'test@test.com'
        if n in ('token', 'access_token'): return 'TOKEN'
        if n == 'origin': return 'web'
        if n == 'platform': return 'pc'
        if 'date' in n: return '2024-01-01'
        if 'time' in n: return '1704067200'
        if 'url' in n: return 'https://example.com'
        if 'num' in n or 'count' in n: return 10
        return 'test'

    # ── Phase 4: Visit SPA routes to trigger more API calls ──────────────────

    async def _phase4_visit_routes(self, page):
        """Visit discovered SPA routes to trigger their API calls"""
        print(f"\n  {C.BOLD}{C.Y}═══ Phase 4: Visit SPA Routes (trigger APIs) ═══{C.END}\n")

        # Navigate back to target first
        try:
            await page.goto(self.target_url, wait_until='domcontentloaded', timeout=15000)
            await page.wait_for_timeout(2000)
        except:
            pass

        # Prioritize interesting routes
        priority = ['all', 'game', 'slot', 'live', 'sport', 'vip', 'promotion', 'help',
                    'detail', 'user', 'account', 'wallet', 'deposit', 'withdraw',
                    'history', 'record', 'rank', 'agent', 'referral', 'roulette',
                    'lottery', 'wheel', 'bonus', 'rebate', 'invite', 'message']

        routes = sorted(self.raw_routes)
        pri_routes = [r for r in routes if any(kw in r.lower() for kw in priority)]
        other_routes = [r for r in routes if r not in pri_routes]
        ordered = pri_routes + other_routes

        visited = set()
        count = 0
        for route in ordered:
            if count >= self.max_pages:
                break
            # Clean route
            if route.startswith('http'):
                if not self._is_target_scope(route):
                    continue
                path = urlparse(route).path
            else:
                path = route.split('?')[0]

            if path in visited or path == '/':
                continue
            visited.add(path)

            full_url = self.origin + route if route.startswith('/') else route
            self._log(f"[{count+1:03d}] {route[:80]}", "dim")

            try:
                await page.goto(full_url, wait_until='domcontentloaded', timeout=12000)
                try:
                    await page.wait_for_load_state('networkidle', timeout=6000)
                except:
                    pass
                await page.wait_for_timeout(1200)

                # Light interaction on each page
                await page.evaluate('''async () => {
                    for (let i = 0; i < 5; i++) { window.scrollBy(0, 400); await new Promise(r => setTimeout(r, 200)); }
                }''')
                await page.wait_for_timeout(500)

                count += 1
            except:
                pass

        self._log(f"Visited {count} routes, total intercepted: {len(self.intercepted)}", "ok")

    # ── Phase 5: Build final URL list ────────────────────────────────────────

    def _phase5_build_urls(self):
        """Build final deduped URL list — ONE url per route+param structure"""
        print(f"\n  {C.BOLD}{C.Y}═══ Phase 5: Build Complete URLs (dedup) ═══{C.END}\n")

        seen_sigs = set()

        def _add(method, url, extra=None):
            parsed = urlparse(url)
            pkeys = sorted(parse_qs(parsed.query, keep_blank_values=True).keys())
            sig = self._sig(method, parsed.path, pkeys)
            if sig in seen_sigs:
                return
            seen_sigs.add(sig)

            entry = {
                'url': url, 'method': method, 'path': parsed.path,
                'query_params': {k: v[0] if len(v) == 1 else v
                                for k, v in parse_qs(parsed.query, keep_blank_values=True).items()},
                **(extra or {}),
            }
            if method == 'GET':
                self.get_endpoints[url] = entry
            elif method == 'POST':
                self.post_endpoints[url] = entry
            else:
                self.other_endpoints[url] = entry

        # 1. Network intercepted requests
        for req in self.intercepted:
            url = req['url']
            method = req['method']
            extra = {}
            if req.get('post_data') and not str(req.get('post_data','')).startswith('<binary'):
                extra['post_data'] = req['post_data']
            _add(method, url, extra)

        # 2. Route + param pairs from JS analysis
        for pair in self.route_param_pairs:
            route = pair['route']
            params = pair.get('params', {})
            method = pair['method']
            body_params = pair.get('body_params', [])

            if route.startswith('http'):
                base = route.split('?')[0]
            else:
                base = self.origin + route.split('?')[0]

            if params:
                qs = urlencode(params)
                url = f"{base}?{qs}"
            else:
                url = base

            extra = {}
            if body_params:
                extra['body_params'] = body_params
                extra['content_type'] = 'application/json'

            _add(method, url, extra)

        # 3. Raw routes without params (just the path)
        for route in self.raw_routes:
            if route.startswith('http'):
                url = route
            else:
                url = self.origin + route
            _add('GET', url)

        # 4. Raw API endpoints
        for ep in self.raw_api_endpoints:
            url = self.origin + ep if not ep.startswith('http') else ep
            _add('GET', url)  # These often get reclassified from intercepted data

        self._log(f"GET: {len(self.get_endpoints)}, POST: {len(self.post_endpoints)}, "
                  f"OTHER: {len(self.other_endpoints)}", "ok")

    # ── cURL + Save ──────────────────────────────────────────────────────────

    def _make_curl(self, entry, verbose=False):
        url = entry['url']
        method = entry['method']
        v = '-v' if verbose else '-s -o /dev/null -w "%{http_code}"'
        cmd = f'curl {v} -X {method} "{url}"'

        if method in ('POST', 'PUT', 'PATCH'):
            ct = entry.get('content_type', 'application/json')
            cmd += f' \\\n  -H "Content-Type: {ct}"'
            pd = entry.get('post_data')
            bp = entry.get('body_params', [])
            if pd:
                safe = pd.replace("'", "'\\''")
                cmd += f" \\\n  -d '{safe}'"
            elif bp:
                body = {p: self._guess_param_value(p) for p in bp}
                cmd += f" \\\n  -d '{json.dumps(body)}'"
            else:
                cmd += " \\\n  -d '{}'"
        return cmd

    def _save(self):
        od = self.output_dir

        # GET
        with open(os.path.join(od, "GET_endpoints.txt"), 'w') as f:
            f.write(f"# GET Endpoints — {len(self.get_endpoints)}\n")
            f.write(f"# Target: {self.target_url}\n")
            f.write(f"# {datetime.now().isoformat()}\n#\n\n")
            for url in sorted(self.get_endpoints.keys()):
                f.write(f"{url}\n")

        # POST
        with open(os.path.join(od, "POST_endpoints.txt"), 'w') as f:
            f.write(f"# POST Endpoints — {len(self.post_endpoints)}\n")
            f.write(f"# Target: {self.target_url}\n#\n\n")
            for url, e in sorted(self.post_endpoints.items()):
                f.write(f"{url}\n")
                if e.get('body_params'):
                    f.write(f"  Body: {', '.join(e['body_params'])}\n")
                if e.get('post_data') and not str(e.get('post_data','')).startswith('<binary'):
                    f.write(f"  Data: {str(e['post_data'])[:300]}\n")
                f.write("\n")

        # OTHER
        if self.other_endpoints:
            with open(os.path.join(od, "OTHER_endpoints.txt"), 'w') as f:
                f.write(f"# PUT/DELETE/PATCH — {len(self.other_endpoints)}\n\n")
                for url, e in sorted(self.other_endpoints.items()):
                    f.write(f"[{e['method']}] {url}\n")

        # ALL
        with open(os.path.join(od, "ALL_endpoints.txt"), 'w') as f:
            f.write(f"# All Endpoints | GET: {len(self.get_endpoints)} POST: {len(self.post_endpoints)} OTHER: {len(self.other_endpoints)}\n\n")
            for label, eps in [("GET", self.get_endpoints), ("POST", self.post_endpoints), ("OTHER", self.other_endpoints)]:
                if eps:
                    f.write(f"# ── {label} ({len(eps)}) ──\n")
                    for url, e in sorted(eps.items()):
                        prefix = f"[{e['method']}] " if label == "OTHER" else ""
                        f.write(f"{prefix}{url}\n")
                    f.write("\n")

        # SPA routes
        with open(os.path.join(od, "SPA_routes.txt"), 'w') as f:
            f.write(f"# SPA Routes — {len(self.raw_routes)}\n\n")
            for r in sorted(self.raw_routes):
                f.write(f"{self.origin}{r}\n")

        # curl GET
        p = os.path.join(od, "curl_GET.sh")
        with open(p, 'w') as f:
            f.write("#!/bin/bash\n# GET verification\n\n")
            for url, e in sorted(self.get_endpoints.items()):
                f.write(f"echo \"[GET] {e.get('path', url[:80])}\"\n{self._make_curl(e)}\necho \"\"\n\n")
        os.chmod(p, 0o755)

        # curl POST
        p = os.path.join(od, "curl_POST.sh")
        with open(p, 'w') as f:
            f.write("#!/bin/bash\n# POST verification\n\n")
            for url, e in sorted(self.post_endpoints.items()):
                f.write(f"echo \"[POST] {e.get('path', url[:80])}\"\n{self._make_curl(e)}\necho \"\"\n\n")
        os.chmod(p, 0o755)

        # curl ALL verbose
        p = os.path.join(od, "curl_ALL_verbose.sh")
        with open(p, 'w') as f:
            f.write("#!/bin/bash\n# All — verbose\n\n")
            all_e = list(self.get_endpoints.items()) + list(self.post_endpoints.items()) + list(self.other_endpoints.items())
            for url, e in sorted(all_e, key=lambda x: x[0]):
                f.write(f"# [{e['method']}] {e.get('path','')}\n{self._make_curl(e, verbose=True)}\n\n")
        os.chmod(p, 0o755)

        # API calls
        with open(os.path.join(od, "API_calls.txt"), 'w') as f:
            seen = OrderedDict()
            for key, count in self.api_log_seen.items():
                if key not in seen:
                    seen[key] = count
            f.write(f"# API Calls (unique) — {len(seen)}\n\n")
            for key, count in seen.items():
                f.write(f"{key} (×{count})\n")

        # Secrets
        if self.secrets:
            unique = []
            seen_s = set()
            for s in self.secrets:
                key = (s['type'], s['value'])
                if key not in seen_s:
                    seen_s.add(key)
                    unique.append(s)
            with open(os.path.join(od, "SECRETS.txt"), 'w') as f:
                f.write(f"# Secrets: {len(unique)}\n\n")
                for s in unique:
                    f.write(f"[{s['type']}] {s['value']}\n  {s['file']}\n  {s['context'][:200]}\n\n")
            with open(os.path.join(od, "SECRETS.json"), 'w') as f:
                json.dump(unique, f, indent=2)

        # JS files
        with open(os.path.join(od, "JS_files.txt"), 'w') as f:
            f.write(f"# JS: {len(self.js_urls)} ({len(self.js_content)} downloaded)\n\n")
            for u in sorted(self.js_urls):
                dl = "✓" if u in self.js_content else "✗"
                f.write(f"[{dl}] {u}\n")

        # Postman
        postman = {
            "info": {"name": f"Hunt-{self.netloc}", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
            "item": []
        }
        for label, eps in [("GET", self.get_endpoints), ("POST", self.post_endpoints)]:
            folder = {"name": label, "item": []}
            for url, e in sorted(eps.items()):
                item = {"name": e.get('path', url[:60]), "request": {"method": label, "url": url}}
                if label == 'POST':
                    item['request']['header'] = [{"key": "Content-Type", "value": e.get('content_type', 'application/json')}]
                    bp = e.get('body_params', [])
                    pd = e.get('post_data')
                    if pd and not str(pd).startswith('<binary'):
                        item['request']['body'] = {"mode": "raw", "raw": pd}
                    elif bp:
                        item['request']['body'] = {"mode": "raw", "raw": json.dumps({p: self._guess_param_value(p) for p in bp})}
                folder['item'].append(item)
            postman['item'].append(folder)
        with open(os.path.join(od, "postman_collection.json"), 'w') as f:
            json.dump(postman, f, indent=2)

        # Summary
        n_sec = len(set((s['type'], s['value']) for s in self.secrets))
        with open(os.path.join(od, "SUMMARY.txt"), 'w') as f:
            f.write(f"{'='*60}\n EndpointHunter v4.0\n{'='*60}\n")
            f.write(f" Target:     {self.target_url}\n")
            f.write(f" Date:       {datetime.now().isoformat()}\n")
            f.write(f" GET:        {len(self.get_endpoints)}\n")
            f.write(f" POST:       {len(self.post_endpoints)}\n")
            f.write(f" OTHER:      {len(self.other_endpoints)}\n")
            f.write(f" SPA routes: {len(self.raw_routes)}\n")
            f.write(f" JS files:   {len(self.js_urls)} ({len(self.js_content)} dl)\n")
            f.write(f" Secrets:    {n_sec}\n")
            f.write(f"{'='*60}\n")

    # ── Main ─────────────────────────────────────────────────────────────────

    async def run(self):
        start = datetime.now()
        banner()

        print(f"  {C.BOLD}Target:{C.END}    {self.target_url}")
        print(f"  {C.BOLD}Depth:{C.END}     {self.max_depth}")
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
            page.on('request', self._on_request)
            page.on('response', self._on_response)

            await self._phase1_load_and_intercept(page)
            await self._phase2_download_all_js(page)
            self._phase3_analyze_js()
            await self._phase4_visit_routes(page)
            self._phase5_build_urls()

            await browser.close()

        self._save()

        elapsed = datetime.now() - start
        n_sec = len(set((s['type'], s['value']) for s in self.secrets))

        print(f"""
  {C.BOLD}{C.G}{'═'*60}
  SCAN COMPLETE
  {'═'*60}{C.END}
  {C.W}Output:       {C.CY}{self.output_dir}/{C.END}
  {C.W}GET:          {C.G}{len(self.get_endpoints)}{C.END}
  {C.W}POST:         {C.R}{len(self.post_endpoints)}{C.END}
  {C.W}OTHER:        {C.Y}{len(self.other_endpoints)}{C.END}
  {C.W}SPA Routes:   {C.G}{len(self.raw_routes)}{C.END}
  {C.W}JS Files:     {C.G}{len(self.js_content)}/{len(self.js_urls)}{C.END}
  {C.W}Secrets:      {C.R}{n_sec}{C.END}
  {C.W}Time:         {C.CY}{elapsed}{C.END}
  {C.BOLD}{C.G}{'═'*60}{C.END}

  {C.BOLD}Files:{C.END}
  {C.DIM}├── GET_endpoints.txt       — One URL per line
  ├── POST_endpoints.txt      — POST + body params
  ├── ALL_endpoints.txt       — Combined
  ├── SPA_routes.txt          — Client routes from JS
  ├── API_calls.txt           — Observed API calls
  ├── curl_GET.sh / curl_POST.sh / curl_ALL_verbose.sh
  ├── postman_collection.json
  ├── SECRETS.txt / .json
  ├── JS_files.txt
  └── js_files/               — Downloaded JS{C.END}
""")


def main():
    parser = argparse.ArgumentParser(
        description='EndpointHunter v4.0 — Chunk-First SPA Endpoint Discovery',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 endpoint_hunter_v4.py https://mgc88.cc/
  python3 endpoint_hunter_v4.py https://target.com -d 15 -v
  python3 endpoint_hunter_v4.py https://target.com --auth "token=abc"

Key changes in v4:
  ✓ Downloads ALL JS chunks (including from CDN domains like cdn360-pc-h5.w0zuv.live)
  ✓ Pairs routes with their query params from JS context
  ✓ Builds complete URLs: /all?type=IsNew&page=1, /detail/helpCenter?id=1
  ✓ ONE URL per route+param structure (strict dedup)
  ✓ Visits discovered SPA routes to trigger API calls
  ✓ No duplicate log spam
        """
    )

    parser.add_argument('url', help='Target URL')
    parser.add_argument('-d', '--depth', type=int, default=10, help='Max depth (default: 10)')
    parser.add_argument('--auth', help='Auth params (e.g., "uid=123&key=abc")')
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('--max-pages', type=int, default=300, help='Max SPA routes to visit (default: 300)')
    parser.add_argument('--timeout', type=int, default=60, help='Timeout secs (default: 60)')
    parser.add_argument('--show-browser', action='store_true')

    args = parser.parse_args()
    scanner = EndpointHunter(
        target_url=args.url, max_depth=args.depth, auth_params=args.auth,
        verbose=args.verbose, headless=not args.show_browser,
        timeout=args.timeout, max_pages=args.max_pages,
    )
    asyncio.run(scanner.run())


if __name__ == "__main__":
    main()
