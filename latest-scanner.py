#!/usr/bin/env python3
"""
EndpointHunter v5.0 — Clean SPA Endpoint Discovery
Fixes: No component names as routes, no Swiper params, strict filtering
Strategy: Network intercept (ground truth) + filtered JS analysis + SPA route visiting
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
 ║  {C.BOLD}EndpointHunter v5.0{C.END}{C.CY} — Clean SPA Endpoint Discovery          ║
 ║  No false routes · No noise params · Strict filtering            ║
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

        self.asset_domains = set()
        self.asset_domains.add(self.netloc)

        # JS
        self.js_urls = set()
        self.js_content = {}
        self.analyzed_js = set()

        # Network intercept (ground truth)
        self.intercepted = []
        self.api_log_seen = {}

        # Discovered data
        self.valid_routes = set()          # confirmed real routes
        self.api_endpoints = []            # [{path, method, params, body_params, source}]
        self.route_with_params = []        # [{route, params}]

        # Final
        self.get_endpoints = OrderedDict()
        self.post_endpoints = OrderedDict()
        self.other_endpoints = OrderedDict()

        self.secrets = []
        self.output_dir = self._create_output_dir()

        # ── Route validation: what makes a REAL route vs a component name ──
        # PascalCase = component name (CommonCashierPop, DefaultMessageCard)
        # Real routes: /all, /detail/helpCenter, /vip, /game/slot
        self._component_pattern = re.compile(r'^/[A-Z][a-zA-Z]+(?:[A-Z][a-zA-Z]+){1,}$')

        # Param names that are clearly NOT URL query params (library configs)
        self._junk_params = {
            # Swiper.js
            'slidesPerView', 'spaceBetween', 'grabCursor', 'centeredSlides', 'autoplay',
            'pagination', 'navigation', 'scrollbar', 'freeMode', 'freeModeSticky',
            'watchSlidesProgress', 'watchSlidesVisibility', 'loop', 'preloadImages',
            'observer', 'observeParents', 'breakpoints', 'effect', 'coverflowEffect',
            'cubeEffect', 'flipEffect', 'fadeEffect', 'creativeEffect', 'cardsEffect',
            'virtualTranslate', 'slideClass', 'wrapperClass', 'containerClass',
            'slideActiveClass', 'slideDuplicateClass', 'loadedClass', 'loadingClass',
            'preloaderClass', 'lazyPreloaderClass', 'hiddenClass', 'lockClass',
            'disabledClass', 'dragClass', 'notificationClass', 'thumbsContainerClass',
            'zoomedSlideClass', 'containerModifierClass', 'slideThumbActiveClass',
            'slidesPerColumn', 'slidesPerGroup', 'slidesPerGroupSkip', 'slidesOffsetBefore',
            'allowTouchMove', 'allowSlideNext', 'allowSlidePrev', 'simulateTouch',
            'threshold', 'touchEventsTarget', 'touchReleaseOnEdges', 'preventClicks',
            'preventClicksPropagation', 'passiveListeners', 'mousewheel', 'keyboard',
            'resizeObserver', 'runCallbacksOnInit', 'watchOverflow', 'cssMode',
            'autoHeight', 'nested', 'rewind', 'speed', 'initialSlide', 'direction',
            'uniqueNavElements', 'parallax', 'a11y', 'lazy', 'virtual', 'thumbs',
            'controller', 'hashNavigation', 'history', 'grid', 'zoom', 'dynamicBullets',
            'dynamicMainBullets', 'formatFractionCurrent', 'renderFraction', 'renderBullet',
            'renderProgressbar', 'renderCustom', 'renderExternal', 'renderSlide',
            'bulletElement', 'firstSlideMessage', 'lastSlideMessage', 'nextSlideMessage',
            'prevSlideMessage', 'paginationType', 'clickable', 'hideOnClick',
            'progressbarOpposite', 'crossFade', 'shadow', 'shadowScale', 'shadowOffset',
            'slideShadows', 'limitRotation', 'rotate', 'stretch', 'depth', 'modifier',
            'minRatio', 'maxRatio', 'loadPrevNext', 'loadPrevNextAmount', 'swiper',
            'focusableElements', 'eventsTarged', 'eventsPrefix', 'swiperElementNodeName',
            'invert', 'forceToAxis', 'releaseOnEdges', 'sensitivity', 'draggable',
            'snapOnRelease', 'dragSize', 'onlyInViewport', 'waitForTransition',
            'stopOnLastSlide', 'reverseDirection', 'disableOnInteraction',
            'autoplayDisableOnInteraction', 'loadOnTransitionStart',
            'breakpointsInverse', 'updateOnImagesReady', 'addSlidesBefore',
            'addSlidesAfter', 'inverse', 'dryRun', 'prevEl', 'nextEl', 'enabled',
            'containerModif', 'containerModifierClas',
            # Generic JS / Vue internals
            'render', 'init', 'on', 'push', 'join', 'hide', 'toggle', 'cache',
            'sync', 'el', 'key', 'data', 'error', 'body', 'text', 'title', 'header',
            'height', 'width', 'delay', 'mode', 'scope', 'state', 'event', 'slides',
            'control', 'embed', 'nav', 'tabs', 'onload', 'onAny', '_emitClasses',
            'replaceState', 'createElements', '_construct', 'hasOwnProperty',
            'currentRoute', 'fullpath', 'path', 'name',  # router internals
            # Short var names from minification
            'e', 'i', 'u', 'v', 'p', 's', 'C', 'K', '_',
            'at', 'bt', 'ct', 'dt', 'et', 'ft', 'gt', 'ht', 'it', 'kt', 'lt',
            'mt', 'nt', 'st', 'ut', 'vt', 'wt', 'xt', 'yt',
            'Be', 'Ce', 'De', 'Fe', 'Ge', 'He', 'Ie', 'Je', 'Ke', 'Me', 'Ne',
            'Oe', 'Qe', 'Re', 'Ue', 'Ve', 'We', 'Xe', 'Ye', 'Ze',
            'Ct', 'Dt', 'Ft', 'Gt', 'Ht', 'Mt', 'Nt', 'Ut', 'Wt',
            'ce', 'je', 'lr', 'qe', 'qu', 'ze',
            # Other non-URL stuff
            'version', 'brand', 'runtimeLocale', 'locale', 'language',
            'isShow', 'isPcHorizontal', 'isCS', 'isCs', 'isMyChat',
            'showReset', 'watchState', 'by', 'icons',
            'openBindPhone', 'openBindEmail', 'openBindFunds', 'openFundsPassword',
            'setOrChange', 'currentSize', 'tipData', 'continuation', 'continuationToken',
            'ginationBulletMessage',
        }

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

    def _is_target(self, url):
        try: return urlparse(url).netloc == self.netloc
        except: return False

    def _create_output_dir(self):
        domain = self.netloc.replace("www.", "")
        safe = re.sub(r'[^\w\-.]', '_', domain)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        d = f"hunt_{safe}_{ts}"
        Path(d).mkdir(parents=True, exist_ok=True)
        Path(os.path.join(d, "js_files")).mkdir(exist_ok=True)
        return d

    def _sig(self, method, path, param_keys):
        parts = path.split("/")
        norm = []
        for p in parts:
            if re.match(r'^\d+$', p): norm.append("{N}")
            elif re.match(r'^[a-f0-9]{8,}$', p, re.I): norm.append("{H}")
            else: norm.append(p)
        return f"{method}|{'/' .join(norm)}|{','.join(sorted(param_keys))}"

    def _log(self, msg, level="info"):
        colors = {"info": C.CY, "ok": C.G, "warn": C.Y, "err": C.R, "dim": C.DIM}
        print(f"  {colors.get(level, C.W)}{msg}{C.END}")

    def _vlog(self, msg):
        if self.verbose:
            print(f"    {C.DIM}{msg}{C.END}")

    # ══════════════════════════════════════════════════════════════════════════
    # ROUTE VALIDATION — the core fix
    # ══════════════════════════════════════════════════════════════════════════

    def _is_valid_route(self, path):
        """Strict validation: is this a real URL route or a component/class name?"""
        if not path or len(path) < 2 or not path.startswith('/'):
            return False

        # Skip static files
        if any(path.lower().endswith(ext) for ext in
               ('.js', '.css', '.png', '.jpg', '.gif', '.svg', '.ico', '.json',
                '.map', '.woff', '.woff2', '.ttf', '.webp', '.xml', '.txt')):
            return False

        # Skip internal framework paths
        if any(seg in path for seg in ('_nuxt', '__nuxt', 'node_modules', 'assets/', 'static/')):
            return False

        # ── THE KEY FILTER: reject PascalCase component names ──
        # Component names: /CommonCashierPopDepositFiatCurrencyTab
        # Real routes: /all, /detail/helpCenter, /vip, /game/slot, /roulette
        segments = path.strip('/').split('/')
        for seg in segments:
            if not seg:
                continue
            # PascalCase with 2+ capital words = component name
            # e.g. "CommonCashierPop", "DefaultMessageCard", "BonusWalletPage"
            capitals = re.findall(r'[A-Z]', seg)
            if len(capitals) >= 2 and seg[0].isupper():
                # Check if it looks like a real route (some routes can have camelCase)
                # Real: "helpCenter" (1 capital mid-word), "IsNew" (short param value)
                # Fake: "CommonCashierPopDepositFiatCurrencyTab" (many capitals, long)
                if len(capitals) >= 3 and len(seg) > 15:
                    return False
                # Also reject if it starts with common component prefixes
                component_prefixes = (
                    'Common', 'Default', 'Base', 'App', 'Layout', 'Modal', 'Popup',
                    'Dialog', 'Drawer', 'Panel', 'Card', 'Block', 'Widget', 'Wrapper',
                    'Container', 'Provider', 'Controller', 'Manager', 'Handler',
                    'Renderer', 'Factory', 'Service', 'Store', 'Mixin', 'Plugin',
                    'Directive', 'Filter', 'Guard', 'Interceptor', 'Resolver',
                    'Validator', 'Formatter', 'Adapter', 'Bridge', 'Proxy',
                )
                if any(seg.startswith(prefix) for prefix in component_prefixes):
                    return False

            # Reject single uppercase words that are clearly class names
            # e.g. "ActivateWallet", "BonusOverview", "CryptoGame"
            if seg[0].isupper() and len(capitals) >= 2 and len(seg) > 10:
                return False

        # Length sanity
        if len(path) > 100:
            return False

        return True

    def _is_valid_param(self, name):
        """Is this a real URL query parameter or library config noise?"""
        if not name or len(name) < 2 or len(name) > 30:
            return False
        if name in self._junk_params:
            return False
        # Reject minified var names (1-2 chars, or XY pattern)
        if len(name) <= 2:
            return False
        if re.match(r'^[A-Z][a-z]$', name):  # Xe, Be, etc.
            return False
        # Reject camelCase with 3+ capitals (likely config object)
        capitals = len(re.findall(r'[A-Z]', name))
        if capitals >= 3 and len(name) > 12:
            return False
        return True

    def _guess_val(self, name):
        n = name.lower()
        if n in ('id', 'uid', 'gid', 'pid'): return '1'
        if n == 'page': return '1'
        if n == 'type': return 'IsNew'
        if n == 'name': return 'test'
        if n in ('limit', 'size', 'pagesize', 'per_page'): return '20'
        if n == 'sort': return 'new'
        if n in ('status', 'state'): return 'active'
        if n in ('lang',): return 'en'
        if n in ('category', 'cat'): return 'all'
        if n == 'tab': return '1'
        if n in ('keyword', 'search', 'q'): return 'test'
        if n == 'gametype': return 'slot'
        if n == 'origin': return 'web'
        if n == 'platform': return 'pc'
        if n == 'symbol': return 'USDT'
        if n == 'currency': return 'USD'
        if n == 'channel': return '1'
        if 'id' in n: return '1'
        if 'page' in n: return '1'
        if 'num' in n or 'count' in n: return '10'
        if 'date' in n: return '2024-01-01'
        if 'url' in n: return 'https://example.com'
        if 'token' in n: return 'TOKEN'
        return 'test'

    # ── Network Interception ─────────────────────────────────────────────────

    def _on_request(self, request):
        url = request.url
        if not url.startswith("http") or not self._is_target(url):
            return

        parsed = urlparse(url)
        skip_ext = ('.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff',
                    '.woff2', '.ttf', '.eot', '.mp4', '.webp', '.css', '.map')
        if any(parsed.path.lower().endswith(ext) for ext in skip_ext):
            return

        if parsed.path.endswith('.js'):
            self.js_urls.add(urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', '')))
            return

        post_data = None
        try:
            post_data = request.post_data
        except:
            try:
                raw = request.post_data_buffer
                post_data = f"<binary:{len(raw)}b>" if raw else None
            except:
                pass

        self.intercepted.append({
            'url': url, 'method': request.method.upper(),
            'post_data': post_data, 'path': parsed.path, 'query': parsed.query,
        })

    def _on_response(self, response):
        try:
            url = response.url
            if not self._is_target(url):
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

    # Also intercept JS from CDN domains
    def _on_request_js(self, request):
        """Separate handler just for discovering JS files on CDN"""
        url = request.url
        if not url.startswith("http"):
            return
        parsed = urlparse(url)
        if parsed.path.endswith('.js') and ('_nuxt' in url or 'chunk' in url or 'assets' in url):
            self.asset_domains.add(parsed.netloc)
            self.js_urls.add(urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', '')))

    # ── Phase 1: Load + Interact ─────────────────────────────────────────────

    async def _phase1(self, page):
        print(f"\n  {C.BOLD}{C.Y}═══ Phase 1: Load + Interact + Intercept ═══{C.END}\n")

        try:
            await page.goto(self.target_url, wait_until='domcontentloaded', timeout=self.timeout * 1000)
            try: await page.wait_for_load_state('networkidle', timeout=15000)
            except: pass
            await page.wait_for_timeout(3000)
        except Exception as e:
            self._log(f"Load error: {e}", "err")

        # Discover CDN from script tags
        try:
            srcs = await page.evaluate('''() => {
                return Array.from(document.querySelectorAll('script[src]')).map(s => s.src);
            }''')
            for src in srcs:
                p = urlparse(src)
                if p.path.endswith('.js'):
                    self.asset_domains.add(p.netloc)
                    self.js_urls.add(urlunparse((p.scheme, p.netloc, p.path, '', '', '')))
        except: pass

        self._log(f"CDN domains: {self.asset_domains}", "ok")

        # Interact
        self._log("Interacting (scroll + click)...")
        await self._interact(page)

        # Extract real links from DOM
        await self._extract_dom_routes(page)

        self._log(f"Intercepted: {len(self.intercepted)} requests", "ok")
        self._log(f"Valid routes from DOM: {len(self.valid_routes)}", "ok")
        self._log(f"JS files found: {len(self.js_urls)}", "ok")

    async def _interact(self, page):
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

            selectors = [
                'nav a', '.nav a', '.nav-item', '.nav-link', 'header a',
                '[role="tab"]', '.tab', '.tab-item', '[class*="tab"]',
                '[class*="filter"]', '[class*="category"]', '[class*="menu"] a',
                'button[data-type]', '[data-category]',
                '.pagination a', 'a[href*="page="]', '[class*="next"]', '[class*="more"]',
                'footer a', '.card a', '[class*="game"] a',
            ]

            clicked = set()
            for sel in selectors:
                try:
                    els = await page.query_selector_all(sel)
                    for el in els[:12]:
                        try:
                            ident = await page.evaluate(
                                '(el) => (el.getAttribute("href")||"") + "|" + (el.textContent||"").trim().slice(0,20)', el)
                            if ident in clicked: continue
                            clicked.add(ident)
                            if not await el.is_visible(): continue

                            href = await page.evaluate(
                                '(el) => el.getAttribute("href") || el.getAttribute("to") || ""', el)
                            if href and href.startswith('/') and self._is_valid_route(href):
                                self.valid_routes.add(href.split('?')[0])

                            await el.click(timeout=2500)
                            await page.wait_for_timeout(600)

                            cur = page.url
                            if self._is_target(cur):
                                p = urlparse(cur)
                                route = p.path
                                if self._is_valid_route(route):
                                    self.valid_routes.add(route)
                                    if p.query:
                                        self.route_with_params.append({
                                            'route': route,
                                            'params': dict(parse_qs(p.query, keep_blank_values=True)),
                                        })
                        except: pass
                except: pass
        except: pass

    async def _extract_dom_routes(self, page):
        try:
            results = await page.evaluate('''() => {
                const links = [];
                document.querySelectorAll('a[href], [to]').forEach(el => {
                    const v = el.getAttribute('href') || el.getAttribute('to') || '';
                    if (v.startsWith('/')) links.push(v);
                    if (v.startsWith('http')) links.push(v);
                });
                document.querySelectorAll('[data-href],[data-url],[data-to]').forEach(el => {
                    for (const a of ['data-href','data-url','data-to']) {
                        const v = el.getAttribute(a);
                        if (v) links.push(v);
                    }
                });
                return links;
            }''')
            for link in results:
                if link.startswith('/'):
                    path = link.split('?')[0]
                    if self._is_valid_route(path):
                        self.valid_routes.add(path)
                elif link.startswith('http') and self._is_target(link):
                    p = urlparse(link)
                    if self._is_valid_route(p.path):
                        self.valid_routes.add(p.path)
        except: pass

    # ── Phase 2: Download ALL JS ─────────────────────────────────────────────

    async def _phase2(self, page):
        print(f"\n  {C.BOLD}{C.Y}═══ Phase 2: Download ALL JS Chunks ═══{C.END}\n")

        await self._discover_nuxt_chunks(page)
        self._log(f"JS files to download: {len(self.js_urls)}", "info")

        for pass_num in range(1, 6):
            to_dl = [u for u in self.js_urls if u not in self.js_content]
            if not to_dl: break

            self._log(f"Pass {pass_num}: downloading {len(to_dl)} files...", "warn")
            for i, url in enumerate(sorted(to_dl), 1):
                try:
                    resp = await page.goto(url, wait_until='load', timeout=12000)
                    if resp and resp.status == 200:
                        content = await resp.text()
                        if content and len(content) > 10:
                            self.js_content[url] = content
                            fname = re.sub(r'[^\w\-.]', '_', url.split('/')[-1])[:120]
                            with open(os.path.join(self.output_dir, "js_files", fname), 'w',
                                      encoding='utf-8', errors='ignore') as f:
                                f.write(content)
                            self._find_js_refs(url, content)
                            if self.verbose and i % 20 == 0:
                                print(f"    {C.DIM}[{i}/{len(to_dl)}]{C.END}")
                except: pass

            remaining = len([u for u in self.js_urls if u not in self.js_content])
            self._log(f"Pass {pass_num}: cached {len(self.js_content)}, remaining {remaining}", "ok")
            if remaining == 0: break

        self._log(f"Total: {len(self.js_content)}/{len(self.js_urls)} JS downloaded", "ok")

    async def _discover_nuxt_chunks(self, page):
        cdn_origins = set()
        for d in self.asset_domains:
            cdn_origins.add(f"https://{d}")

        # From intercepted requests
        for req in self.intercepted:
            if '_nuxt' in req['url'] and req['url'].endswith('.json'):
                try:
                    resp = await page.goto(req['url'], wait_until='load', timeout=8000)
                    if resp and resp.status == 200:
                        self._extract_chunk_urls(await resp.text(), req['url'])
                except: pass

        for origin in cdn_origins:
            for path in ['/_nuxt/builds/latest.json']:
                try:
                    resp = await page.goto(origin + path, wait_until='load', timeout=8000)
                    if resp and resp.status == 200:
                        self._extract_chunk_urls(await resp.text(), origin + path)
                except: pass

        # From HTML
        try:
            await page.goto(self.target_url, wait_until='domcontentloaded', timeout=15000)
            html = await page.content()
            for m in re.finditer(r'(?:src|href)\s*=\s*["\']((?:https?://)?[^"\']*\.js)["\']', html):
                ref = m.group(1)
                if ref.startswith('//'): ref = 'https:' + ref
                elif ref.startswith('/'):
                    for cdn in cdn_origins:
                        self.js_urls.add(cdn + ref.split('?')[0])
                elif ref.startswith('http'):
                    self.js_urls.add(ref.split('?')[0])
        except: pass

    def _extract_chunk_urls(self, text, base_url):
        base_origin = f"{urlparse(base_url).scheme}://{urlparse(base_url).netloc}"
        for m in re.finditer(r'["\']([^"\']*\.(?:js|mjs))["\']', text):
            ref = m.group(1)
            if ref.startswith('http'):
                self.js_urls.add(ref.split('?')[0])
            elif ref.startswith('/'):
                self.js_urls.add(base_origin + ref)
            else:
                base_dir = '/'.join(base_url.split('/')[:-1])
                self.js_urls.add(f"{base_dir}/{ref.lstrip('./')}".split('?')[0])

    def _find_js_refs(self, base_url, content):
        base_origin = f"{urlparse(base_url).scheme}://{urlparse(base_url).netloc}"
        for pat in [
            r'["\']([^"\']*?[a-zA-Z0-9_\-]+\.[a-f0-9]{6,}\.js)["\']',
            r'["\']([^"\']*?_nuxt/[^\s"\']*\.js)["\']',
            r'["\'](/[a-zA-Z0-9_\-/.]+\.js)["\']',
            r'["\']([a-zA-Z0-9_\-]+\.[a-f0-9]{6,8}\.js)["\']',
        ]:
            for m in re.finditer(pat, content):
                ref = m.group(1)
                if ref.startswith('http'):
                    if urlparse(ref).netloc in self.asset_domains:
                        self.js_urls.add(ref.split('?')[0])
                elif ref.startswith('/'):
                    self.js_urls.add(base_origin + ref)
                else:
                    base_dir = '/'.join(base_url.split('/')[:-1])
                    self.js_urls.add(f"{base_dir}/{ref.lstrip('./')}".split('?')[0])

    # ── Phase 3: Analyze JS — with STRICT filtering ──────────────────────────

    def _phase3(self):
        print(f"\n  {C.BOLD}{C.Y}═══ Phase 3: JS Analysis (strict filtering) ═══{C.END}\n")

        total_routes = 0
        total_apis = 0

        for url, content in self.js_content.items():
            if url in self.analyzed_js: continue
            self.analyzed_js.add(url)

            if HAS_BEAUTIFIER and len(content) < 2_000_000:
                try:
                    opts = jsbeautifier.default_options()
                    opts.indent_size = 2
                    content = jsbeautifier.beautify(content, opts)
                except: pass

            r, a = self._analyze_js(url, content)
            total_routes += r
            total_apis += a

        self._log(f"Valid routes from JS: {total_routes}", "ok")
        self._log(f"API endpoints from JS: {total_apis}", "ok")
        self._log(f"Total valid routes: {len(self.valid_routes)}", "ok")

    def _analyze_js(self, url, content):
        route_count = 0
        api_count = 0

        # ── 1. Vue Router path definitions ──
        # ONLY accept path: "/lowercase/kebab-case" patterns
        for m in re.finditer(r'path\s*:\s*["\'](/[a-z][a-zA-Z0-9_/\-:.*]*)["\']', content):
            route = m.group(1)
            if not self._is_valid_route(route.split('?')[0]):
                continue
            resolved = re.sub(r':(\w+)', lambda x: self._guess_val(x.group(1)), route)
            resolved = re.sub(r'/\(\.\*\)$', '', resolved)
            resolved = re.sub(r'/\*$', '', resolved)

            self.valid_routes.add(resolved.split('?')[0])

            # Find params in nearby context
            ctx_start = max(0, m.start() - 1500)
            ctx_end = min(len(content), m.end() + 1500)
            context = content[ctx_start:ctx_end]
            params = self._extract_clean_params(context)

            if params:
                self.route_with_params.append({'route': resolved.split('?')[0], 'params': params})
            route_count += 1

        # ── 2. Explicit URL strings with query params ──
        # "/all?type=IsNew&page=1" — these are gold, take them directly
        for m in re.finditer(r'["\'`](/[a-z][a-zA-Z0-9_/\-]*\?[a-zA-Z0-9_=&%\+\-\.]+)["\'`]', content):
            full = m.group(1)
            path = full.split('?')[0]
            if not self._is_valid_route(path):
                continue

            params = {}
            query = full.split('?')[1] if '?' in full else ''
            for kv in query.split('&'):
                if '=' in kv:
                    k, v = kv.split('=', 1)
                    if self._is_valid_param(k):
                        params[k] = v if v else self._guess_val(k)

            self.valid_routes.add(path)
            if params:
                self.route_with_params.append({'route': path, 'params': params})
            route_count += 1

        # ── 3. Simple path strings (lowercase only) ──
        for m in re.finditer(r'["\'](/[a-z][a-z0-9]*(?:/[a-zA-Z0-9_\-]*)*)["\']', content):
            path = m.group(1)
            if self._is_valid_route(path) and len(path) > 1 and len(path) < 60:
                self.valid_routes.add(path)
                route_count += 1

        # ── 4. API endpoints ──
        api_pats = [
            (r'["\'`](/api/[a-zA-Z0-9_/\-{}:?=&\.\+%]+)["\'`]', None),
            (r'\.post\s*\(\s*["\'`](/[a-zA-Z0-9_/\-{}:?=&]+)["\'`]', 'POST'),
            (r'\.get\s*\(\s*["\'`](/[a-zA-Z0-9_/\-{}:?=&]+)["\'`]', 'GET'),
            (r'\.put\s*\(\s*["\'`](/[a-zA-Z0-9_/\-{}:?=&]+)["\'`]', 'PUT'),
            (r'\.delete\s*\(\s*["\'`](/[a-zA-Z0-9_/\-{}:?=&]+)["\'`]', 'DELETE'),
            (r'\.patch\s*\(\s*["\'`](/[a-zA-Z0-9_/\-{}:?=&]+)["\'`]', 'PATCH'),
        ]

        for pat, forced_method in api_pats:
            for m in re.finditer(pat, content):
                ep = m.group(1)
                ep = re.sub(r'\$\{[^}]+\}', '1', ep)
                if any(ep.endswith(ext) for ext in ('.js', '.css', '.png')): continue

                ctx_start = max(0, m.start() - 800)
                ctx_end = min(len(content), m.end() + 800)
                context = content[ctx_start:ctx_end]

                method = forced_method or self._detect_method(ep, context)
                body_params = self._extract_body_params(context) if method in ('POST', 'PUT', 'PATCH') else []
                clean_params = self._extract_clean_params(context)

                self.api_endpoints.append({
                    'path': ep, 'method': method, 'params': clean_params,
                    'body_params': body_params, 'source': url,
                })
                api_count += 1

        # ── 5. Secrets ──
        for sec_type, patterns in self.secret_patterns.items():
            for pat in patterns:
                for m in re.finditer(pat, content, re.I):
                    val = m.group(1) if m.groups() else m.group(0)
                    if val and len(val) >= 8:
                        skip = ('placeholder', 'example', 'test', 'xxx', 'null', 'undefined')
                        if not any(s in val.lower() for s in skip):
                            cs = max(0, m.start() - 60)
                            ce = min(len(content), m.end() + 60)
                            self.secrets.append({
                                'type': sec_type, 'value': val, 'file': url,
                                'context': content[cs:ce].replace('\n', ' ')[:250],
                            })

        return route_count, api_count

    def _extract_clean_params(self, context):
        """Extract ONLY real URL query params, not library config"""
        params = {}

        # From ?key=value patterns
        for m in re.finditer(r'[?&]([a-zA-Z_]\w{2,20})=([a-zA-Z0-9_\-\.%+]*)', context):
            k, v = m.group(1), m.group(2)
            if self._is_valid_param(k) and k not in params:
                params[k] = v if v else self._guess_val(k)

        # From query/params/searchParams objects (ONLY these specific contexts)
        for m in re.finditer(r'(?:route\.query|searchParams|useRoute\(\)\.query|\$route\.query)\s*\.?\s*(?:\[["\'`])?(\w{2,20})', context):
            k = m.group(1)
            if self._is_valid_param(k) and k not in params:
                params[k] = self._guess_val(k)

        # From URLSearchParams usage
        for m in re.finditer(r'(?:URLSearchParams|searchParams).*?(?:get|set|append|has)\s*\(\s*["\'`](\w{2,20})["\'`]', context):
            k = m.group(1)
            if self._is_valid_param(k) and k not in params:
                params[k] = self._guess_val(k)

        return params

    def _extract_body_params(self, context):
        params = []
        for pat in [r'(?:data|body|payload)\s*[:=]\s*\{([^}]{1,500})\}',
                    r'JSON\.stringify\s*\(\s*\{([^}]{1,500})\}']:
            for m in re.findall(pat, context, re.I):
                for km in re.finditer(r'([a-zA-Z_]\w{1,20})\s*:', m):
                    p = km.group(1)
                    if self._is_valid_param(p):
                        params.append(p)
        return list(set(params))

    def _detect_method(self, endpoint, context):
        ctx = context.lower()
        for pat, meth in [
            (r'\.post\s*\(', 'POST'), (r'\.put\s*\(', 'PUT'),
            (r'\.delete\s*\(', 'DELETE'), (r'\.patch\s*\(', 'PATCH'),
            (r'method\s*[:=]\s*["\']post', 'POST'), (r'method\s*[:=]\s*["\']put', 'PUT'),
            (r'method\s*[:=]\s*["\']delete', 'DELETE'),
        ]:
            if re.search(pat, ctx): return meth
        ep = endpoint.lower()
        if any(w in ep for w in ('create', 'add', 'register', 'login', 'signup', 'upload', 'submit', 'save')): return 'POST'
        if any(w in ep for w in ('update', 'edit', 'modify')): return 'PUT'
        if any(w in ep for w in ('delete', 'remove')): return 'DELETE'
        return 'GET'

    # ── Phase 4: Visit SPA routes ────────────────────────────────────────────

    async def _phase4(self, page):
        print(f"\n  {C.BOLD}{C.Y}═══ Phase 4: Visit SPA Routes ═══{C.END}\n")

        try:
            await page.goto(self.target_url, wait_until='domcontentloaded', timeout=15000)
            await page.wait_for_timeout(2000)
        except: pass

        priority = ['all', 'game', 'slot', 'live', 'sport', 'vip', 'promotion', 'help',
                    'detail', 'user', 'account', 'wallet', 'deposit', 'withdraw',
                    'history', 'record', 'rank', 'agent', 'roulette', 'lottery',
                    'wheel', 'bonus', 'rebate', 'invite', 'message', 'about']

        routes = sorted(self.valid_routes)
        pri = [r for r in routes if any(kw in r.lower() for kw in priority)]
        other = [r for r in routes if r not in pri]
        ordered = pri + other

        visited_paths = set()
        count = 0
        for route in ordered:
            if count >= self.max_pages: break
            path = route.split('?')[0]
            if path in visited_paths or path == '/': continue
            visited_paths.add(path)

            full_url = self.origin + route
            self._log(f"[{count+1:03d}] {route[:80]}", "dim")

            try:
                await page.goto(full_url, wait_until='domcontentloaded', timeout=12000)
                try: await page.wait_for_load_state('networkidle', timeout=6000)
                except: pass
                await page.wait_for_timeout(1200)

                # Light scroll
                await page.evaluate('''async () => {
                    for (let i = 0; i < 5; i++) { window.scrollBy(0, 400); await new Promise(r => setTimeout(r, 200)); }
                }''')
                await page.wait_for_timeout(500)
                count += 1
            except: pass

        self._log(f"Visited {count} routes", "ok")

    # ── Phase 5: Build final URLs ────────────────────────────────────────────

    def _phase5(self):
        print(f"\n  {C.BOLD}{C.Y}═══ Phase 5: Build Final URLs (strict dedup) ═══{C.END}\n")

        seen = set()

        def _add(method, url, extra=None):
            parsed = urlparse(url)
            pkeys = sorted(parse_qs(parsed.query, keep_blank_values=True).keys())
            sig = self._sig(method, parsed.path, pkeys)
            if sig in seen: return
            seen.add(sig)

            entry = {
                'url': url, 'method': method, 'path': parsed.path,
                'query_params': {k: v[0] if len(v) == 1 else v
                                for k, v in parse_qs(parsed.query, keep_blank_values=True).items()},
                **(extra or {}),
            }
            if method == 'GET': self.get_endpoints[url] = entry
            elif method == 'POST': self.post_endpoints[url] = entry
            else: self.other_endpoints[url] = entry

        # 1. Network intercepted (highest confidence)
        for req in self.intercepted:
            extra = {}
            if req.get('post_data') and not str(req.get('post_data', '')).startswith('<binary'):
                extra['post_data'] = req['post_data']
            _add(req['method'], req['url'], extra)

        # 2. API endpoints from JS
        for ep in self.api_endpoints:
            path = ep['path']
            if path.startswith('http'):
                base = path.split('?')[0]
            else:
                base = self.origin + path.split('?')[0]

            params = ep.get('params', {})
            if params:
                url = f"{base}?{urlencode(params)}"
            else:
                url = base

            extra = {}
            if ep.get('body_params'):
                extra['body_params'] = ep['body_params']
                extra['content_type'] = 'application/json'
            _add(ep['method'], url, extra)

        # 3. Routes with params
        for pair in self.route_with_params:
            route = pair['route']
            params = pair.get('params', {})
            base = self.origin + route

            # Flatten parse_qs style params
            clean_params = {}
            for k, v in params.items():
                if isinstance(v, list):
                    clean_params[k] = v[0]
                else:
                    clean_params[k] = v

            if clean_params:
                url = f"{base}?{urlencode(clean_params)}"
            else:
                url = base
            _add('GET', url)

        # 4. Bare routes (no params)
        for route in self.valid_routes:
            url = self.origin + route
            _add('GET', url)

        self._log(f"Final: GET={len(self.get_endpoints)} POST={len(self.post_endpoints)} OTHER={len(self.other_endpoints)}", "ok")

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
                cmd += f" \\\n  -d '{pd.replace(chr(39), chr(39)+chr(92)+chr(39)+chr(39))}'"
            elif bp:
                body = {p: self._guess_val(p) for p in bp}
                cmd += f" \\\n  -d '{json.dumps(body)}'"
            else:
                cmd += " \\\n  -d '{}'"
        return cmd

    def _save(self):
        od = self.output_dir

        # GET
        with open(os.path.join(od, "GET_endpoints.txt"), 'w') as f:
            f.write(f"# GET Endpoints — {len(self.get_endpoints)}\n# Target: {self.target_url}\n# {datetime.now().isoformat()}\n\n")
            for url in sorted(self.get_endpoints.keys()):
                f.write(f"{url}\n")

        # POST
        with open(os.path.join(od, "POST_endpoints.txt"), 'w') as f:
            f.write(f"# POST Endpoints — {len(self.post_endpoints)}\n# Target: {self.target_url}\n\n")
            for url, e in sorted(self.post_endpoints.items()):
                f.write(f"{url}\n")
                if e.get('body_params'): f.write(f"  Body: {', '.join(e['body_params'])}\n")
                if e.get('post_data') and not str(e.get('post_data','')).startswith('<binary'):
                    f.write(f"  Data: {str(e['post_data'])[:300]}\n")
                f.write("\n")

        # OTHER
        if self.other_endpoints:
            with open(os.path.join(od, "OTHER_endpoints.txt"), 'w') as f:
                for url, e in sorted(self.other_endpoints.items()):
                    f.write(f"[{e['method']}] {url}\n")

        # ALL
        with open(os.path.join(od, "ALL_endpoints.txt"), 'w') as f:
            f.write(f"# GET: {len(self.get_endpoints)} | POST: {len(self.post_endpoints)} | OTHER: {len(self.other_endpoints)}\n\n")
            for label, eps in [("GET", self.get_endpoints), ("POST", self.post_endpoints), ("OTHER", self.other_endpoints)]:
                if eps:
                    f.write(f"# ── {label} ({len(eps)}) ──\n")
                    for url in sorted(eps.keys()): f.write(f"{url}\n")
                    f.write("\n")

        # SPA routes
        with open(os.path.join(od, "SPA_routes.txt"), 'w') as f:
            f.write(f"# Valid SPA Routes — {len(self.valid_routes)}\n\n")
            for r in sorted(self.valid_routes): f.write(f"{self.origin}{r}\n")

        # cURL
        for fname, eps in [("curl_GET.sh", self.get_endpoints), ("curl_POST.sh", self.post_endpoints)]:
            p = os.path.join(od, fname)
            with open(p, 'w') as f:
                f.write(f"#!/bin/bash\n# {fname}\n\n")
                for url, e in sorted(eps.items()):
                    f.write(f"echo \"[{e['method']}] {e.get('path', url[:80])}\"\n{self._make_curl(e)}\necho \"\"\n\n")
            os.chmod(p, 0o755)

        p = os.path.join(od, "curl_ALL_verbose.sh")
        with open(p, 'w') as f:
            f.write("#!/bin/bash\n\n")
            all_e = list(self.get_endpoints.items()) + list(self.post_endpoints.items()) + list(self.other_endpoints.items())
            for url, e in sorted(all_e, key=lambda x: x[0]):
                f.write(f"# [{e['method']}] {e.get('path','')}\n{self._make_curl(e, verbose=True)}\n\n")
        os.chmod(p, 0o755)

        # API calls log
        with open(os.path.join(od, "API_calls.txt"), 'w') as f:
            f.write(f"# API Calls — {len(self.api_log_seen)} unique\n\n")
            for key, count in self.api_log_seen.items():
                f.write(f"{key} (×{count})\n")

        # Secrets
        if self.secrets:
            unique = []
            seen_s = set()
            for s in self.secrets:
                key = (s['type'], s['value'])
                if key not in seen_s: seen_s.add(key); unique.append(s)
            with open(os.path.join(od, "SECRETS.txt"), 'w') as f:
                for s in unique: f.write(f"[{s['type']}] {s['value']}\n  {s['file']}\n\n")
            with open(os.path.join(od, "SECRETS.json"), 'w') as f:
                json.dump(unique, f, indent=2)

        # JS files
        with open(os.path.join(od, "JS_files.txt"), 'w') as f:
            f.write(f"# JS: {len(self.js_content)}/{len(self.js_urls)}\n\n")
            for u in sorted(self.js_urls):
                f.write(f"[{'✓' if u in self.js_content else '✗'}] {u}\n")

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
                    item['request']['header'] = [{"key": "Content-Type", "value": "application/json"}]
                    bp = e.get('body_params', [])
                    pd = e.get('post_data')
                    if pd and not str(pd).startswith('<binary'):
                        item['request']['body'] = {"mode": "raw", "raw": pd}
                    elif bp:
                        item['request']['body'] = {"mode": "raw", "raw": json.dumps({p: self._guess_val(p) for p in bp})}
                folder['item'].append(item)
            postman['item'].append(folder)
        with open(os.path.join(od, "postman_collection.json"), 'w') as f:
            json.dump(postman, f, indent=2)

        # Summary
        n_sec = len(set((s['type'], s['value']) for s in self.secrets))
        with open(os.path.join(od, "SUMMARY.txt"), 'w') as f:
            f.write(f"{'='*60}\n EndpointHunter v5.0\n{'='*60}\n")
            f.write(f" Target:     {self.target_url}\n GET:        {len(self.get_endpoints)}\n")
            f.write(f" POST:       {len(self.post_endpoints)}\n OTHER:      {len(self.other_endpoints)}\n")
            f.write(f" Routes:     {len(self.valid_routes)}\n JS:         {len(self.js_content)}/{len(self.js_urls)}\n")
            f.write(f" Secrets:    {n_sec}\n{'='*60}\n")

    # ── Main ─────────────────────────────────────────────────────────────────

    async def run(self):
        start = datetime.now()
        banner()
        print(f"  {C.BOLD}Target:{C.END} {self.target_url}  |  {C.BOLD}Output:{C.END} {self.output_dir}/\n")

        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=self.headless,
                args=['--no-sandbox', '--disable-setuid-sandbox', '--disable-blink-features=AutomationControlled']
            )
            context = await browser.new_context(
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                viewport={'width': 1920, 'height': 1080},
            )
            page = await context.new_page()
            page.on('request', self._on_request)
            page.on('request', self._on_request_js)
            page.on('response', self._on_response)

            await self._phase1(page)
            await self._phase2(page)
            self._phase3()
            await self._phase4(page)
            self._phase5()

            await browser.close()

        self._save()
        elapsed = datetime.now() - start
        n_sec = len(set((s['type'], s['value']) for s in self.secrets))

        print(f"""
  {C.BOLD}{C.G}{'═'*60}
  SCAN COMPLETE
  {'═'*60}{C.END}
  {C.W}Output:    {C.CY}{self.output_dir}/{C.END}
  {C.W}GET:       {C.G}{len(self.get_endpoints)}{C.END}
  {C.W}POST:      {C.R}{len(self.post_endpoints)}{C.END}
  {C.W}OTHER:     {C.Y}{len(self.other_endpoints)}{C.END}
  {C.W}Routes:    {C.G}{len(self.valid_routes)}{C.END}
  {C.W}JS:        {C.G}{len(self.js_content)}/{len(self.js_urls)}{C.END}
  {C.W}Secrets:   {C.R}{n_sec}{C.END}
  {C.W}Time:      {C.CY}{elapsed}{C.END}
  {C.BOLD}{C.G}{'═'*60}{C.END}
""")


def main():
    parser = argparse.ArgumentParser(description='EndpointHunter v5.0 — Clean SPA Endpoint Discovery')
    parser.add_argument('url', help='Target URL')
    parser.add_argument('-d', '--depth', type=int, default=10)
    parser.add_argument('--auth', help='Auth params')
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('--max-pages', type=int, default=300)
    parser.add_argument('--timeout', type=int, default=60)
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
