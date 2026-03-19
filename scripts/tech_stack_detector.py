#!/usr/bin/env python3
"""Technology stack detector.

Fingerprints web technologies, frameworks, CDN/WAF, and third-party services.
Requires: httpx, beautifulsoup4.

Output: JSON to stdout.
"""

from __future__ import annotations

import argparse
import json
import logging
import re
from urllib.parse import urlparse

import httpx

logger = logging.getLogger("tech_stack_detector")

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

# Third-party service domains -> vendor name + category
THIRD_PARTY_DOMAINS = {
    # Analytics
    "cdn.segment.com": {"name": "Segment", "category": "Analytics"},
    "cdn.mxpnl.com": {"name": "Mixpanel", "category": "Analytics"},
    "heapanalytics.com": {"name": "Heap", "category": "Analytics"},
    "static.hotjar.com": {"name": "Hotjar", "category": "Analytics"},
    "plausible.io": {"name": "Plausible", "category": "Analytics"},
    "cdn.amplitude.com": {"name": "Amplitude", "category": "Analytics"},
    "js.posthog.com": {"name": "PostHog", "category": "Analytics"},
    "js.driftt.com": {"name": "Drift", "category": "Chat"},
    "cdn.rudderlabs.com": {"name": "RudderStack", "category": "Analytics"},
    "cdn.logrocket.io": {"name": "LogRocket", "category": "Session Replay"},
    "cdn.mouseflow.com": {"name": "Mouseflow", "category": "Session Replay"},
    "static.clarity.ms": {"name": "Microsoft Clarity", "category": "Analytics"},
    "fullstory.com": {"name": "FullStory", "category": "Session Replay"},
    "pendo.io": {"name": "Pendo", "category": "Product Analytics"},
    # Support / Chat
    "js.intercomcdn.com": {"name": "Intercom", "category": "Support"},
    "widget.intercom.io": {"name": "Intercom", "category": "Support"},
    "static.zdassets.com": {"name": "Zendesk", "category": "Support"},
    "embed.tawk.to": {"name": "Tawk.to", "category": "Chat"},
    "wchat.freshchat.com": {"name": "Freshchat", "category": "Chat"},
    "js.crisp.chat": {"name": "Crisp", "category": "Chat"},
    "cdn.livechatinc.com": {"name": "LiveChat", "category": "Chat"},
    "widget.manychat.com": {"name": "ManyChat", "category": "Chat"},
    "chatbot.com": {"name": "Chatbot.com", "category": "Chat"},
    # Payments
    "js.stripe.com": {"name": "Stripe", "category": "Payments"},
    "checkout.stripe.com": {"name": "Stripe", "category": "Payments"},
    "www.paypal.com": {"name": "PayPal", "category": "Payments"},
    "pay.google.com": {"name": "Google Pay", "category": "Payments"},
    "applepay.cdn-apple.com": {"name": "Apple Pay", "category": "Payments"},
    "js.braintreegateway.com": {"name": "Braintree", "category": "Payments"},
    "checkoutshopper-live.adyen.com": {"name": "Adyen", "category": "Payments"},
    "jstest.authorize.net": {"name": "Authorize.net", "category": "Payments"},
    # Marketing
    "js.hs-scripts.com": {"name": "HubSpot", "category": "Marketing"},
    "js.hs-analytics.net": {"name": "HubSpot", "category": "Marketing"},
    "js.hsforms.net": {"name": "HubSpot", "category": "Marketing"},
    "connect.facebook.net": {"name": "Meta Pixel", "category": "Marketing"},
    "snap.licdn.com": {"name": "LinkedIn Insight", "category": "Marketing"},
    "ads.linkedin.com": {"name": "LinkedIn Ads", "category": "Marketing"},
    "static.ads-twitter.com": {"name": "Twitter/X Pixel", "category": "Marketing"},
    "cdn.optimizely.com": {"name": "Optimizely", "category": "A/B Testing"},
    "cdn.vwo.com": {"name": "VWO", "category": "A/B Testing"},
    "js.qualified.com": {"name": "Qualified", "category": "Marketing"},
    "js.chilipiper.com": {"name": "Chili Piper", "category": "Scheduling"},
    "assets.calendly.com": {"name": "Calendly", "category": "Scheduling"},
    # Privacy / Consent
    "cdn.cookielaw.org": {"name": "OneTrust", "category": "Privacy"},
    "consent.cookiebot.com": {"name": "Cookiebot", "category": "Privacy"},
    "cdn.iubenda.com": {"name": "Iubenda", "category": "Privacy"},
    "policy.app.cookieinformation.com": {"name": "Cookie Information", "category": "Privacy"},
    "cdn.privacy-mgmt.com": {"name": "Sourcepoint", "category": "Privacy"},
    "cdn.osano.com": {"name": "Osano", "category": "Privacy"},
    # Error monitoring / DevOps
    "js.sentry-cdn.com": {"name": "Sentry", "category": "Error Monitoring"},
    "browser.sentry-cdn.com": {"name": "Sentry", "category": "Error Monitoring"},
    "cdn.bugsnag.com": {"name": "Bugsnag", "category": "Error Monitoring"},
    "d2wy8f7a9ursnm.cloudfront.net": {"name": "Bugsnag", "category": "Error Monitoring"},
    "cdn.rollbar.com": {"name": "Rollbar", "category": "Error Monitoring"},
    "rum-static.pingdom.net": {"name": "Pingdom", "category": "Monitoring"},
    "rum.datadog-ci.com": {"name": "Datadog", "category": "Monitoring"},
    "js-agent.newrelic.com": {"name": "New Relic", "category": "Monitoring"},
    # Tag management
    "tags.tiqcdn.com": {"name": "Tealium", "category": "Tag Management"},
    "assets.adobedtm.com": {"name": "Adobe Launch", "category": "Tag Management"},
    # CDN / Infrastructure
    "cdn.jsdelivr.net": {"name": "jsDelivr", "category": "CDN"},
    "cdnjs.cloudflare.com": {"name": "cdnjs", "category": "CDN"},
    "unpkg.com": {"name": "unpkg", "category": "CDN"},
    # CMS platforms
    "cdn.shopify.com": {"name": "Shopify", "category": "E-commerce"},
    "static.wixstatic.com": {"name": "Wix", "category": "Website Builder"},
    "images.squarespace-cdn.com": {"name": "Squarespace", "category": "Website Builder"},
    "assets.squarespace.com": {"name": "Squarespace", "category": "Website Builder"},
    "cdn.webflow.com": {"name": "Webflow", "category": "Website Builder"},
    # Fonts / Design
    "fonts.googleapis.com": {"name": "Google Fonts", "category": "Fonts"},
    "use.typekit.net": {"name": "Adobe Fonts", "category": "Fonts"},
    # Social embeds
    "platform.twitter.com": {"name": "Twitter/X Embed", "category": "Social"},
    "www.youtube.com": {"name": "YouTube", "category": "Video"},
    "player.vimeo.com": {"name": "Vimeo", "category": "Video"},
    "fast.wistia.com": {"name": "Wistia", "category": "Video"},
    "play.vidyard.com": {"name": "Vidyard", "category": "Video"},
    # Captcha / Security
    "www.google.com/recaptcha": {"name": "reCAPTCHA", "category": "Security"},
    "challenges.cloudflare.com": {"name": "Cloudflare Turnstile", "category": "Security"},
    "hcaptcha.com": {"name": "hCaptcha", "category": "Security"},
}

# HTTP header patterns that reveal infrastructure vendors
INFRA_HEADER_PATTERNS = {
    "x-vercel-id": {"name": "Vercel", "category": "Hosting"},
    "x-vercel-cache": {"name": "Vercel", "category": "Hosting"},
    "x-shopify-stage": {"name": "Shopify", "category": "E-commerce"},
    "x-wix-request-id": {"name": "Wix", "category": "Website Builder"},
    "x-squarespace-did": {"name": "Squarespace", "category": "Website Builder"},
    "x-sucuri-id": {"name": "Sucuri", "category": "WAF"},
    "x-kinsta-cache": {"name": "Kinsta", "category": "Hosting"},
    "x-pantheon-styx-hostname": {"name": "Pantheon", "category": "Hosting"},
    "x-github-request-id": {"name": "GitHub Pages", "category": "Hosting"},
    "x-netlify-request-id": {"name": "Netlify", "category": "Hosting"},
    "fly-request-id": {"name": "Fly.io", "category": "Hosting"},
    "x-render-origin-server": {"name": "Render", "category": "Hosting"},
    "x-railway-request-id": {"name": "Railway", "category": "Hosting"},
    "x-heroku-dynos-in-use": {"name": "Heroku", "category": "Hosting"},
    "x-amz-cf-id": {"name": "AWS CloudFront", "category": "CDN"},
    "x-amz-cf-pop": {"name": "AWS CloudFront", "category": "CDN"},
    "x-azure-ref": {"name": "Azure CDN", "category": "CDN"},
    "x-cache-hits": {"name": "Fastly", "category": "CDN"},
    "x-wp-total": {"name": "WordPress", "category": "CMS"},
    "x-drupal-cache": {"name": "Drupal", "category": "CMS"},
    "x-generator": {"name": None, "category": "CMS"},
}

# Header-based technology signatures
HEADER_SIGNATURES = {
    "nginx": {"header": "server", "pattern": r"nginx", "category": "web_server"},
    "apache": {"header": "server", "pattern": r"apache", "category": "web_server"},
    "iis": {"header": "server", "pattern": r"(iis|microsoft)", "category": "web_server"},
    "cloudflare": {"header": "server", "pattern": r"cloudflare", "category": "cdn"},
    "php": {"header": "x-powered-by", "pattern": r"php", "category": "language"},
    "asp.net": {"header": "x-powered-by", "pattern": r"asp\.net", "category": "framework"},
    "express": {"header": "x-powered-by", "pattern": r"express", "category": "framework"},
    "cloudflare_ray": {"header": "cf-ray", "pattern": r".*", "category": "cdn"},
    "akamai": {"header": "x-akamai", "pattern": r".*", "category": "cdn"},
    "fastly": {"header": "x-served-by", "pattern": r"cache-.*\.fastly", "category": "cdn"},
    "varnish": {"header": "via", "pattern": r"varnish", "category": "caching"},
}

# HTML content patterns
HTML_SIGNATURES = {
    "wordpress": {"patterns": [r"/wp-content/", r"/wp-includes/", r"wp-json"], "category": "cms"},
    "drupal": {"patterns": [r"/sites/default/", r"Drupal\.settings", r"/misc/drupal\.js"], "category": "cms"},
    "joomla": {"patterns": [r"/components/com_", r"Joomla!", r"/media/jui/"], "category": "cms"},
    "shopify": {"patterns": [r"cdn\.shopify\.com", r"Shopify\.theme"], "category": "ecommerce"},
    "magento": {"patterns": [r"/skin/frontend/", r"Mage\.Cookies", r"/js/mage/"], "category": "ecommerce"},
    "react": {"patterns": [r"react", r"_reactRoot", r"__REACT"], "category": "js_framework"},
    "vue": {"patterns": [r"vue\.js", r"__VUE", r"v-cloak"], "category": "js_framework"},
    "angular": {"patterns": [r"angular", r"ng-app", r"ng-controller"], "category": "js_framework"},
    "jquery": {"patterns": [r"jquery", r"\$\.fn\.jquery"], "category": "js_library"},
    "bootstrap": {"patterns": [r"bootstrap", r"btn-primary", r"container-fluid"], "category": "css_framework"},
    "google_analytics": {"patterns": [r"google-analytics\.com", r"gtag\(", r"ga\("], "category": "analytics"},
    "google_tag_manager": {"patterns": [r"googletagmanager\.com"], "category": "analytics"},
    "facebook_pixel": {"patterns": [r"facebook\.net.*fbevents\.js", r"fbq\("], "category": "analytics"},
    "mixpanel": {"patterns": [r"mixpanel\.com", r"mixpanel\.init"], "category": "analytics"},
    "segment": {"patterns": [r"segment\.com", r"analytics\.js", r"analytics\.load"], "category": "analytics"},
    "hotjar": {"patterns": [r"hotjar\.com", r"_hjSettings", r"hj\("], "category": "analytics"},
    "amplitude": {"patterns": [r"amplitude\.com", r"amplitude\.getInstance"], "category": "analytics"},
    "heap": {"patterns": [r"heapanalytics\.com", r"heap\.load"], "category": "analytics"},
    "matomo": {"patterns": [r"matomo", r"piwik", r"_paq\.push"], "category": "analytics"},
    "stripe": {"patterns": [r"stripe\.com", r"Stripe\(", r"stripe\.js"], "category": "payment"},
    "paypal": {"patterns": [r"paypal\.com", r"paypal\.Buttons", r"paypal-buttons"], "category": "payment"},
    "square": {"patterns": [r"squareup\.com", r"Square\.payments"], "category": "payment"},
    "braintree": {"patterns": [r"braintreegateway\.com", r"braintree\.client"], "category": "payment"},
    "adyen": {"patterns": [r"adyen\.com", r"AdyenCheckout"], "category": "payment"},
    "authorize_net": {"patterns": [r"authorize\.net", r"acceptjs"], "category": "payment"},
    "tealium": {"patterns": [r"tealium\.com", r"utag\.js"], "category": "tag_manager"},
    "adobe_launch": {"patterns": [r"assets\.adobedtm\.com", r"_satellite"], "category": "tag_manager"},
    "intercom": {"patterns": [r"intercom\.io", r"Intercom\("], "category": "support"},
    "zendesk": {"patterns": [r"zendesk\.com", r"zE\("], "category": "support"},
    "drift": {"patterns": [r"drift\.com", r"drift\.load"], "category": "support"},
    "livechat": {"patterns": [r"livechatinc\.com", r"LiveChatWidget"], "category": "support"},
    "optimizely": {"patterns": [r"optimizely\.com", r"window\.optimizely"], "category": "marketing"},
    "google_optimize": {"patterns": [r"optimize\.google\.com", r"gtag.*optimize"], "category": "marketing"},
    "hubspot": {"patterns": [r"hubspot\.com", r"_hsq\.push"], "category": "marketing"},
    "mailchimp": {"patterns": [r"mailchimp\.com", r"mc\.js"], "category": "marketing"},
    "cloudflare_waf": {"patterns": [r"cloudflare.*challenge", r"cf-browser-verification"], "category": "waf"},
}


def _extract_version(text: str) -> str | None:
    """Try to extract version number from text."""
    m = re.search(r"[\d]+\.[\d]+(?:\.[\d]+)?", text)
    return m.group(0) if m else None


def _analyze_headers(headers: dict) -> dict:
    """Analyze HTTP headers for technology signatures."""
    detected = {}
    headers_lower = {k.lower(): v for k, v in headers.items()}

    for tech_name, sig in HEADER_SIGNATURES.items():
        header_name = sig["header"]
        if header_name in headers_lower:
            if re.search(sig["pattern"], headers_lower[header_name], re.IGNORECASE):
                detected[tech_name] = {
                    "category": sig["category"],
                    "detection_methods": [f"HTTP header: {header_name}"],
                    "version": _extract_version(headers_lower[header_name]),
                }

    return detected


def _analyze_html(html: str) -> dict:
    """Analyze HTML content for technology signatures."""
    detected = {}
    for tech_name, sig in HTML_SIGNATURES.items():
        for pattern in sig["patterns"]:
            if re.search(pattern, html, re.IGNORECASE):
                detected[tech_name] = {
                    "category": sig["category"],
                    "detection_methods": ["HTML content analysis"],
                    "version": None,
                }
                break
    return detected


def _extract_third_party_services(html: str, site_domain: str) -> list[dict]:
    """Extract third-party services from HTML resource references."""
    if not HAS_BS4:
        return []

    services = []
    seen_names = set()

    try:
        try:
            soup = BeautifulSoup(html, "lxml")
        except Exception:
            soup = BeautifulSoup(html, "html.parser")

        external_urls = set()
        for tag in soup.find_all("script", src=True):
            external_urls.add(tag["src"])
        for tag in soup.find_all("link", href=True):
            external_urls.add(tag["href"])
        for tag in soup.find_all("img", src=True):
            external_urls.add(tag["src"])
        for tag in soup.find_all("iframe", src=True):
            external_urls.add(tag["src"])

        for url in external_urls:
            if url.startswith("data:") or url.startswith("#"):
                continue
            if not url.startswith("http") and not url.startswith("//"):
                continue

            clean = url
            if clean.startswith("//"):
                clean = "https:" + clean
            try:
                hostname = urlparse(clean).netloc.lower()
            except Exception:
                continue

            if not hostname or site_domain in hostname:
                continue

            for pattern, info in THIRD_PARTY_DOMAINS.items():
                if pattern in hostname and info["name"] not in seen_names:
                    seen_names.add(info["name"])
                    services.append({
                        "name": info["name"],
                        "category": info["category"],
                        "domain": hostname,
                        "detection_method": "html_resource",
                    })
                    break

    except Exception as e:
        logger.debug(f"Third-party extraction error: {e}")

    return services


def _detect_infra_headers(headers: dict) -> list[dict]:
    """Detect infrastructure vendors from HTTP response headers."""
    services = []
    seen = set()
    headers_lower = {k.lower(): v for k, v in headers.items()}

    for header_name, info in INFRA_HEADER_PATTERNS.items():
        if header_name in headers_lower:
            name = info["name"]
            if name is None and header_name == "x-generator":
                name = headers_lower[header_name].split("/")[0].strip()
                if not name or len(name) < 2:
                    continue
            if name and name not in seen:
                seen.add(name)
                services.append({
                    "name": name,
                    "category": info["category"],
                    "detection_method": f"header:{header_name}",
                })

    return services


def detect_stack(domain: str, timeout: int = 10) -> dict:
    """Detect technology stack for a website."""
    url = domain if domain.startswith("http") else f"https://{domain}"
    site_domain = urlparse(url).netloc.lower().lstrip("www.")

    result = {
        "url": url,
        "technologies": {},
        "categories": {},
        "third_party_services": [],
        "error": None,
    }

    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            response = client.get(
                url,
                headers={"User-Agent": "Mozilla/5.0 (compatible; BusinessProfiler/1.0)"},
            )

        resp_headers = dict(response.headers)

        # Header-based detection
        header_techs = _analyze_headers(resp_headers)
        for tech, info in header_techs.items():
            result["technologies"][tech] = info

        # Infrastructure header detection
        result["third_party_services"].extend(_detect_infra_headers(resp_headers))

        # HTML content analysis
        if response.text:
            html_techs = _analyze_html(response.text)
            for tech, info in html_techs.items():
                if tech in result["technologies"]:
                    result["technologies"][tech]["detection_methods"].extend(info["detection_methods"])
                else:
                    result["technologies"][tech] = info

            tp_services = _extract_third_party_services(response.text, site_domain)
            result["third_party_services"].extend(tp_services)

        # Deduplicate third_party_services by name
        seen_names = set()
        deduped = []
        for svc in result["third_party_services"]:
            if svc["name"] not in seen_names:
                seen_names.add(svc["name"])
                deduped.append(svc)
        result["third_party_services"] = deduped

        # Group by categories
        for tech, info in result["technologies"].items():
            cat = info["category"]
            if cat not in result["categories"]:
                result["categories"][cat] = []
            result["categories"][cat].append(tech)

    except httpx.TimeoutException:
        result["error"] = "Connection timeout"
    except httpx.HTTPError as e:
        result["error"] = str(e)
    except Exception as e:
        result["error"] = str(e)

    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Detect website technology stack")
    parser.add_argument("--domain", required=True, help="Domain to analyze (auto-prepends https://)")
    args = parser.parse_args()

    print(json.dumps(detect_stack(args.domain), indent=2))
