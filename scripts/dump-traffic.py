#!/usr/bin/env python3
"""Read a traffic.mitm file and print full URLs, headers, and bodies."""
import sys
import json
import gzip

KEY_PATHS = [
    "incentive", "mentor", "invite", "referral",
    "pro_scan_code", "share/page", "share/",
    "device_register", "linker", "passport",
    "abtest", "feed/initial", "user/webid",
    "/t/ZS9y8",  # the invite short URL
    "popup/dispatch",  # geo-block dialog source
    "user/strategy",   # feature flags / availability
    "get_domains",     # domain routing config
]


def fmt_body(b, limit=12000):
    if not b:
        return "(empty)"
    # TikTok sometimes sends gzip without Content-Encoding header
    if b[:2] == b'\x1f\x8b':
        try:
            b = gzip.decompress(b)
        except Exception:
            pass
    try:
        j = json.loads(b)
        return json.dumps(j, ensure_ascii=False, indent=2)[:limit]
    except Exception:
        try:
            return b.decode("utf-8", errors="replace")[:limit]
        except Exception:
            return repr(b[:limit])


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "traffic.mitm"
    try:
        from mitmproxy import io as mio
        from mitmproxy.http import HTTPFlow
    except ImportError as e:
        print(f"mitmproxy import failed: {e}")
        sys.exit(1)

    total = 0
    key_flows = []
    with open(path, "rb") as f:
        reader = mio.FlowReader(f)
        for flow in reader.stream():
            if not isinstance(flow, HTTPFlow):
                continue
            total += 1
            req = flow.request
            url = req.pretty_url
            is_key = any(k in url for k in KEY_PATHS)

            print(f"{req.method} {url}")
            if flow.response:
                ct = flow.response.headers.get("content-type", "")
                print(f"  -> {flow.response.status_code}  {len(flow.response.content)}b  {ct[:60]}")
            if is_key:
                key_flows.append(flow)

    print(f"\n\nTotal flows: {total}  Key flows: {len(key_flows)}")
    print("=" * 70)

    for flow in key_flows:
        req = flow.request
        print(f"\n{'='*70}")
        print(f"KEY: {req.method} {req.pretty_url}")
        print("--- Request headers ---")
        for k, v in req.headers.items():
            print(f"  {k}: {v[:300]}")
        if req.content:
            print(f"--- Request body ({len(req.content)}b) ---")
            print(fmt_body(req.content))
        if flow.response:
            r = flow.response
            print(f"--- Response {r.status_code} ({len(r.content)}b) ---")
            for k, v in r.headers.items():
                print(f"  {k}: {v[:200]}")
            print("--- Response body ---")
            print(fmt_body(r.content, limit=12000))


if __name__ == "__main__":
    main()
