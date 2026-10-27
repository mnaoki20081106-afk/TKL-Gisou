#!/usr/bin/env python3
"""
mitmproxy addon: JP geo-rewrite + suppress TikTok Lite geo-block dialog.

Layer 1 (device_register): rewrite store-country-code=us → jp in Set-Cookie.
  TikTok Lite's geo-block chain starts here — device_register assigns the
  region via a signed cookie.  We overwrite the value to jp so all subsequent
  requests (consent/api/combine, popup/dispatch, feed/initial) are served
  as Japan region.  store-country-sign is left intact; strict signature
  validation is rare on the invite flow.

Layer 2 (popup/dispatch fallback): if the geo-dialog still fires despite
  the cookie rewrite, suppress the policy_notice body so the app continues.
"""
import json
import gzip
import re

from mitmproxy import http

_ZSTD_MAGIC = b'\x28\xb5\x2f\xfd'


def _decode_body(content: bytes) -> bytes:
    if content[:4] == _ZSTD_MAGIC:
        try:
            import zstandard
            return zstandard.ZstdDecompressor().decompress(content)
        except Exception:
            pass
    if content[:2] == b'\x1f\x8b':
        try:
            return gzip.decompress(content)
        except Exception:
            pass
    return content


def _rewrite_geo_cookies(flow: http.HTTPFlow) -> None:
    """Rewrite store-country-code us→jp in device_register Set-Cookie headers."""
    raw_cookies = flow.response.headers.get_all("set-cookie")
    if not any("store-country-code=" in c for c in raw_cookies):
        return

    del flow.response.headers["set-cookie"]
    for cookie_val in raw_cookies:
        if "store-country-code=" in cookie_val:
            orig = cookie_val
            cookie_val = re.sub(r'store-country-code=[^;,\s]+',
                                'store-country-code=jp', cookie_val)
            if cookie_val != orig:
                print(f"[GEO-JP] Rewrote store-country-code → jp  (sign left intact)")
        flow.response.headers.add("set-cookie", cookie_val)


def response(flow: http.HTTPFlow) -> None:
    url = flow.request.pretty_url

    # Normalize ttzip (TikTok's zstd variant) so mitmproxy stores decoded content
    if flow.response.headers.get("content-encoding", "").lower() == "ttzip":
        raw = flow.response.raw_content
        if raw and raw[:4] == _ZSTD_MAGIC:
            try:
                import zstandard
                decompressed = zstandard.ZstdDecompressor().decompress(raw)
                flow.response.raw_content = decompressed
                del flow.response.headers["content-encoding"]
                flow.response.headers["content-length"] = str(len(decompressed))
            except Exception:
                pass

    # Layer 1: JP region assignment via cookie rewrite
    if "device_register" in url:
        _rewrite_geo_cookies(flow)

    # Diagnostic: log get_domains response to reveal traffic control rule structure
    if "get_domains" in url:
        try:
            raw = _decode_body(flow.response.content)
            print(f"[GET_DOMAINS] {url[-80:]} ({len(raw)}b): {raw[:4000].decode('utf-8', errors='replace')}")
        except Exception as e:
            print(f"[GET_DOMAINS] decode error: {e}")

    # Diagnostic: log all popup/dispatch scene=555 bodies (business type identification)
    if "popup/dispatch" in url and "scene=555" in url:
        try:
            raw = _decode_body(flow.response.content)
            print(f"[POPUP555] {url[-100:]} body: {raw[:2000].decode('utf-8', errors='replace')}")
        except Exception as e:
            print(f"[POPUP555] error: {e}")

    # Diagnostic: log gecko config (TTNet routing rules source)
    if "gecko/server/v5/package" in url or "gecko/api/settings" in url:
        try:
            raw = _decode_body(flow.response.content)
            print(f"[GECKO] {url[-80:]} ({len(raw)}b): {raw[:2000].decode('utf-8', errors='replace')}")
        except Exception as e:
            print(f"[GECKO] error: {e}")

    # Layer 2: suppress geo-block dialog (fallback if layer 1 is insufficient)
    if "popup/dispatch" not in url:
        return

    try:
        raw = _decode_body(flow.response.content)
        data = json.loads(raw)
    except Exception:
        return

    notices = data.get("policy_notices", [])
    is_geo_block = any(
        n.get("business", "") == "geoblocking_non_op_wo_uid"
        for n in notices
    )

    if not is_geo_block:
        return

    logid = flow.response.headers.get("x-tt-logid", "")
    now = data.get("extra", {}).get("now", 0)

    empty = {
        "status_code": 0,
        "status_msg": "",
        "extra": {
            "fatal_item_ids": [],
            "logid": logid,
            "now": now,
        },
        "log_pb": {"impr_id": logid},
    }
    new_body = json.dumps(empty).encode()

    flow.response.content = new_body
    flow.response.headers["content-length"] = str(len(new_body))
    if "content-encoding" in flow.response.headers:
        del flow.response.headers["content-encoding"]

    print(f"[GEO-BYPASS] Suppressed geo-block dialog on {url}")
