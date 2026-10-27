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
    """Rewrite region cookies in device_register Set-Cookie headers.

    store-country-code us→jp : tells each API server the device is JP region.
    store-idc useast*/usva* → alisg : routes TTNet to Singapore IDC so product_facade
      goes to api19-normal-c-alisg instead of api19-va (which drops incentive for non-US).
    """
    raw_cookies = flow.response.headers.get_all("set-cookie")
    if not any(("store-country-code=" in c or "store-idc=" in c) for c in raw_cookies):
        return

    del flow.response.headers["set-cookie"]
    for cookie_val in raw_cookies:
        orig = cookie_val
        if "store-country-code=" in cookie_val:
            cookie_val = re.sub(r'store-country-code=[^;,\s]+',
                                'store-country-code=jp', cookie_val)
        if "store-idc=" in cookie_val:
            # rewrite any US-based IDC to Singapore
            cookie_val = re.sub(r'store-idc=(?:useast|usva|us)[^;,\s]*',
                                'store-idc=alisg', cookie_val)
        if cookie_val != orig:
            changed = []
            if "store-country-code=jp" in cookie_val and "store-country-code=jp" not in orig:
                changed.append("store-country-code→jp")
            if "store-idc=alisg" in cookie_val and "store-idc=alisg" not in orig:
                changed.append("store-idc→alisg")
            if changed:
                print(f"[GEO-JP] Rewrote {', '.join(changed)}  (sign left intact)")
        flow.response.headers.add("set-cookie", cookie_val)


def request(flow: http.HTTPFlow) -> None:
    """Rewrite sys_region/op_region/region US→JP on all TikTok API requests.

    TTNet derives traffic-control rules from get_domains/v5/ using these params.
    US region config blocks incentive/product_facade paths client-side before
    any request reaches the proxy.  Rewriting to JP makes the server return JP
    routing config (which allows those paths) and tells each API endpoint the
    device is operating in JP.
    """
    url = flow.request.pretty_url
    if not any(h in url for h in ("tiktokv.com", "tiktok.com", "byteoversea")):
        return

    qs = flow.request.query
    changed = False
    for param in ("sys_region", "op_region", "region"):
        if qs.get(param, "").upper() == "US":
            qs[param] = "JP"
            changed = True

    if changed:
        flow.request.query = qs
        print(f"[GEO-REQ] Rewrote region params →JP: {flow.request.path[:80]}")


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

    # Diagnostic: log get_domains response — print top-level keys + dispatch_actions
    if "get_domains" in url:
        try:
            raw = _decode_body(flow.response.content)
            try:
                gd = json.loads(raw)
                d = gd.get("data", gd)
                keys = list(d.keys())
                print(f"[GET_DOMAINS] keys: {keys}")
                # print dispatch_actions specifically (the traffic control rule set)
                da = d.get("ttnet_dispatch_actions") or d.get("dispatch_actions")
                if da is not None:
                    print(f"[GET_DOMAINS] dispatch_actions ({len(da)} rules): {json.dumps(da, ensure_ascii=False)[:8000]}")
                else:
                    print(f"[GET_DOMAINS] dispatch_actions: NOT FOUND — first 6000b: {raw[:6000].decode('utf-8', errors='replace')}")
            except Exception as je:
                print(f"[GET_DOMAINS] JSON error: {je} — raw[:2000]: {raw[:2000].decode('utf-8', errors='replace')}")
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
