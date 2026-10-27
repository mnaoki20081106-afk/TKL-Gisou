#!/usr/bin/env python3
"""
mitmproxy addon: JP geo-rewrite + suppress TikTok Lite geo-block dialog.

Layer 1 (device_register): rewrite store-country-code=us → jp in Set-Cookie.
  Also log response body to understand IDC selection chain.

Layer 2 (popup/dispatch fallback): suppress geoblocking_non_op_wo_uid dialog.

Layer 3 (get_domains): patch idc_weight_api_normal_ug_incentive_alisg dispatch
  rule to include api19-va.tiktokv.com → api19-normal-c-alisg.tiktokv.com.
  ERR_TTNET_TRAFFIC_CONTROL_DROP on product_facade is a client-side drop from
  TTNet evaluating dispatch_actions before making a TCP connection.  Patching
  the rule causes TTNet to route incentive/ paths on api19-va to Singapore
  instead of dropping them.
"""
import json
import gzip
import re

from mitmproxy import http

_ZSTD_MAGIC = b'\x28\xb5\x2f\xfd'

# Target service name for the incentive→alisg dispatch rule we need to patch
_INCENTIVE_ALISG_SVC = "idc_weight_api_normal_ug_incentive_alisg"


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
    """Rewrite region cookies in device_register Set-Cookie headers."""
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


def _patch_get_domains(flow: http.HTTPFlow) -> None:
    """Layer 3: patch ttnet_dispatch_actions in get_domains response.

    Adds api19-va.tiktokv.com to the idc_weight_api_normal_ug_incentive_alisg
    rule so TTNet routes /tiktok/incentive/ paths on api19-va → Singapore IDC
    instead of client-side-dropping them (ERR_TTNET_TRAFFIC_CONTROL_DROP).
    """
    try:
        raw = _decode_body(flow.response.content)
    except Exception as e:
        print(f"[PATCH_GD] decode error: {e}")
        return

    try:
        gd = json.loads(raw)
    except Exception as e:
        print(f"[PATCH_GD] JSON parse error: {e}")
        return

    d = gd.get("data", gd)
    da = d.get("ttnet_dispatch_actions") or d.get("dispatch_actions")
    if not da:
        print("[PATCH_GD] dispatch_actions not found — skipping patch")
        return

    patched = False
    for rule in da:
        param = rule.get("param", {})
        if param.get("service_name") == _INCENTIVE_ALISG_SVC:
            host_group = param.get("host_group", [])
            strategy_info = param.get("strategy_info", {})
            if "api19-va.tiktokv.com" not in host_group:
                host_group.append("api19-va.tiktokv.com")
                param["host_group"] = host_group
            strategy_info["api19-va.tiktokv.com"] = "api19-normal-c-alisg.tiktokv.com"
            param["strategy_info"] = strategy_info
            # Remove sign — content changed, old sign is invalid; TTNet may skip
            # validation or accept unsigned rules gracefully
            rule.pop("sign", None)
            patched = True
            print(f"[PATCH_GD] Patched {_INCENTIVE_ALISG_SVC}: api19-va→api19-normal-c-alisg added, sign removed")
            break

    if not patched:
        print(f"[PATCH_GD] Rule {_INCENTIVE_ALISG_SVC} not found in {len(da)} dispatch_actions")
        return

    # Re-encode and inject
    new_body = json.dumps(gd).encode()
    flow.response.content = new_body
    flow.response.headers["content-length"] = str(len(new_body))
    if "content-encoding" in flow.response.headers:
        del flow.response.headers["content-encoding"]


def request(flow: http.HTTPFlow) -> None:
    """Log incentive-path requests to diagnose if product_facade ever reaches proxy."""
    url = flow.request.pretty_url
    if not any(h in url for h in ("tiktokv.com", "tiktok.com", "byteoversea")):
        return

    # Diagnostic: log any request with incentive or product_facade path
    path = flow.request.path
    if "/tiktok/incentive/" in path or "/product_facade/" in path:
        print(f"[INCENTIVE-REQ] host={flow.request.host} path={path[:120]}")

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

    # Normalize ttzip
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

    # Layer 1: JP region via cookie rewrite + body log
    if "device_register" in url:
        _rewrite_geo_cookies(flow)
        # Log body to understand IDC fields TTNet reads
        try:
            raw = _decode_body(flow.response.content)
            print(f"[DEVREG-BODY] first 3000b: {raw[:3000].decode('utf-8', errors='replace')}")
        except Exception as e:
            print(f"[DEVREG-BODY] error: {e}")

    # Layer 3: patch dispatch_actions to route api19-va incentive → Singapore
    if "get_domains" in url:
        _patch_get_domains(flow)

        # Diagnostics (after patch)
        try:
            raw = _decode_body(flow.response.content)
            try:
                gd = json.loads(raw)
                d = gd.get("data", gd)
                keys = list(d.keys())
                print(f"[GET_DOMAINS] keys: {keys}")
                da = d.get("ttnet_dispatch_actions") or d.get("dispatch_actions")
                if da is not None:
                    key_rules = [r for r in da if any(
                        kw in json.dumps(r) for kw in ['api19', 'incentive', 'ppf', 'va.tiktok', 'alisg']
                    )]
                    print(f"[GET_DOMAINS] dispatch_actions ({len(da)} rules, {len(key_rules)} key): {json.dumps(key_rules, ensure_ascii=False)}")
                else:
                    print(f"[GET_DOMAINS] dispatch_actions: NOT FOUND — first 3000b: {raw[:3000].decode('utf-8', errors='replace')}")
            except Exception as je:
                print(f"[GET_DOMAINS] JSON error: {je} — raw[:2000]: {raw[:2000].decode('utf-8', errors='replace')}")
        except Exception as e:
            print(f"[GET_DOMAINS] decode error: {e}")

    # Diagnostic: popup/dispatch scene=555
    if "popup/dispatch" in url and "scene=555" in url:
        try:
            raw = _decode_body(flow.response.content)
            print(f"[POPUP555] {url[-100:]} body: {raw[:2000].decode('utf-8', errors='replace')}")
        except Exception as e:
            print(f"[POPUP555] error: {e}")

    # Diagnostic: gecko config
    if "gecko/server/v5/package" in url or "gecko/api/settings" in url:
        try:
            raw = _decode_body(flow.response.content)
            print(f"[GECKO] {url[-80:]} ({len(raw)}b): {raw[:2000].decode('utf-8', errors='replace')}")
        except Exception as e:
            print(f"[GECKO] error: {e}")

    # Layer 2: suppress geo-block dialog
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
