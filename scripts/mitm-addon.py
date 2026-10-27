#!/usr/bin/env python3
"""
mitmproxy addon: JP geo-rewrite + suppress TikTok Lite geo-block dialog.

Layer 1 (device_register): rewrite store-country-code=us → jp in Set-Cookie.
  Also log response body to understand IDC selection chain.

Layer 2 (popup/dispatch fallback): suppress geoblocking_non_op_wo_uid dialog.

Layer 3 (get_domains): patch idc_weight_api_normal_ug_incentive_alisg dispatch
  rule to include api19-va.tiktokv.com → api19-normal-c-alisg.tiktokv.com.
  NOTE: TTNet validates the sign field on each rule; our modified rule has no
  sign and is rejected by the client.  Layer 4 is the real fix.

Layer 4 (H2 keepalive hosts): rewrite ping_keepalive_hosts in both device_register
  (tnc_data.ttnet_h2_config) and get_domains (ttnet_h2_config) to point at alisg
  servers.  If TTNet's initial H2 connections go to Singapore, all API calls
  route through alisg IDC and the US-east ERR_TTNET_TRAFFIC_CONTROL_DROP on
  product_facade is bypassed entirely.
"""
import json
import gzip
import re

from mitmproxy import http

_ZSTD_MAGIC = b'\x28\xb5\x2f\xfd'

# Target service name for the incentive→alisg dispatch rule we need to patch
_INCENTIVE_ALISG_SVC = "idc_weight_api_normal_ug_incentive_alisg"

# Alisg H2 host to substitute for US east keepalive entries
_ALISG_H2_HOST = "api19-normal-c-alisg.tiktokv.com:443"
# Secondary alisg host (redundancy in case primary is down)
_ALISG_H2_HOST2 = "api22-normal-c-alisg.tiktokv.com:443"


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


def _is_us_h2_host(h: str) -> bool:
    """True if the host string is a US east / US-va server entry."""
    return any(pat in h for pat in (
        ".tiktokv.us",
        "useast",
        "-useast",
        "tiktokv.us:",
        "-va.tiktokv",
        "usva",
    ))


def _patch_h2_keepalive_hosts(data: dict, context: str) -> bool:
    """Layer 4: replace US east H2 keepalive hosts with alisg equivalents.

    Searches for ping_keepalive_hosts in:
      - data["tnc_data"]["ttnet_h2_config"]          (device_register)
      - data["data"]["ttnet_h2_config"]               (get_domains top-level)
      - data["ttnet_h2_config"]                       (get_domains nested)

    tnc_data may be a JSON-string (double-encoded) — handles that too.
    Returns True if any substitution was made.
    """
    patched = False

    h2_containers = []

    # Path 1: device_register — data → tnc_data → ttnet_h2_config
    tnc = data.get("tnc_data") or data.get("data", {}).get("tnc_data")
    if isinstance(tnc, str):
        try:
            tnc = json.loads(tnc)
        except Exception:
            tnc = None
    if isinstance(tnc, dict):
        h2 = tnc.get("ttnet_h2_config")
        if isinstance(h2, dict):
            h2_containers.append(("tnc_data.ttnet_h2_config", h2))

    # Path 2: get_domains — data.data.ttnet_h2_config
    inner = data.get("data", {})
    if isinstance(inner, dict):
        h2 = inner.get("ttnet_h2_config")
        if isinstance(h2, dict):
            h2_containers.append(("data.ttnet_h2_config", h2))

    # Path 3: get_domains — data.ttnet_h2_config (if response is flat)
    h2 = data.get("ttnet_h2_config")
    if isinstance(h2, dict):
        h2_containers.append(("ttnet_h2_config", h2))

    for path, h2 in h2_containers:
        hosts = h2.get("ping_keepalive_hosts")
        if not isinstance(hosts, list) or not hosts:
            continue

        replaced = []
        new_hosts = []
        for h in hosts:
            if _is_us_h2_host(h):
                replaced.append(h)
                # Replace with alisg hosts (add both for redundancy, deduplicate later)
                new_hosts.append(_ALISG_H2_HOST)
                new_hosts.append(_ALISG_H2_HOST2)
            else:
                new_hosts.append(h)

        if replaced:
            # Deduplicate while preserving insertion order
            seen: set = set()
            deduped = []
            for h in new_hosts:
                if h not in seen:
                    seen.add(h)
                    deduped.append(h)
            h2["ping_keepalive_hosts"] = deduped
            patched = True
            print(f"[H2-PATCH] {context} @ {path}: replaced {len(replaced)} US hosts -> alisg")
            print(f"[H2-PATCH-REMOVED] {replaced}")
            print(f"[H2-PATCH-NEW] {deduped}")
        else:
            existing = hosts[:4]
            print(f"[H2-PATCH] {context} @ {path}: no US hosts found in {existing!r} (already alisg?)")

    if not h2_containers:
        print(f"[H2-PATCH] {context}: ttnet_h2_config not found at any expected path")

    return patched


def _patch_get_domains(data: dict) -> bool:
    """Layer 3: patch ttnet_dispatch_actions in get_domains response data dict.

    Adds api19-va.tiktokv.com to the idc_weight_api_normal_ug_incentive_alisg
    rule so TTNet routes /tiktok/incentive/ paths on api19-va → Singapore IDC.
    NOTE: sign validation in TTNet rejects unsigned rules; this layer is kept
    as a belt-and-suspenders measure alongside Layer 4.
    Returns True if the rule was found and patched.
    """
    d = data.get("data", data)
    da = d.get("ttnet_dispatch_actions") or d.get("dispatch_actions")
    if not da:
        print("[PATCH_GD] dispatch_actions not found — skipping patch")
        return False

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
            rule.pop("sign", None)
            print(f"[PATCH_GD] Patched {_INCENTIVE_ALISG_SVC}: api19-va->api19-normal-c-alisg added, sign removed")
            return True

    print(f"[PATCH_GD] Rule {_INCENTIVE_ALISG_SVC} not found in {len(da)} dispatch_actions")
    return False


def request(flow: http.HTTPFlow) -> None:
    """Log incentive-path requests to diagnose if product_facade ever reaches proxy."""
    url = flow.request.pretty_url
    if not any(h in url for h in ("tiktokv.com", "tiktok.com", "byteoversea")):
        return

    path = flow.request.path
    if "/tiktok/incentive/" in path or "/product_facade/" in path or "/falcon/incentive" in path:
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

    # Layer 5: rewrite x-tt-app-init-region so server sees JP, not US
    x_init = flow.request.headers.get("x-tt-app-init-region", "")
    if x_init and ("sysregion=US" in x_init or "appregion=US" in x_init):
        new_init = re.sub(r'sysregion=US', 'sysregion=JP', x_init)
        new_init = re.sub(r'appregion=US', 'appregion=JP', new_init)
        flow.request.headers["x-tt-app-init-region"] = new_init
        print(f"[GEO-INIT] Rewrote x-tt-app-init-region: {x_init!r} -> {new_init!r}")


def response(flow: http.HTTPFlow) -> None:
    url = flow.request.pretty_url

    # Normalize ttzip (before any handler reads flow.response.content)
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

    # ppf/eligibility: log response body (Layer 5 diagnostic)
    if "ppf/api/eligibility" in url:
        try:
            raw = _decode_body(flow.response.content)
            print(f"[PPF-ELIG] {flow.response.status_code} ({len(raw)}b): {raw[:2000].decode('utf-8', errors='replace')}")
        except Exception as e:
            print(f"[PPF-ELIG] error: {e}")

    # Layer 1 + Layer 4 (device_register)
    if "device_register" in url:
        _rewrite_geo_cookies(flow)
        try:
            raw = _decode_body(flow.response.content)
            data = json.loads(raw)

            # Log tnc_data dispatch_actions (incentive/ppf rules specifically)
            tnc = data.get("tnc_data")
            if isinstance(tnc, str):
                try:
                    tnc = json.loads(tnc)
                except Exception:
                    tnc = None
            if isinstance(tnc, dict):
                da = tnc.get("ttnet_dispatch_actions", [])
                key_rules = [r for r in da if any(
                    kw in json.dumps(r) for kw in ['incentive', 'product_facade', 'ppf', 'api19', 'alisg']
                )]
                print(f"[DEVREG-TNC-DA] {len(da)} rules total, {len(key_rules)} key (incentive/ppf/alisg):")
                print(f"[DEVREG-TNC-DA-KEY] {json.dumps(key_rules, ensure_ascii=False)[:4000]}")
            else:
                print(f"[DEVREG-TNC-DA] tnc_data not a dict: {type(tnc)}")

            h2_patched = _patch_h2_keepalive_hosts(data, "device_register")
            if h2_patched:
                new_body = json.dumps(data).encode()
                flow.response.content = new_body
                flow.response.headers["content-length"] = str(len(new_body))
                # Clear any residual encoding since we're writing plain JSON
                flow.response.headers.pop("content-encoding", None)
        except Exception as e:
            print(f"[DEVREG-BODY] error: {e}")

    # Layer 3 + Layer 4 + diagnostics (get_domains)
    if "get_domains" in url:
        try:
            raw = _decode_body(flow.response.content)
            data = json.loads(raw)
        except Exception as e:
            print(f"[GET_DOMAINS] decode/parse error: {e}")
            return

        # Apply all patches to the shared parsed object
        _patch_get_domains(data)
        _patch_h2_keepalive_hosts(data, "get_domains")

        # Re-encode once
        new_body = json.dumps(data).encode()
        flow.response.content = new_body
        flow.response.headers["content-length"] = str(len(new_body))
        flow.response.headers.pop("content-encoding", None)

        # Diagnostics
        d = data.get("data", data)
        keys = list(d.keys())
        print(f"[GET_DOMAINS] keys: {keys}")

        da = d.get("ttnet_dispatch_actions") or d.get("dispatch_actions")
        if da is not None:
            key_rules = [r for r in da if any(
                kw in json.dumps(r) for kw in ['api19', 'incentive', 'ppf', 'va.tiktok', 'alisg']
            )]
            print(f"[GET_DOMAINS] dispatch_actions ({len(da)} rules, {len(key_rules)} key): "
                  f"{json.dumps(key_rules, ensure_ascii=False)}")
        else:
            print(f"[GET_DOMAINS] dispatch_actions: NOT FOUND — first 3000b: "
                  f"{json.dumps(data)[:3000]}")

        # Log rect_request_control (might contain product_facade drop rules)
        rrc = d.get("rect_request_control")
        if rrc is not None:
            print(f"[GET_DOMAINS] rect_request_control ({type(rrc).__name__}): "
                  f"{json.dumps(rrc, ensure_ascii=False)[:3000]}")
        else:
            print("[GET_DOMAINS] rect_request_control: NOT FOUND")

        # Log ttnet_h2_config after patch
        h2cfg = d.get("ttnet_h2_config")
        if h2cfg is not None:
            print(f"[GET_DOMAINS] ttnet_h2_config (post-patch): {json.dumps(h2cfg, ensure_ascii=False)[:1000]}")

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
