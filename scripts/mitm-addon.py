#!/usr/bin/env python3
"""
mitmproxy addon: suppress TikTok Lite geo-block dialog.

Intercepts popup/dispatch responses that carry the geo-blocking policy notice
(business == "geoblocking_non_op_wo_uid") and replaces the body with an empty
success response so the app continues loading.
"""
import json
import gzip

from mitmproxy import http


def _decode_body(content: bytes) -> bytes:
    if content[:2] == b'\x1f\x8b':
        try:
            return gzip.decompress(content)
        except Exception:
            pass
    return content


def response(flow: http.HTTPFlow) -> None:
    url = flow.request.pretty_url

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
    # Remove content-encoding so the plain JSON is delivered as-is
    if "content-encoding" in flow.response.headers:
        del flow.response.headers["content-encoding"]

    print(f"[GEO-BYPASS] Suppressed geo-block on {url}")
