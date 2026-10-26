#!/usr/bin/env python3
"""Parse uiautomator dump XML, extract snssdk deeplink or tap by keyword."""
import subprocess, sys, re, xml.etree.ElementTree as ET
from urllib.parse import parse_qs, unquote

KEYWORDS = [
    "コイン", "受け取", "accept", "claim", "start",
    "始め", "参加", "ポイント", "get", "scan",
    "今すぐ", "利用", "開く", "open", "collect",
]


def fire_snssdk(url):
    print(f"[*] Firing snssdk deeplink: {url[:120]}...")
    result = subprocess.run(
        ["adb", "-s", "localhost:5555", "shell",
         f"am start -a android.intent.action.VIEW -d '{url}'"],
        capture_output=True, text=True, check=False
    )
    out = (result.stdout + result.stderr).strip()
    print(f"[*] am start: {out}")


def main():
    xml_path = sys.argv[1] if len(sys.argv) > 1 else "ui_dump.xml"
    try:
        tree = ET.parse(xml_path)
    except Exception as e:
        print(f"[!] XML parse failed: {e}")
        return

    snssdk_url = None
    incentive_url = None
    hits = []

    print("=== All text nodes ===")
    for node in tree.iter("node"):
        text = ((node.get("text") or "") + " " + (node.get("content-desc") or "")).strip()
        bounds = node.get("bounds", "")
        clickable = node.get("clickable") == "true"
        if text:
            print(f"  {'[TAP]' if clickable else '[txt]'} {text!r:60s} {bounds}")

        # Path 1: URL bar navigated to a ?redirect_url=snssdk473824://... URL
        if snssdk_url is None and "snssdk473824" in text:
            try:
                qs = parse_qs(text.lstrip("?"), keep_blank_values=True)
                val = qs.get("redirect_url", [None])[0]
                if val:
                    decoded = unquote(val)
                    if decoded.startswith("snssdk473824://"):
                        snssdk_url = decoded
                        print(f"[*] snssdk URL extracted via redirect_url ({len(snssdk_url)} chars)")
                elif text.startswith("snssdk473824://"):
                    snssdk_url = text.strip()
                    print(f"[*] snssdk URL is bare ({len(snssdk_url)} chars)")
            except Exception:
                pass

        # Path 2: URL bar shows the incentive web page directly →
        # wrap in snssdk473824://roma_redirect/?params_url= so TikTok Lite opens it
        if snssdk_url is None and incentive_url is None:
            if text.startswith("http") and "tiktok.com/ug/incentive/" in text:
                incentive_url = text.strip()
                print(f"[*] incentive web URL captured ({len(incentive_url)} chars)")

        # Keyword tap fallback — skip URL-like text
        if bounds and text and not any(skip in text for skip in ["http", "snssdk", "redirect_url"]):
            if any(k.lower() in text.lower() for k in KEYWORDS):
                m = re.findall(r"\d+", bounds)
                if len(m) == 4:
                    x = (int(m[0]) + int(m[2])) // 2
                    y = (int(m[1]) + int(m[3])) // 2
                    hits.append((text, x, y, clickable))

    print()

    if snssdk_url:
        fire_snssdk(snssdk_url)
    elif incentive_url:
        deeplink = f"snssdk473824://roma_redirect/?params_url={incentive_url}"
        print(f"[*] Constructed roma_redirect from incentive URL ({len(deeplink)} chars)")
        fire_snssdk(deeplink)
    elif hits:
        text, x, y, _ = hits[0]
        print(f"[*] Keyword match: {text!r} -> tapping ({x},{y})")
        subprocess.run(
            ["adb", "-s", "localhost:5555", "shell", f"input tap {x} {y}"],
            check=False,
        )
        print("[*] Tap sent")
    else:
        print("[!] No snssdk deeplink, incentive URL, or keyword match -- skipping")


if __name__ == "__main__":
    main()
