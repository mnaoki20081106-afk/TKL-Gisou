#!/usr/bin/env python3
"""Parse uiautomator dump XML, extract snssdk deeplink or tap by keyword."""
import subprocess, sys, re, xml.etree.ElementTree as ET
from urllib.parse import parse_qs, quote

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

    # aid=1340 confirmed in this APK — if snssdk473824:// failed, retry with snssdk1340://
    if "snssdk473824://" in url and any(
        kw in out.lower() for kw in ["not started", "unable to resolve", "error"]
    ):
        url1340 = url.replace("snssdk473824://", "snssdk1340://")
        print(f"[*] Retrying with snssdk1340://: {url1340[:120]}...")
        result2 = subprocess.run(
            ["adb", "-s", "localhost:5555", "shell",
             f"am start -a android.intent.action.VIEW -d '{url1340}'"],
            capture_output=True, text=True, check=False
        )
        out2 = (result2.stdout + result2.stderr).strip()
        print(f"[*] am start (snssdk1340): {out2}")


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
        if snssdk_url is None and "snssdk" in text:
            try:
                qs = parse_qs(text.lstrip("?"), keep_blank_values=True)
                val = qs.get("redirect_url", [None])[0]
                if val:
                    # parse_qs already decoded the outer percent-encoding once.
                    # Do NOT unquote again — inner params_url must stay encoded.
                    if val.startswith("snssdk"):
                        snssdk_url = val
                        print(f"[*] snssdk URL extracted via redirect_url ({len(snssdk_url)} chars)")
                elif text.startswith("snssdk"):
                    snssdk_url = text.strip()
                    print(f"[*] snssdk URL is bare ({len(snssdk_url)} chars)")
            except Exception:
                pass

        # Path 2: URL bar shows the incentive web page directly →
        # Use snssdk1340:// (aid=1340 confirmed for this APK build)
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
        # snssdk1340:// is the confirmed scheme for this APK (aid=1340)
        encoded = quote(incentive_url, safe='')
        deeplink = f"snssdk1340://roma_redirect/?params_url={encoded}"
        print(f"[*] Constructed snssdk1340 roma_redirect ({len(deeplink)} chars)")
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
