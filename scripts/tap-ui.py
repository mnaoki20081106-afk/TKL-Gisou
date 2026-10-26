#!/usr/bin/env python3
"""Parse uiautomator dump XML and tap the invite accept button via adb."""
import subprocess, sys, re, xml.etree.ElementTree as ET

KEYWORDS = [
    "コイン", "受け取", "accept", "claim", "start",
    "始め", "参加", "ポイント", "get", "scan",
    "今すぐ", "利用", "開く", "open",
]

def main():
    xml_path = sys.argv[1] if len(sys.argv) > 1 else "ui_dump.xml"
    try:
        tree = ET.parse(xml_path)
    except Exception as e:
        print(f"[!] XML parse failed: {e}")
        return

    hits = []
    print("=== All text nodes ===")
    for node in tree.iter("node"):
        text = ((node.get("text") or "") + " " + (node.get("content-desc") or "")).strip()
        bounds = node.get("bounds", "")
        clickable = node.get("clickable") == "true"
        if text:
            print(f"  {'[TAP]' if clickable else '[txt]'} {text!r:60s} {bounds}")
        if bounds and any(k.lower() in text.lower() for k in KEYWORDS):
            m = re.findall(r'\d+', bounds)
            if len(m) == 4:
                x = (int(m[0]) + int(m[2])) // 2
                y = (int(m[1]) + int(m[3])) // 2
                hits.append((text, x, y, clickable))

    print()
    if hits:
        text, x, y, _ = hits[0]
        print(f"[*] Keyword match: {text!r} -> tapping ({x},{y})")
        subprocess.run(
            ["adb", "-s", "localhost:5555", "shell", f"input tap {x} {y}"],
            check=False,
        )
        print("[*] Tap sent")
    else:
        print("[!] No keyword match in UI -- skipping tap (check ui_dump.xml artifact)")

if __name__ == "__main__":
    main()
