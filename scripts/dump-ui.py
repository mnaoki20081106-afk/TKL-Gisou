#!/usr/bin/env python3
"""Print all text nodes from a uiautomator dump XML."""
import sys, xml.etree.ElementTree as ET

xml_path = sys.argv[1] if len(sys.argv) > 1 else "ui_dump.xml"
try:
    for node in ET.parse(xml_path).iter("node"):
        t = ((node.get("text") or "") + " " + (node.get("content-desc") or "")).strip()
        if t:
            c = "[TAP]" if node.get("clickable") == "true" else "[txt]"
            print(f"  {c} {t!r} {node.get('bounds','')}")
except Exception as e:
    print(f"(ui_dump parse error: {e})")
