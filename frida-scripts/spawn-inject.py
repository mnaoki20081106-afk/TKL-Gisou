#!/usr/bin/env python3
"""Spawn TikTok Lite via frida-server, inject SSL bypass, resume."""
import frida
import time
import sys
import os

JS_PATH  = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tiktok-ssl-bypass.js")
PACKAGE  = "com.zhiliaoapp.musically.go"
LIFETIME = 180  # seconds to keep frida alive after resume


def on_message(message, data):
    if message.get("type") == "log":
        print(f"[script] {message.get('payload')}", flush=True)
    else:
        print(f"[frida] {message}", flush=True)


def get_device():
    dm = frida.get_device_manager()
    print("[*] Enumerating devices:", flush=True)
    for d in dm.enumerate_devices():
        print(f"    id={d.id!r}  name={d.name!r}  type={d.type!r}", flush=True)
    # -U equivalent: frida's USB transport covers both physical USB and adb-over-TCP
    try:
        dev = frida.get_usb_device(timeout=15)
        print(f"[*] Got USB device: {dev.id}", flush=True)
        return dev
    except Exception as e:
        print(f"[!] get_usb_device failed: {e}", flush=True)
    # fallback: first non-local device
    for d in dm.enumerate_devices():
        if d.type != "local":
            print(f"[*] Fallback device: {d.id}", flush=True)
            return d
    raise RuntimeError("No usb/remote device found")


def main():
    print(f"[*] frida {frida.__version__}", flush=True)
    device = get_device()
    print(f"[*] Device: {device.id} ({device.name})", flush=True)

    print(f"[*] Spawning {PACKAGE} ...", flush=True)
    pid = device.spawn([PACKAGE])
    print(f"[*] Spawned PID={pid}", flush=True)

    session = device.attach(pid)
    print(f"[*] Attached to PID={pid}", flush=True)

    with open(JS_PATH) as f:
        source = f.read()

    script = session.create_script(source)
    script.on("message", on_message)
    script.load()
    print("[*] Script loaded", flush=True)

    device.resume(pid)
    print("[*] App resumed — SSL bypass active", flush=True)

    time.sleep(LIFETIME)
    print("[*] Lifetime expired, exiting", flush=True)


if __name__ == "__main__":
    main()
