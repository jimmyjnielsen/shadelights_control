#!/usr/bin/env python3
"""
Rotate the mid ring through the color wheel while keeping the top/bottom
zones at a steady warm white.

Usage:
    python3 color_wheel_demo.py [--host localhost] [--step 2] [--interval 100] [--peak 2500]

  --host      hostname or IP of the Pi running shade_api.py (default: localhost)
  --step      degrees to advance per send (default: 5 → ~24s per rotation)
              increase for a faster sweep: --step 15 gives ~8s per rotation
  --interval  milliseconds between sends (default: 300, minimum 200)
              below ~300ms the lamp drops commands and relay to other lamps breaks
  --peak      max channel value 0-4095 (default: 2500; lower = dimmer)
"""

import argparse, colorsys, time, urllib.request, json, sys

def post_color(host, top_warm, top_cold, bottom_warm, bottom_cold,
               mid_warm, mid_red, mid_green, mid_blue):
    body = json.dumps({
        "top_warm": top_warm, "top_cold": top_cold,
        "bottom_warm": bottom_warm, "bottom_cold": bottom_cold,
        "mid_warm": mid_warm, "mid_red": mid_red,
        "mid_green": mid_green, "mid_blue": mid_blue,
    }).encode()
    req = urllib.request.Request(
        f"http://{host}:8765/color",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        return r.status == 200

def hue_to_rgb12(hue_deg, peak):
    r, g, b = colorsys.hsv_to_rgb(hue_deg / 360.0, 1.0, 1.0)
    return int(r * peak), int(g * peak), int(b * peak)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host",     default="localhost")
    ap.add_argument("--step",     type=float, default=5.0,
                    help="hue degrees per send (default 5 → ~24s/rotation)")
    ap.add_argument("--interval", type=int,   default=300,
                    help="ms between sends, min 200 (default 300)")
    ap.add_argument("--peak",     type=int,   default=2500)
    args = ap.parse_args()

    interval_sec = max(0.20, args.interval / 1000.0)
    rot_sec = 360.0 / args.step * interval_sec

    TOP_WARM    = 2000
    BOTTOM_WARM = 1500

    print(f"Color wheel demo → http://{args.host}:8765")
    print(f"Step: {args.step}°  Interval: {interval_sec*1000:.0f}ms  "
          f"→ ~{rot_sec:.1f}s per rotation  Peak: {args.peak}")
    print("Ctrl+C to stop and restore the lamp to its last scene.\n")

    hue = 0.0
    try:
        while True:
            t0 = time.monotonic()
            r, g, b = hue_to_rgb12(hue, args.peak)
            ok = post_color(
                args.host,
                top_warm=TOP_WARM, top_cold=0,
                bottom_warm=BOTTOM_WARM, bottom_cold=0,
                mid_warm=0, mid_red=r, mid_green=g, mid_blue=b,
            )
            if not ok:
                sys.stdout.write("\r  [warn] request failed, continuing...\n")
            else:
                bar = int(hue / 10)
                sys.stdout.write(f"\r  hue={hue:5.1f}°  R={r:4d} G={g:4d} B={b:4d}  "
                                 f"[{'█'*bar}{'░'*(36-bar)}]")
                sys.stdout.flush()

            hue = (hue + args.step) % 360

            # Sleep only the time remaining in the interval (request time counts)
            elapsed = time.monotonic() - t0
            remaining = interval_sec - elapsed
            if remaining > 0:
                time.sleep(remaining)

    except KeyboardInterrupt:
        print("\n\nRestoring last scene...")
        req = urllib.request.Request(
            f"http://{args.host}:8765/scene/1",
            method="POST",
        )
        try:
            urllib.request.urlopen(req, timeout=15)
            print("Done.")
        except Exception as e:
            print(f"Could not restore scene: {e}")

if __name__ == "__main__":
    main()
