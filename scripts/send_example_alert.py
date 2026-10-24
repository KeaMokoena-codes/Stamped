"""
Demo trigger for the capture listener: posts an example evidence bundle to it.

  python schemas/init_db.py
  python -m capture.listener --staging-root data/sample      # terminal 1
  python scripts/send_example_alert.py                       # terminal 2

Standard library only. It is not an alert source and it talks to nothing but the
listener URL you give it. Exit code: 0 on a 2xx response, 1 otherwise.
"""
import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

DEFAULT_BUNDLE = Path(__file__).resolve().parent.parent / "data" / "sample" / "bundle_example.json"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="POST an evidence bundle to a running capture listener.")
    parser.add_argument("--url", default="http://127.0.0.1:5000/alert")
    parser.add_argument("--bundle", type=Path, default=DEFAULT_BUNDLE, help="bundle JSON file to send")
    args = parser.parse_args(argv)

    try:
        body = args.bundle.read_bytes()
    except OSError as exc:
        print(f"Cannot read {args.bundle}: {exc}", file=sys.stderr)
        return 1

    request = urllib.request.Request(args.url, data=body, method="POST",
                                     headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            status, payload = response.status, response.read()
    except urllib.error.HTTPError as exc:
        status, payload = exc.code, exc.read()
    except urllib.error.URLError as exc:
        print(f"Could not reach {args.url}: {exc.reason}. Is the listener running?", file=sys.stderr)
        return 1

    print(f"HTTP {status}")
    try:
        print(json.dumps(json.loads(payload), indent=2))
    except ValueError:
        print(payload.decode("utf-8", "replace"))
    return 0 if 200 <= status < 300 else 1


if __name__ == "__main__":
    sys.exit(main())