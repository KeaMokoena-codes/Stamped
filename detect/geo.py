"""
IP geolocation for the impossible-travel rule: a thin wrapper over an OFFLINE
MaxMind-format (.mmdb) city database.

The rule never imports this module. It takes a plain function
    geolocate(ip: str) -> (lat, lon) | None
plus a `geo_info` dict describing the database, so the rule stays pure and can
be tested with a fake geolocator. This module builds both from a database file.

SUPPORTED DATABASES (anything in the GeoIP2/GeoLite2 "City" .mmdb layout)
  * DB-IP "IP to City Lite"     (check the current licence/attribution terms)
  * MaxMind GeoLite2-City       (needs a free MaxMind account and licence key)
The file is large and separately licensed: do NOT commit it (see .gitignore).

PROVENANCE
  geo_info = {"source": <file name>, "sha256": <hash of the file>,
              "build_epoch": <database build time, if the file states it>}
  The rule stores geo_info and the coordinates it used inside every finding, so
  the finding hash changes if the database (or a coordinate) changes. Without
  this a finding could not be reproduced after a database update.

ACCURACY LIMITS (state these whenever a result is quoted)
  * Free/offline databases are commonly wrong at city level, by tens to
    hundreds of km, and sometimes by a whole country (anycast, CDN and
    corporate ranges, recently reassigned blocks).
  * Mobile carrier IPs usually resolve to the carrier's gateway, not the phone.
  * VPN, proxy and Tor exits resolve to the exit node, not the person.
  * IPv6 coverage is weaker than IPv4.
  A distance computed from these coordinates is an estimate, never a measurement.
"""
from __future__ import annotations

import hashlib
import ipaddress
from functools import lru_cache
from pathlib import Path


def is_public_ip(ip: str) -> bool:
    """True only for globally routable addresses. Private, loopback, link-local,
    CGNAT, multicast, reserved and unparseable values are not geolocatable."""
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def open_geo(db_path):
    """Return (geolocate, geo_info) for an .mmdb city database.

    Raises ImportError with install instructions if `geoip2` is missing, and
    FileNotFoundError if the database file is absent. It never falls back to a
    guess or a bundled fake: no database means no impossible-travel result.
    """
    try:
        import geoip2.database
        import geoip2.errors
    except ImportError as e:  # pragma: no cover - environment dependent
        raise ImportError("impossible_travel needs the 'geoip2' package: pip install geoip2") from e

    path = Path(db_path)
    if not path.is_file():
        raise FileNotFoundError(f"geolocation database not found: {path}")

    reader = geoip2.database.Reader(str(path))
    meta = reader.metadata()
    geo_info = {
        "source": path.name,
        "sha256": _file_sha256(path),
        "build_epoch": getattr(meta, "build_epoch", None),
    }

    @lru_cache(maxsize=None)
    def geolocate(ip: str):
        if not is_public_ip(ip):
            return None
        try:
            loc = reader.city(ip).location
        except (geoip2.errors.AddressNotFoundError, ValueError):
            return None
        if loc.latitude is None or loc.longitude is None:
            return None
        return (float(loc.latitude), float(loc.longitude))

    return geolocate, geo_info