"""Tests for detect/geo.py against a tiny .mmdb built on the fly.

The database is synthetic, so this checks the WRAPPER (lookup, skipping of
private/unknown IPs, provenance), not real-world geolocation accuracy.
Skipped when the optional packages are not installed (pip install geoip2 mmdb-writer netaddr).
"""
import hashlib
from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("geoip2")
mmdb_writer = pytest.importorskip("mmdb_writer")
netaddr = pytest.importorskip("netaddr")

from detect.geo import is_public_ip, open_geo                       # noqa: E402
from detect.rules.impossible_travel import TravelConfig, detect_impossible_travel  # noqa: E402


@pytest.fixture
def mmdb(tmp_path):
    w = mmdb_writer.MMDBWriter(ip_version=4, database_type="GeoIP2-City", languages=["en"],
                               description={"en": "stamped test db"})
    w.insert_network(netaddr.IPSet(["8.8.8.0/24"]), {"location": {"latitude": 37.386, "longitude": -122.0838}})
    w.insert_network(netaddr.IPSet(["9.9.9.0/24"]), {"location": {"latitude": 50.1109, "longitude": 8.6821}})
    w.insert_network(netaddr.IPSet(["1.1.1.0/24"]), {"country": {"iso_code": "AU"}})   # no coordinates
    path = tmp_path / "test-city.mmdb"
    w.to_db_file(str(path))
    return path


def test_is_public_ip():
    assert is_public_ip("8.8.8.8")
    for ip in ("10.0.0.1", "192.168.1.5", "127.0.0.1", "169.254.0.1", "100.64.0.1", "not-an-ip", ""):
        assert not is_public_ip(ip)


def test_lookup_returns_coordinates_and_none_for_unknown(mmdb):
    geolocate, _ = open_geo(mmdb)
    assert geolocate("8.8.8.8") == pytest.approx((37.386, -122.0838))
    assert geolocate("7.7.7.7") is None          # not in database
    assert geolocate("10.1.2.3") is None         # private: never looked up
    assert geolocate("1.1.1.1") is None          # record without coordinates


def test_geo_info_records_database_identity(mmdb):
    _, info = open_geo(mmdb)
    assert info["source"] == "test-city.mmdb"
    assert info["sha256"] == hashlib.sha256(mmdb.read_bytes()).hexdigest()
    assert "build_epoch" in info


def test_missing_database_raises_not_guesses(tmp_path):
    with pytest.raises(FileNotFoundError):
        open_geo(tmp_path / "nope.mmdb")


def test_rule_end_to_end_with_real_mmdb_reader(mmdb):
    geolocate, info = open_geo(mmdb)
    t0 = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)
    events = [
        {"event_id": f"e{i}", "evidence_id": "E1", "raw_ref": f"line:{i}", "outcome": "success",
         "timestamp_utc": (t0 + timedelta(minutes=5 * i)).isoformat(), "account": "alice", "source_ip": ip}
        for i, ip in enumerate(["8.8.8.8", "9.9.9.9"])]
    f = detect_impossible_travel(events, TravelConfig(), geolocate, info)
    assert len(f) == 1 and f[0]["geo_source"]["sha256"] == info["sha256"]
    assert f[0]["distance_km"] == pytest.approx(9100, abs=300)