"""CLF loader tests. Lines imitate the format; they are not copied data."""
import gzip
import hashlib

from detect.datasets.clf import parse_clf

OK = '199.72.81.55 - - [01/Jul/1995:00:00:01 -0400] "GET /history/apollo/ HTTP/1.0" 200 6245'
NOBYTES = 'host.example - - [01/Jul/1995:00:00:09 -0400] "GET /x HTTP/1.0" 304 -'
BAD = 'host.example - - [01/Jul/1995:00:00:12 -0400] "GET /y HTTP/1.0" 404 -'
ODD = 'burger.letters.com - - [01/Jul/1995:00:00:11 -0400] "GET /shuttle/ HTTP/1.0" 200 0'


def write(tmp_path, lines, name="log.txt"):
    p = tmp_path / name
    p.write_bytes(("\n".join(lines) + "\n").encode("latin-1"))
    return p


def test_success_line_becomes_a_volume_event_in_utc(tmp_path):
    e = parse_clf(write(tmp_path, [OK])).events[0]
    assert (e["event_type"], e["outcome"], e["account"], e["bytes_out"]) == ("data_access", "success", "199.72.81.55", 6245)
    assert e["timestamp_utc"] == "1995-07-01T04:00:01+00:00"          # -0400 -> UTC


def test_dash_bytes_and_error_statuses_carry_no_volume(tmp_path):
    ev = parse_clf(write(tmp_path, [NOBYTES, BAD])).events
    assert [e["bytes_out"] for e in ev] == [None, None]
    assert [e["outcome"] for e in ev] == ["failure", "failure"]       # 304 and 404 are not 2xx


def test_zero_byte_success_is_kept_as_zero(tmp_path):
    assert parse_clf(write(tmp_path, [ODD])).events[0]["bytes_out"] == 0


def test_unparseable_lines_are_counted_not_crashed(tmp_path):
    r = parse_clf(write(tmp_path, ["garbage", OK, 'x - - [bad] "GET" 200 1']))
    assert (r.total_lines, r.unparsed_lines, len(r.events)) == (3, 2, 1)


def test_line_numbers_and_ids_are_deterministic(tmp_path):
    p = write(tmp_path, ["junk", OK])
    a, b = parse_clf(p), parse_clf(p)
    assert a.events[0]["raw_ref"] == "line:2" and a.events == b.events


def test_evidence_id_is_sha256_of_the_file_as_given_and_gz_works(tmp_path):
    p = write(tmp_path, [OK])
    assert parse_clf(p).evidence_id == hashlib.sha256(p.read_bytes()).hexdigest()
    g = tmp_path / "log.gz"
    g.write_bytes(gzip.compress(p.read_bytes()))
    r = parse_clf(g)
    assert r.evidence_id == hashlib.sha256(g.read_bytes()).hexdigest() and len(r.events) == 1