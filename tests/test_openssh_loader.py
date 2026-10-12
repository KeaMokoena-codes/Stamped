"""Loader and weak-label tests. Lines mimic the sshd format; they are not copied data."""
import hashlib

from detect.datasets.openssh import parse_openssh
from detect.validation import score_labeled


def write(tmp_path, lines, crlf=False):
    p = tmp_path / "ssh.log"
    p.write_bytes(("\r\n" if crlf else "\n").join(lines).encode() + b"\n")
    return p


FAIL = "Dec 10 06:55:46 H sshd[1]: Failed password for root from 1.2.3.4 port 5000 ssh2"
FAIL_INV = "Dec 10 06:55:47 H sshd[1]: Failed password for invalid user bob from 1.2.3.4 port 5001 ssh2"
OK = "Dec 10 06:56:00 H sshd[2]: Accepted password for alice from 9.9.9.9 port 6000 ssh2"
INV = "Dec 10 06:55:46 H sshd[1]: Invalid user webmaster from 7.7.7.7"
NOISE = [
    "Dec 10 06:55:46 H sshd[1]: pam_unix(sshd:auth): authentication failure; rhost=1.2.3.4  user=root",
    "Dec 10 06:55:46 H sshd[1]: Failed none for invalid user x from 1.2.3.4 port 1 ssh2",
    "Dec 10 06:55:46 H sshd[1]: Received disconnect from 1.2.3.4: 11: Bye Bye [preauth]",
]


def test_failures_and_successes_become_events(tmp_path):
    r = parse_openssh(write(tmp_path, [FAIL, FAIL_INV, OK]), 2015)
    assert [e.outcome for e in r.events] == ["failure", "failure", "success"]
    assert r.events[1].account == "bob" and r.events[1].source_ip == "1.2.3.4"


def test_pam_none_and_disconnect_lines_are_not_counted(tmp_path):
    r = parse_openssh(write(tmp_path, [FAIL] + NOISE), 2015)
    assert len(r.events) == 1


def test_handles_crlf_line_endings(tmp_path):
    assert len(parse_openssh(write(tmp_path, [FAIL, OK], crlf=True), 2015).events) == 2


def test_raw_ref_is_exact_line_number_and_event_id_deterministic(tmp_path):
    p = write(tmp_path, [NOISE[0], FAIL])
    a, b = parse_openssh(p, 2015), parse_openssh(p, 2015)
    assert a.events[0].raw_ref == "line:2"
    assert a.events[0].event_id == b.events[0].event_id


def test_evidence_id_is_sha256_of_file_bytes(tmp_path):
    p = write(tmp_path, [FAIL])
    assert parse_openssh(p, 2015).evidence_id == hashlib.sha256(p.read_bytes()).hexdigest()


def test_year_rolls_over_when_month_decreases(tmp_path):
    jan = "Jan 02 00:00:01 H sshd[1]: Failed password for root from 1.2.3.4 port 5 ssh2"
    r = parse_openssh(write(tmp_path, [FAIL, jan]), 2015)
    assert r.events[0].timestamp_utc.startswith("2015-12-10")
    assert r.events[1].timestamp_utc.startswith("2016-01-02")


def test_unparseable_lines_are_counted_not_crashed(tmp_path):
    r = parse_openssh(write(tmp_path, ["garbage", FAIL]), 2015)
    assert r.unparsed_lines == 1 and len(r.events) == 1


def test_weak_labels(tmp_path):
    r = parse_openssh(write(tmp_path, [FAIL_INV, INV, OK]), 2015)
    assert r.malicious_ips == {"1.2.3.4", "7.7.7.7"}
    assert r.benign_ips == {"9.9.9.9"}


def test_ip_with_accepted_and_invalid_user_is_not_benign(tmp_path):
    ok_same = "Dec 10 06:56:00 H sshd[2]: Accepted password for alice from 7.7.7.7 port 6000 ssh2"
    r = parse_openssh(write(tmp_path, [INV, ok_same]), 2015)
    assert "7.7.7.7" in r.malicious_ips and "7.7.7.7" not in r.benign_ips


def f(key):
    return {"grouped_by": "source_ip", "key": key}


def test_score_labeled_excludes_unlabelled_from_precision():
    r = score_labeled([f("a"), f("b"), f("u")], {"a", "c"}, {"b"})
    assert (r["tp"], r["fp"], r["fn"], r["unlabelled_flagged"]) == (1, 1, 1, 1)
    assert r["precision"] == 0.5 and r["recall"] == 0.5


def test_score_labeled_reports_label_counts():
    r = score_labeled([], {"a", "b"}, {"c"})
    assert (r["n_malicious"], r["n_benign"]) == (2, 1) and r["precision"] is None