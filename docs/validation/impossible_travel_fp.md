# Impossible-travel rule: validation notes, accuracy limits and false positives

Rule: `impossible_travel` v1.1.0 (`detect/rules/impossible_travel.py`)

**Scope (v1.1.0):** only login events (`event_type == "auth"`) are used. v1.0.0 treated any
successful event with an account and IP as a login, so ordinary API calls made from two places
could be flagged (reproduced with the real CloudTrail parser). Covered by
`tests/test_event_type_filter.py`. The Loghub feasibility run in section 4 is SSH-only, so its
counts are unaffected.
Geolocation wrapper: `detect/geo.py`

## 1. What the rule does and what it does NOT claim

It flags two successful logins for one account, from different IPs, that are at least
`min_distance_km` (default 300) apart and would need an average speed above
`speed_threshold_kmh` (default 900) to cover in the time between them.

It does **not** prove that credentials were shared or stolen. Every distance and speed is an
**estimate** derived from IP geolocation, which has real accuracy limits (section 2). A finding is
a lead for an examiner, not a conclusion.

## 2. Geolocation source and known accuracy limits

* Source: an offline `.mmdb` City database (DB-IP "IP to City Lite" or MaxMind GeoLite2-City), read
  with the `geoip2` library. The database actually used is recorded in every finding
  (`geo_source`: file name, SHA-256, build time).
* Database used for the results below: **DB-IP "IP to City Lite", October 2026 release**
  (`dbip-city-lite-2026-10.mmdb`, build_epoch 1790818881, SHA-256 starts `9e250f02722d1ad1`),
  licensed CC BY 4.0. **IP geolocation by DB-IP.com** (attribution required; web pages that show
  results from it must link to https://db-ip.com).
* Free/offline databases are often wrong at city level, by tens to hundreds of km, and sometimes by
  a whole country (anycast, CDN and corporate ranges, recently reassigned blocks).
* `min_distance_km` (default 300) exists because of this error. It trades missed short real hops
  for fewer false alarms between two points that are really in the same area.
* Mobile carrier IPs usually resolve to the carrier's gateway, not the phone.
* VPN, proxy and Tor exits resolve to the exit node, not the person.
* IPv6 coverage is weaker than IPv4. Private, reserved and unknown addresses are not located; those
  logins are dropped and counted, never guessed.
* The 900 km/h and 300 km defaults are **starting points, not tuned values**. There is no labelled
  public dataset to tune them against (section 4).

## 3. Known false-positive scenarios

Each of these is demonstrated by a test in `tests/test_impossible_travel.py`
(the tests use a fake geolocator, so they show the rule's behaviour, not a database's accuracy).

| Scenario | Why it triggers | Demonstrated by | How an examiner tells it apart |
|---|---|---|---|
| VPN exit node | User logs in from home, then through a VPN whose exit is in another country minutes later | `test_FP_vpn_exit_node_same_user` (Johannesburg then Frankfurt, 5 min: flagged) | Second IP belongs to a known VPN/hosting provider; same user agent or session pattern |
| Mobile carrier NAT | Phone data egresses at the carrier's gateway, far from the user's wifi | `test_FP_mobile_carrier_nat_gateway` (Cape Town wifi then Johannesburg gateway, 2 min: flagged) | Second IP is in a carrier range; user switched network type |
| Shared corporate egress / shared service account | Colleagues in different offices use one account, or traffic leaves via a distant proxy | `test_FP_shared_corporate_egress_two_colleagues_one_service_account` (flagged) | Account is a service account; IPs are known office ranges |
| Nearby VPN exit, same metro area | Counter-case: should NOT fire | `test_NOT_FP_nearby_vpn_exit_under_min_distance_is_quiet` (~55 km: quiet) | n/a |

### Checked against a real geolocation database

The guardrail for this issue says a false-positive claim must be checked, not just asserted.
The unit tests above use a fake geolocator. Run the demo with the real database and record the result:

```
python detect/datasets/scripts/geo_fp_demo.py --geo-db <city.mmdb> --home-ip <your normal IP> --other-ip <a VPN exit you use> --minutes 5
```

| Scenario | Database | Cities the database gave | Distance (km) | Flagged? | Matches the note above? |
|---|---|---|---|---|---|
| VPN (home IP, then VPN exit) | n/a | not run (no VPN available to the tester) | n/a | n/a | n/a: covered only by the fake-geolocator unit test |
| Mobile data (wifi IP, then phone IP, 5 min apart) | DB-IP Lite 2026-10 | Wifi IP: approx. Gauteng (-25.976, 28.118); mobile IP: approx. Durban area (-29.853, 30.998) | 516 | **Yes**: 6,188 km/h implied | **Yes**: the carrier's IP resolved about 516 km from the real position and the rule flagged a benign switch from wifi to mobile data, as predicted |

Do not commit your own IP addresses; record cities and results only.

## 4. Validation on a public dataset

**Limitation: no public labelled data is available for this rule, so precision and recall are not measured.**
Public authentication logs either use internal hostnames that cannot be geolocated or are synthetic.
Scoring against the team's own synthetic travel would be circular.

What can be done is a feasibility run on the public Loghub OpenSSH log (CC BY 4.0, see
`brute_force_fp.md` for the citation). It reports counts, not accuracy:

```
python detect/datasets/scripts/validate_impossible_travel.py <SSH.log> --year 2015 --geo-db <city.mmdb>
```

Dataset SHA-256: `89eee9e36c182722f9fadc6e5617a4818ffc66109e7e222b8f9e8b78fc3aa2f3`
(655,147 lines, 160,609 failure/success events). The log has no year and no timezone, so 2015 and UTC
are assumptions; only the gaps between logins matter here.

* Accounts with a successful login: 9. Accounts with successes from 2 or more IPs: 6.
* 182 successful logins, all 182 located by the database (0 unlocatable).
* 173 consecutive pairs compared; 114 were the same IP (ignored).

| speed_kmh | min_distance_km | pairs compared | same IP | below min distance | evaluated | flagged |
|---|---|---|---|---|---|---|
| 500 | 100 | 173 | 114 | 28 | 31 | 9 |
| 500 | 300 | 173 | 114 | 35 | 24 | 8 |
| 500 | 500 | 173 | 114 | 35 | 24 | 8 |
| 900 | 100 | 173 | 114 | 28 | 31 | 8 |
| **900 (default)** | **300 (default)** | 173 | 114 | 35 | 24 | **8** |
| 900 | 500 | 173 | 114 | 35 | 24 | 8 |
| 1500 | 100 | 173 | 114 | 28 | 31 | 7 |
| 1500 | 300 | 173 | 114 | 35 | 24 | 7 |
| 1500 | 500 | 173 | 114 | 35 | 24 | 7 |

**How to read this.** With the default settings the rule flagged 8 of 173 consecutive login pairs. The
count barely moves across the grid (7 to 9), so the result is not sensitive to the exact thresholds on
this data. **We cannot say whether the 8 are real anomalies or benign** (VPNs, travel, shared accounts):
Loghub has no travel labels and is a single lab server, so precision and recall are not measurable and
none are claimed. Only 9 accounts are involved, so this shows the rule runs on real public logs and
produces a small, reviewable number of leads, not that it is accurate. All figures also inherit the
geolocation limits in section 2.

## 5. Provenance

Same shape as `brute_force_login`, stored by `detect/findings.py`:

* `input_hash` is the hash of only the two login events examined.
* `finding_hash` covers the whole finding, including config, rule version, coordinates used and
  `geo_source`. A different database or coordinate gives a different hash.
* `source_events` link to the exact evidence lines (`raw_ref`).
* Severity is always `medium`, because geolocation is too imprecise to justify higher.

### Note on the mobile-data result

The real result clears the default `min_distance_km` of 300 by only about 216 km. Raising it to 600
would have silenced this particular false positive, at the cost of also missing genuine logins from
two places 300 to 600 km apart. This is the trade-off described in section 2, now seen on real data.