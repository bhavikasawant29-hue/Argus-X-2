"""Live verification of vulnerability correlation endpoint and demo pipeline integration."""
import requests, sys, time

BASE = "http://127.0.0.1:8000"
failures = []

def check(label, cond, detail=""):
    if cond:
        print(f"  PASS: {label}")
    else:
        print(f"  FAIL: {label}{' -- ' + detail if detail else ''}")
        failures.append(label)

# Wait for server
for _ in range(10):
    try:
        requests.get(f"{BASE}/api/health", timeout=2)
        break
    except Exception:
        time.sleep(1)

# 1. Health
r = requests.get(f"{BASE}/api/health", timeout=5)
check("Health endpoint up", r.status_code == 200)

# 2. Correlate endpoint structure
r = requests.post(f"{BASE}/api/vulnerabilities/correlate", timeout=60)
check("POST /api/vulnerabilities/correlate returns 200", r.status_code == 200,
      f"got {r.status_code}: {r.text[:200]}")
if r.status_code == 200:
    d = r.json()
    check("Response has 'correlations' key", "correlations" in d)
    check("Response has 'summary' key", "summary" in d)
    check("Response has 'disclaimer' key", "disclaimer" in d)
    s = d.get("summary", {})
    check("Summary has 'total'", "total" in s)
    check("Summary has 'evidence_supported'", "evidence_supported" in s)
    check("Summary has 'plausible_correlation'", "plausible_correlation" in s)
    check("Summary has 'unverified'", "unverified" in s)

    corrs = d.get("correlations", [])
    print(f"\n  Correlations found: {s.get('total', 0)}")
    print(f"  evidence_supported={s.get('evidence_supported', 0)}, "
          f"plausible={s.get('plausible_correlation', 0)}, "
          f"unverified={s.get('unverified', 0)}")

    # Check each correlation record has required fields
    for c in corrs:
        for field in ("cve_id", "host", "correlation_status", "rationale",
                      "related_attack_event_ids", "related_attack_stages"):
            check(f"Correlation {c.get('cve_id','?')}/{c.get('host','?')} has '{field}'",
                  field in c)
        check(f"Correlation status is valid category",
              c.get("correlation_status") in ("evidence_supported", "plausible_correlation", "unverified"))

    # Print correlation summary for each
    print()
    for c in corrs:
        print(f"    [{c['correlation_status'].upper()[:8]}] {c['cve_id']} @ {c['host']}")
        print(f"      product={c.get('product')}, version={c.get('version')}, cvss={c.get('cvss_score')}")
        print(f"      KEV={c.get('known_exploited')}, stages={c.get('related_attack_stages')}")
        print(f"      rationale: {c.get('rationale', '')[:100]}...")
        print()

# 3. Demo includes vuln_correlations
r2 = requests.post(f"{BASE}/api/demo", timeout=60)
check("POST /api/demo returns 200", r2.status_code == 200)
if r2.status_code == 200:
    d2 = r2.json()
    check("/api/demo includes 'vuln_correlations'", "vuln_correlations" in d2)
    check("/api/demo summary includes 'vuln_correlations_total'", "vuln_correlations_total" in d2.get("summary", {}))

# 4. Verify analyze-log is still absent
r3 = requests.post(f"{BASE}/api/ml/analyze-log", json={"text": "test"}, timeout=5)
check("analyze-log endpoint remains absent (404)", r3.status_code == 404)

# 5. Vuln correlations not in OpenAPI spec paths for HF
oa = requests.get(f"{BASE}/openapi.json", timeout=5).json()
paths = list(oa.get("paths", {}).keys())
check("/api/vulnerabilities/correlate in OpenAPI spec", "/api/vulnerabilities/correlate" in paths)
check("No HF analyze-log in OpenAPI spec", "/api/ml/analyze-log" not in paths)

print(f"\n{'='*60}")
if failures:
    print(f"FAILED: {len(failures)} check(s): {failures}")
    sys.exit(1)
else:
    print(f"ALL LIVE CHECKS PASSED")
