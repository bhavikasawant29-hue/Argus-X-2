from ingestion.vulnerability_loader import ingest_nvd

recs, statuses = ingest_nvd(["CVE-2021-44228"])
rec = recs[0]
prods = rec["affected_products"]
log4j_prods = [p for p in prods if "log4j" in (p.get("product") or "").lower()]
print("Log4j products in NVD record:", len(log4j_prods))
for p in log4j_prods[:10]:
    print(p)
