"""Generates docker-compose.yml for N_SITES site containers + 1 evidence
container. Regenerate with `python3 generate_compose.py > docker-compose.yml`
if N_SITES changes."""
import os

N_SITES = int(os.environ.get("DIB_DIST_N_SITES", "10"))

lines = ["services:", "  evidence:", "    build:", "      context: ../../../..",
         "      dockerfile: src/dib/registry/distributed/Dockerfile", "    environment:",
         "      - DIB_DIST_ROLE=evidence", f"      - DIB_DIST_N_SITES={N_SITES}",
         "      - DIB_DIST_DATA_DIR=/data"]
for i in range(N_SITES):
    lines += [f"      - DIB_DIST_SITE_URL_{i}=http://site-{i}:8000"]
lines += ["    volumes:", "      - evidence_data:/data",
          "    ports:", "      - \"18100:8000\""]

for i in range(N_SITES):
    lines += [
        f"  site-{i}:", "    build:", "      context: ../../../..",
         "      dockerfile: src/dib/registry/distributed/Dockerfile", "    environment:",
        "      - DIB_DIST_ROLE=site", f"      - DIB_DIST_SITE_INDEX={i}",
        f"      - DIB_DIST_N_SITES={N_SITES}", "      - DIB_DIST_EVIDENCE_URL=http://evidence:8000",
        "      - DIB_DIST_DATA_DIR=/data", "    volumes:", f"      - site_{i}_data:/data",
        "    depends_on:", "      - evidence",
        "    ports:", f"      - \"{18110 + i}:8000\"",
    ]

lines += ["volumes:", "  evidence_data:"]
for i in range(N_SITES):
    lines += [f"  site_{i}_data:"]

print("\n".join(lines))
