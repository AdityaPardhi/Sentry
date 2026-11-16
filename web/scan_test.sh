#!/bin/bash
# Use the already-running server on port 8080
PORT=8080
PROJ=/mnt/c/Projects/Sentry-restored
BASE=http://127.0.0.1:$PORT
BINDIR=$PROJ/bin

# Get token from live page
TOKEN=$(curl -s "$BASE/" | python3 -c "
import sys, re
html = sys.stdin.read()
m = re.search(r'const SENTRY_TOKEN = \"([^\"]+)\"', html)
print(m.group(1) if m else 'NOTFOUND')
")
echo "TOKEN: $TOKEN"

echo "--- HEALTH ---"
curl -s -H "X-Sentry-Token: $TOKEN" -H "Host: 127.0.0.1:$PORT" "$BASE/api/health"
echo ""

for FNAME in t1_clean t3_secret_reader t4_network t5_spawner; do
  FP=$BINDIR/$FNAME
  echo ""
  echo "======== $FNAME ========"
  echo "FILE_SHA256: $(sha256sum $FP)"
  echo "--- curl /api/scan ---"
  curl -s --max-time 90 -X POST \
    -H "X-Sentry-Token: $TOKEN" \
    -H "Host: 127.0.0.1:$PORT" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@$FP" \
    "$BASE/api/scan?name=$FNAME" \
    2>&1
  echo ""
done
