#!/bin/sh
set -eu

cd "$(dirname "$0")/.."
mkdir -p data

nmap_revision=6b9d95c5f12efd9d53491b82a27423e0899b212b
curl --fail --location --retry 2 --connect-timeout 10 --max-time 120 \
  "https://raw.githubusercontent.com/nmap/nmap/$nmap_revision/nmap-service-probes" \
  --output data/nmap-service-probes
