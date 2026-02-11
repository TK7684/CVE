#!/bin/bash
set -e

echo "[*] Checking for Nuclei Template Updates..."
# Update templates (stored in volume /root/nuclei-templates)
nuclei -update-templates -silent

echo "[*] Starting The Hunter's Loop..."
exec "$@"
