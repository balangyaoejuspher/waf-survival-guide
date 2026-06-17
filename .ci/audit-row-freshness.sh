#!/usr/bin/env bash
set -euo pipefail

# Verify every entry in EXCEPTIONS.md whose Review-by date has passed is
# either struck-through (~~...~~) or marked removed.
#
# Exit codes:
#   0 — no expired live rows
#   1 — one or more rows past Review-by date and still live

ledger="${1:-EXCEPTIONS.md}"
today="$(date -u +%Y-%m-%d)"

if [ ! -f "$ledger" ]; then
  echo "ERROR: ledger file not found: $ledger" >&2
  exit 2
fi

expired=$(
  awk -F'|' -v today="$today" '
    /^\|/ {
      # Skip header / separator / example rows.
      if ($0 ~ /-{3,}/) next
      if ($0 ~ /_example_/) next
      if ($0 ~ /~~/) next

      # Find a YYYY-MM-DD anywhere on the line; use the last one as Review-by.
      n = split($0, parts, /[[:space:]]+/)
      review = ""
      for (i = 1; i <= n; i++) {
        if (parts[i] ~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/) review = parts[i]
      }
      if (review != "" && review < today) {
        print "EXPIRED " review ": " $0
      }
    }
  ' "$ledger"
)

if [ -n "$expired" ]; then
  echo "The following EXCEPTIONS.md rows are past their Review-by date:" >&2
  echo "$expired" >&2
  echo >&2
  echo "Fix: either strike-through the row (~~...~~) and append a removal note," >&2
  echo "or bump Review-by with a one-line refresh note explaining why it stays." >&2
  exit 1
fi

echo "OK: no expired live rows in $ledger"
