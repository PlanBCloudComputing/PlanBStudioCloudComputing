#!/bin/sh
# check-authors.sh: pre-submission audit of commit authorship.
# List commit identities and check the single-author convention.
# Usage:  sh scripts/check-authors.sh

echo "Commit authors (count, name <email>):"
git log --all --format='%an <%ae>' | sort | uniq -c | sort -rn

echo
echo "Committers (count, name <email>):"
git log --all --format='%cn <%ce>' | sort | uniq -c | sort -rn

echo
BAD=$(git log --all --format='%H %an <%ae> | %cn <%ce>%n%B' | grep -Ei 'co-authored-by')
if [ -n "$BAD" ]; then
  echo "FAIL: found Co-Authored-By trailers in history:" >&2
  echo "$BAD" >&2
  exit 1
fi

echo "OK: no Co-Authored-By trailers found. Confirm the authors above are only Alvi, Katie and Steven."
exit 0
