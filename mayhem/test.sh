#!/usr/bin/env bash
#
# mayhem/test.sh — run the NAS codec known-answer suite built by mayhem/build.sh
# (mayhem/nas_kat.cpp: upstream's captured UE packets, decoded field values asserted,
# 4G messages re-encoded and compared byte for byte). Upstream's gtest suites need the
# full Bazel MME build (protobuf, ITTI, mme_config), so they are not run here.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

RUNNER="$SRC/mayhem/build/nas_kat"
EXPECTED=9
if [ ! -x "$RUNNER" ]; then
  echo "test.sh: $RUNNER missing — mayhem/build.sh did not build it" >&2
  emit_ctrf "nas_kat" 0 "$EXPECTED"
  exit 1
fi
out=$("$RUNNER" 2>&1); rc=$?
echo "$out"
passed=$(grep -c '^PASS ' <<<"$out" || true)
failed=$(grep '^FAIL ' <<<"$out" | awk '{print $2}' | sort -u | wc -l)
# Cases that never reported (runner died or was neutered) count as failed.
missing=$(( EXPECTED - passed - failed ))
[ "$missing" -gt 0 ] && failed=$(( failed + missing ))
[ "$rc" -ne 0 ] && [ "$failed" -eq 0 ] && failed=1
emit_ctrf "nas_kat" "$passed" "$failed"
