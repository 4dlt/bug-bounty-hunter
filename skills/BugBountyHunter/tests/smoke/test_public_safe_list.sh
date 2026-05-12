#!/usr/bin/env bash
# A2 smoke test — PublicSafeList.yaml schema, known-safe entries,
# regex validity, and per-entry positive/negative sample validation.
set -euo pipefail
SKILL_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
LIST="$SKILL_DIR/config/PublicSafeList.yaml"
YAML2JSON="$SKILL_DIR/lib/yaml2json.sh"

test -f "$LIST" || { echo "FAIL: PublicSafeList.yaml missing"; exit 1; }

JSON=$("$YAML2JSON" < "$LIST")

COUNT=$(echo "$JSON" | jq '.known_safe_by_design | length')
[[ "$COUNT" -ge 10 ]] || { echo "FAIL: need >=10 entries, got $COUNT"; exit 1; }

# Must include the Apr-18 offenders + broader public-safe canon
for k in datadog_rum_client_token git_commit_sha_header robots_txt_paths sentry_dsn_public google_analytics_id stripe_publishable_key; do
  echo "$JSON" | jq -e --arg k "$k" '.known_safe_by_design[] | select(.id == $k)' > /dev/null \
    || { echo "FAIL: missing entry id=$k"; exit 1; }
done

# Every entry needs id, pattern, note — all non-empty strings
echo "$JSON" | jq -e '.known_safe_by_design | all(
  (.id | type) == "string" and (.id | length) > 0 and
  (.pattern | type) == "string" and (.pattern | length) > 0 and
  (.note | type) == "string" and (.note | length) > 0
)' > /dev/null || { echo "FAIL: entry missing id/pattern/note or empty"; exit 1; }

# IDs must be unique (no duplicate entries)
DUP=$(echo "$JSON" | jq '[.known_safe_by_design[].id] | (length - (unique | length))')
[[ "$DUP" == "0" ]] || { echo "FAIL: duplicate ids in known_safe_by_design"; exit 1; }

# Patterns must be valid Python regex (compile them)
echo "$JSON" | jq -r '.known_safe_by_design[] | "\(.id)\t\(.pattern)"' | while IFS=$'\t' read -r pid pat; do
  python3 -c "import re, sys; re.compile(sys.argv[1], re.MULTILINE)" "$pat" 2>/dev/null \
    || { echo "FAIL: pattern for $pid is not a valid regex"; exit 1; }
done

# Positive/negative sample validation: each entry's pattern must match its positive
# samples and MUST NOT match any negative sample. Negative samples catch collision
# bugs like reCAPTCHA-site-vs-secret that the A2 review found.
#
# Format: id|positive_sample|negative_sample_or_empty
# Multiple positives allowed by repeating the row.
python3 - "$LIST" <<'PYEOF' || exit 1
import re, sys, yaml

SAMPLES = [
    # (id, positive, negative_or_None)
    ("datadog_rum_client_token", "datadog clientToken=pub1234567890abcdef1234567890abcdef", None),
    ("datadog_rum_client_token", "pub0123456789abcdef0123456789abcdef", "publishing_hash=xyz"),
    ("sentry_dsn_public", "https://abc123@o12345.ingest.sentry.io/67890", None),
    ("google_analytics_id", "G-ABCDEFGHIJ", None),
    ("google_analytics_id", "UA-12345-1", None),
    ("google_analytics_id", "GTM-ABC123", None),
    ("stripe_publishable_key", "pk_live_ABCdef1234567890ABCdef12", None),
    ("stripe_publishable_key", "pk_test_ABCdef1234567890ABCdef12", "sk_live_ABCdef1234567890ABCdef12"),
    ("git_commit_sha_header", "X-Git-SHA: abc123def456", None),
    ("git_commit_sha_header", "X-Build-ID: build-42", None),
    ("robots_txt_paths", "User-agent: *\nDisallow: /admin\nAllow: /public", None),
    ("cloudfront_distribution_id", "d1234abcd5678.cloudfront.net", None),
    ("cloudfront_distribution_id", "E1A2B3C4D5E6F7.cloudfront.net", None),
    ("rum_or_synthetic_ids", "rum_token=abc", "drum_id=2"),
    ("rum_or_synthetic_ids", "rum-key=xyz", "scrum_token=xyz"),
    ("segment_write_key", "segment.writeKey = 'abc'", "the auth segment exposes a JWT writeKey"),
    ("segment_write_key", "segment_writeKey: MyKey", None),
    ("intercom_app_id", "intercom.app_id = 'ab12cd34'", "intercom mentioned once with nothing about app_id elsewhere"),
    ("intercom_app_id", "Intercom('ab12cd34')", None),
    ("mapbox_public_token", "pk.eyJ" + "a"*80, "pk.eyJx"),
    ("azure_app_insights_instrumentation_key", "InstrumentationKey=12345678-1234-1234-1234-123456789abc", "InstrumentationKey=tooshort"),
]

data = yaml.safe_load(open(sys.argv[1]))
patterns = {e["id"]: e["pattern"] for e in data["known_safe_by_design"]}

failures = []
for sid, pos, neg in SAMPLES:
    if sid not in patterns:
        # Entry was removed deliberately; sample is obsolete — skip silently
        continue
    pat = patterns[sid]
    if not re.search(pat, pos, re.MULTILINE):
        failures.append(f"  - {sid}: positive sample did not match: {pos!r}")
    if neg is not None and re.search(pat, neg, re.MULTILINE):
        failures.append(f"  - {sid}: negative sample incorrectly matched: {neg!r}")

if failures:
    print("FAIL: pattern sample validation:")
    for f in failures:
        print(f)
    sys.exit(1)

# Bonus: reCAPTCHA safety check — if a future curator re-adds recaptcha_site_key,
# make sure it does NOT match the well-known-public Google sample secret key.
SECRET_SAMPLE = "6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe"
SITE_SAMPLE = "6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI"
if "recaptcha_site_key" in patterns:
    pat = patterns["recaptcha_site_key"]
    if re.search(pat, SECRET_SAMPLE):
        print(f"FAIL: recaptcha_site_key pattern matches a SECRET key — would auto-reject real exfil findings")
        sys.exit(1)

print("PASS: PublicSafeList schema + samples + regex validity + uniqueness + recaptcha safety check")
PYEOF
