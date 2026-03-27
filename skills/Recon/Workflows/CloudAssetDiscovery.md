# Cloud Asset Discovery Workflow

**Purpose:** Enumerate cloud storage buckets, blob containers, and object storage across AWS, Azure, GCP, DigitalOcean, and Alibaba Cloud to discover publicly accessible or misconfigured assets belonging to the target.

**Input:** Target domain and/or organization name
**Output:** List of discovered cloud assets with permission status for shared state
**Authorization:** Passive — checking publicly accessible storage. No exploitation of write permissions.

---

## Step 1: Generate Bucket Name Patterns

Based on the target, generate common naming patterns used for cloud storage:

```bash
TARGET="targetname"

# Generate bucket name wordlist
cat << EOF > bucket_names.txt
${TARGET}
${TARGET}-com
${TARGET}-dev
${TARGET}-staging
${TARGET}-backup
${TARGET}-backups
${TARGET}-assets
${TARGET}-uploads
${TARGET}-media
${TARGET}-data
${TARGET}-prod
${TARGET}-production
${TARGET}-static
${TARGET}-public
${TARGET}-private
${TARGET}-internal
${TARGET}-test
${TARGET}-testing
${TARGET}-uat
${TARGET}-qa
${TARGET}-stage
${TARGET}-cdn
${TARGET}-images
${TARGET}-files
${TARGET}-docs
${TARGET}-documents
${TARGET}-logs
${TARGET}-archive
${TARGET}-temp
${TARGET}-tmp
${TARGET}-web
${TARGET}-app
${TARGET}-api
${TARGET}-db
${TARGET}-database
${TARGET}-config
${TARGET}-infra
${TARGET}-terraform
${TARGET}-deploy
${TARGET}-ci
${TARGET}-artifacts
dev-${TARGET}
staging-${TARGET}
backup-${TARGET}
prod-${TARGET}
test-${TARGET}
data-${TARGET}
assets-${TARGET}
media-${TARGET}
uploads-${TARGET}
static-${TARGET}
${TARGET}2
${TARGET}1
${TARGET}-v2
${TARGET}-old
${TARGET}-new
EOF

echo "Generated $(wc -l < bucket_names.txt) bucket name patterns"
```

---

## Step 2: AWS S3 Bucket Enumeration

### Check bucket existence and permissions

```bash
mkdir -p cloud_results

while IFS= read -r bucket; do
  # Check if bucket exists (HTTP 200 or 403 = exists)
  status=$(curl -sI "https://${bucket}.s3.amazonaws.com" -o /dev/null -w "%{http_code}" --max-time 5)

  if [ "$status" = "200" ] || [ "$status" = "403" ]; then
    echo "[S3] ${bucket} — HTTP ${status}" | tee -a cloud_results/s3_found.txt
  fi
done < bucket_names.txt
```

### Check specific permissions on found buckets

For each bucket found:

#### List permission (public read of bucket contents)

```bash
while IFS= read -r line; do
  bucket=$(echo "$line" | awk '{print $2}')

  # Try to list bucket contents
  list_result=$(curl -s "https://${bucket}.s3.amazonaws.com" --max-time 10)

  if echo "$list_result" | grep -q "<Contents>"; then
    echo "[S3-LIST] ${bucket} — PUBLIC LIST ENABLED" | tee -a cloud_results/s3_public_list.txt
    echo "$list_result" | head -100 > "cloud_results/s3_list_${bucket}.xml"
  elif echo "$list_result" | grep -q "AccessDenied"; then
    echo "[S3-LIST] ${bucket} — Access Denied (exists but not listable)" | tee -a cloud_results/s3_access_denied.txt
  fi
done < cloud_results/s3_found.txt
```

#### Check for public read on common files

```bash
while IFS= read -r line; do
  bucket=$(echo "$line" | awk '{print $2}')

  for path in "index.html" "robots.txt" ".env" "config.json" "backup.sql" "db.sql" "credentials.json" ".git/config" "wp-config.php"; do
    status=$(curl -sI "https://${bucket}.s3.amazonaws.com/${path}" -o /dev/null -w "%{http_code}" --max-time 5)
    if [ "$status" = "200" ]; then
      echo "[S3-FILE] ${bucket}/${path} — ACCESSIBLE (200)" | tee -a cloud_results/s3_files_found.txt
    fi
  done
done < cloud_results/s3_found.txt
```

#### Check for write permission (DO NOT write — just test with dry run HEAD)

```bash
# NOTE: We do NOT actually write. We only document that list/read is open.
# Write testing would require authorization.
```

### S3 Region Enumeration

```bash
# If a bucket exists, determine its region
while IFS= read -r line; do
  bucket=$(echo "$line" | awk '{print $2}')
  region=$(curl -sI "https://${bucket}.s3.amazonaws.com" --max-time 5 | grep -i "x-amz-bucket-region" | awk '{print $2}' | tr -d '\r')
  echo "[S3-REGION] ${bucket} — ${region:-unknown}" | tee -a cloud_results/s3_regions.txt
done < cloud_results/s3_found.txt
```

---

## Step 3: Azure Blob Storage Enumeration

### Check blob containers

```bash
while IFS= read -r name; do
  # Azure blob URL format
  status=$(curl -sI "https://${name}.blob.core.windows.net" -o /dev/null -w "%{http_code}" --max-time 5)

  if [ "$status" != "000" ] && [ "$status" != "404" ]; then
    echo "[AZURE] ${name}.blob.core.windows.net — HTTP ${status}" | tee -a cloud_results/azure_found.txt
  fi
done < bucket_names.txt
```

### Check common container names within found storage accounts

```bash
CONTAINERS="images uploads assets files data backup logs media public private static content documents archive"

while IFS= read -r line; do
  account=$(echo "$line" | awk '{print $2}' | sed 's/.blob.core.windows.net//')

  for container in $CONTAINERS; do
    # Try listing blobs in container (anonymous access)
    status=$(curl -sI "https://${account}.blob.core.windows.net/${container}?restype=container&comp=list" -o /dev/null -w "%{http_code}" --max-time 5)

    if [ "$status" = "200" ]; then
      echo "[AZURE-LIST] ${account}/${container} — PUBLIC LIST" | tee -a cloud_results/azure_public_list.txt
      curl -s "https://${account}.blob.core.windows.net/${container}?restype=container&comp=list" --max-time 10 | head -100 > "cloud_results/azure_list_${account}_${container}.xml"
    elif [ "$status" = "409" ] || [ "$status" = "403" ]; then
      echo "[AZURE-EXISTS] ${account}/${container} — Exists (${status})" | tee -a cloud_results/azure_exists.txt
    fi
  done
done < cloud_results/azure_found.txt
```

---

## Step 4: GCP Storage Enumeration

### Check GCP buckets

```bash
while IFS= read -r name; do
  # GCP storage URL format
  status=$(curl -sI "https://storage.googleapis.com/${name}" -o /dev/null -w "%{http_code}" --max-time 5)

  if [ "$status" = "200" ] || [ "$status" = "403" ]; then
    echo "[GCP] storage.googleapis.com/${name} — HTTP ${status}" | tee -a cloud_results/gcp_found.txt
  fi
done < bucket_names.txt
```

### Check for public listing

```bash
while IFS= read -r line; do
  bucket=$(echo "$line" | awk '{print $2}' | sed 's|storage.googleapis.com/||')

  # GCP JSON API for listing
  list_result=$(curl -s "https://storage.googleapis.com/storage/v1/b/${bucket}/o" --max-time 10)

  if echo "$list_result" | grep -q '"items"'; then
    echo "[GCP-LIST] ${bucket} — PUBLIC LIST ENABLED" | tee -a cloud_results/gcp_public_list.txt
    echo "$list_result" | head -100 > "cloud_results/gcp_list_${bucket}.json"
  fi
done < cloud_results/gcp_found.txt
```

### Alternative GCP URL format

```bash
while IFS= read -r name; do
  status=$(curl -sI "https://${name}.storage.googleapis.com" -o /dev/null -w "%{http_code}" --max-time 5)
  if [ "$status" = "200" ] || [ "$status" = "403" ]; then
    echo "[GCP-ALT] ${name}.storage.googleapis.com — HTTP ${status}" | tee -a cloud_results/gcp_found.txt
  fi
done < bucket_names.txt
```

---

## Step 5: DigitalOcean Spaces Enumeration

### Check Spaces across all DO regions

```bash
DO_REGIONS="nyc3 sfo3 ams3 sgp1 fra1 syd1 blr1"

while IFS= read -r name; do
  for region in $DO_REGIONS; do
    status=$(curl -sI "https://${name}.${region}.digitaloceanspaces.com" -o /dev/null -w "%{http_code}" --max-time 5)

    if [ "$status" = "200" ] || [ "$status" = "403" ]; then
      echo "[DO] ${name}.${region}.digitaloceanspaces.com — HTTP ${status}" | tee -a cloud_results/do_found.txt
    fi
  done
done < bucket_names.txt
```

### Check listing

```bash
if [ -f cloud_results/do_found.txt ]; then
  while IFS= read -r line; do
    url=$(echo "$line" | awk '{print $2}')
    list_result=$(curl -s "https://${url}" --max-time 10)

    if echo "$list_result" | grep -q "<Contents>"; then
      echo "[DO-LIST] ${url} — PUBLIC LIST ENABLED" | tee -a cloud_results/do_public_list.txt
    fi
  done < cloud_results/do_found.txt
fi
```

---

## Step 6: Alibaba Cloud OSS Enumeration

### Check OSS buckets

```bash
ALIYUN_REGIONS="oss-cn-hangzhou oss-cn-shanghai oss-cn-beijing oss-cn-shenzhen oss-cn-hongkong oss-us-west-1 oss-us-east-1 oss-ap-southeast-1 oss-eu-central-1"

while IFS= read -r name; do
  for region in $ALIYUN_REGIONS; do
    status=$(curl -sI "https://${name}.${region}.aliyuncs.com" -o /dev/null -w "%{http_code}" --max-time 5)

    if [ "$status" = "200" ] || [ "$status" = "403" ]; then
      echo "[ALIBABA] ${name}.${region}.aliyuncs.com — HTTP ${status}" | tee -a cloud_results/alibaba_found.txt
    fi
  done
done < bucket_names.txt
```

### Check listing

```bash
if [ -f cloud_results/alibaba_found.txt ]; then
  while IFS= read -r line; do
    url=$(echo "$line" | awk '{print $2}')
    list_result=$(curl -s "https://${url}" --max-time 10)

    if echo "$list_result" | grep -q "<Contents>"; then
      echo "[ALIBABA-LIST] ${url} — PUBLIC LIST ENABLED" | tee -a cloud_results/alibaba_public_list.txt
    fi
  done < cloud_results/alibaba_found.txt
fi
```

---

## Step 7: Automated Tools (Optional)

### cloud_enum

```bash
# If cloud_enum is installed
cloud_enum -k TARGET -k TARGET.com --disable-azure --disable-gcp -o cloud_enum_results.txt
```

### S3Scanner

```bash
# If s3scanner is installed
s3scanner scan --bucket-file bucket_names.txt
```

### MicroBurst (Azure-specific)

```bash
# PowerShell-based, for thorough Azure enumeration
# Invoke-EnumerateAzureBlobs -Base TARGET
```

---

## Step 8: Consolidation

```bash
# Count findings per provider
echo "=== Cloud Asset Discovery Summary ==="
echo "S3 buckets found: $(wc -l < cloud_results/s3_found.txt 2>/dev/null || echo 0)"
echo "S3 public list: $(wc -l < cloud_results/s3_public_list.txt 2>/dev/null || echo 0)"
echo "Azure accounts found: $(wc -l < cloud_results/azure_found.txt 2>/dev/null || echo 0)"
echo "Azure public list: $(wc -l < cloud_results/azure_public_list.txt 2>/dev/null || echo 0)"
echo "GCP buckets found: $(wc -l < cloud_results/gcp_found.txt 2>/dev/null || echo 0)"
echo "GCP public list: $(wc -l < cloud_results/gcp_public_list.txt 2>/dev/null || echo 0)"
echo "DO Spaces found: $(wc -l < cloud_results/do_found.txt 2>/dev/null || echo 0)"
echo "Alibaba OSS found: $(wc -l < cloud_results/alibaba_found.txt 2>/dev/null || echo 0)"
```

---

## Output Format (Shared State)

```json
{
  "cloud_assets": {
    "target": "TARGET",
    "s3": {
      "found": ["target-dev", "target-uploads"],
      "public_list": ["target-uploads"],
      "public_files": [
        {"bucket": "target-uploads", "path": "config.json", "status": 200}
      ],
      "regions": {"target-dev": "us-east-1", "target-uploads": "us-west-2"}
    },
    "azure": {
      "found": ["target.blob.core.windows.net"],
      "public_containers": [],
      "exists_but_denied": ["target/images", "target/backup"]
    },
    "gcp": {
      "found": ["target"],
      "public_list": []
    },
    "digitalocean": {
      "found": [],
      "public_list": []
    },
    "alibaba": {
      "found": [],
      "public_list": []
    },
    "severity": {
      "critical": ["List of publicly listable buckets with sensitive files"],
      "high": ["List of publicly readable buckets"],
      "medium": ["List of buckets that exist (403) — confirm ownership"]
    }
  }
}
```

Save to: `~/.claude/MEMORY/WORK/{current_work}/recon/cloud_assets.json`

---

## Integration Notes

- **Publicly listable buckets** are critical findings — enumerate all contents and check for sensitive data
- **403 buckets** confirm the name exists; try authenticated access if testing own assets, or report to the organization
- **Public files** in cloud storage (especially .env, config.json, backup.sql) should be retrieved and analyzed immediately
- **Combine with DorkGeneration** — Google dorks for `site:s3.amazonaws.com "TARGET"` can find additional buckets
- **Regional scanning** is important — many organizations use region-specific bucket names (e.g., target-eu, target-us)
- **Rate-limit curl requests** to avoid being blocked by cloud providers
- For bug bounty: public S3 buckets with sensitive data are typically P1-P2 severity findings
