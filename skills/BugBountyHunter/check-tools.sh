#!/bin/bash
# check-tools.sh — Verify required and recommended tools for BugBountyHunter
# Run before starting an engagement to identify missing tools

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "========================================"
echo "  BugBountyHunter Tool Availability Check"
echo "========================================"
echo ""

REQUIRED=(dev-browser subfinder httpx nuclei katana ffuf nmap curl jq)
RECOMMENDED=(sqlmap interactsh-client arjun gau dalfox unfurl whois dig)

MISSING_REQUIRED=0
MISSING_RECOMMENDED=0

echo "--- Required Tools ---"
for tool in "${REQUIRED[@]}"; do
  if command -v "$tool" &>/dev/null; then
    printf "  ${GREEN}[OK]${NC}  %-20s %s\n" "$tool" "$(command -v "$tool")"
  else
    printf "  ${RED}[MISSING]${NC}  %-20s\n" "$tool"
    MISSING_REQUIRED=$((MISSING_REQUIRED + 1))

    case "$tool" in
      dev-browser)
        echo "         Install: npm install -g @anthropic-ai/dev-browser"
        ;;
      subfinder)
        echo "         Install: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        ;;
      httpx)
        echo "         Install: go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
        ;;
      nuclei)
        echo "         Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        ;;
      katana)
        echo "         Install: go install github.com/projectdiscovery/katana/cmd/katana@latest"
        ;;
      ffuf)
        echo "         Install: go install github.com/ffuf/ffuf/v2@latest"
        ;;
      nmap)
        echo "         Install: sudo pacman -S nmap  OR  sudo apt install nmap"
        ;;
      curl)
        echo "         Install: sudo pacman -S curl  OR  sudo apt install curl"
        ;;
      jq)
        echo "         Install: sudo pacman -S jq  OR  sudo apt install jq"
        ;;
    esac
  fi
done

echo ""
echo "--- Recommended Tools ---"
for tool in "${RECOMMENDED[@]}"; do
  if command -v "$tool" &>/dev/null; then
    printf "  ${GREEN}[OK]${NC}  %-20s %s\n" "$tool" "$(command -v "$tool")"
  else
    printf "  ${YELLOW}[MISSING]${NC}  %-20s\n" "$tool"
    MISSING_RECOMMENDED=$((MISSING_RECOMMENDED + 1))

    case "$tool" in
      sqlmap)
        echo "         Install: pip install sqlmap  OR  sudo pacman -S sqlmap"
        ;;
      interactsh-client)
        echo "         Install: go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
        ;;
      arjun)
        echo "         Install: pip install arjun"
        ;;
      gau)
        echo "         Install: go install github.com/lc/gau/v2/cmd/gau@latest"
        ;;
      dalfox)
        echo "         Install: go install github.com/hahwul/dalfox/v2@latest"
        ;;
      unfurl)
        echo "         Install: go install github.com/tomnomnom/unfurl@latest"
        ;;
      whois)
        echo "         Install: sudo pacman -S whois  OR  sudo apt install whois"
        ;;
      dig)
        echo "         Install: sudo pacman -S bind  OR  sudo apt install dnsutils"
        ;;
    esac
  fi
done

echo ""
echo "--- Payload Database ---"
PAYLOAD_DIR="$HOME/.claude/skills/Security/Payloads"
if [ -d "$PAYLOAD_DIR" ]; then
  PAYLOAD_COUNT=$(find "$PAYLOAD_DIR" -name "*.yaml" | wc -l)
  printf "  ${GREEN}[OK]${NC}  Payloads directory: %s (%d YAML files)\n" "$PAYLOAD_DIR" "$PAYLOAD_COUNT"
else
  printf "  ${RED}[MISSING]${NC}  Payloads directory not found at %s\n" "$PAYLOAD_DIR"
fi

echo ""
echo "--- Wordlists ---"
SECLISTS=""
for path in "$HOME/SecLists" "/usr/share/wordlists/seclists" "/usr/share/seclists" "/opt/seclists"; do
  if [ -d "$path" ]; then
    SECLISTS="$path"
    break
  fi
done
if [ -n "$SECLISTS" ]; then
  printf "  ${GREEN}[OK]${NC}  SecLists: %s\n" "$SECLISTS"
else
  printf "  ${YELLOW}[MISSING]${NC}  SecLists not found\n"
  echo "         Install: git clone https://github.com/danielmiessler/SecLists.git ~/SecLists"
fi

echo ""
echo "========================================"
if [ "$MISSING_REQUIRED" -gt 0 ]; then
  printf "  ${RED}%d required tool(s) missing${NC}\n" "$MISSING_REQUIRED"
  echo "  Install required tools before running BugBountyHunter."
  exit 1
else
  printf "  ${GREEN}All required tools present${NC}\n"
fi

if [ "$MISSING_RECOMMENDED" -gt 0 ]; then
  printf "  ${YELLOW}%d recommended tool(s) missing${NC} (non-blocking)\n" "$MISSING_RECOMMENDED"
fi
echo "========================================"
