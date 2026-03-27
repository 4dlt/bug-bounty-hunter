#!/bin/bash
# install.sh -- BugBountyHunter installer
#
# Installs the BugBountyHunter system into Claude Code's skill directory.
# Safe to run multiple times (idempotent).
#
# What it does:
#   1. Creates symlinks in ~/.claude/skills/ for new standalone skills
#   2. Copies new workflows into existing skill directories
#   3. Checks for required and recommended tools
#   4. Clones SecLists if not present
#   5. Prints upgrade instructions for existing skills
#
# Usage:
#   chmod +x install.sh
#   ./install.sh

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILLS_DIR="$HOME/.claude/skills"
SECURITY_DIR="$SKILLS_DIR/Security"

echo ""
echo -e "${BOLD}========================================${NC}"
echo -e "${BOLD}  BugBountyHunter Installer${NC}"
echo -e "${BOLD}========================================${NC}"
echo ""

# ─────────────────────────────────────────────
# Step 0: Verify Claude Code skills directory
# ─────────────────────────────────────────────

if [ ! -d "$HOME/.claude" ]; then
    echo -e "${RED}ERROR: ~/.claude directory not found.${NC}"
    echo "Please install Claude Code first: https://claude.ai/claude-code"
    exit 1
fi

if [ ! -d "$SKILLS_DIR" ]; then
    echo -e "${YELLOW}Creating ~/.claude/skills/ directory...${NC}"
    mkdir -p "$SKILLS_DIR"
fi

if [ ! -d "$SECURITY_DIR" ]; then
    echo -e "${YELLOW}Creating ~/.claude/skills/Security/ directory...${NC}"
    mkdir -p "$SECURITY_DIR"
fi

echo -e "${GREEN}[OK]${NC} Claude Code skills directory: $SKILLS_DIR"

# ─────────────────────────────────────────────
# Step 1: Detect existing ai-security-arsenal
# ─────────────────────────────────────────────

ARSENAL_INSTALLED=false
ARSENAL_SKILLS=()

for skill in DastAutomation ApiSecurity IdorPentest WebAssessment; do
    if [ -d "$SKILLS_DIR/$skill" ] || [ -L "$SKILLS_DIR/$skill" ]; then
        ARSENAL_SKILLS+=("$skill")
    fi
done

if [ ${#ARSENAL_SKILLS[@]} -gt 0 ]; then
    ARSENAL_INSTALLED=true
    echo -e "${GREEN}[OK]${NC} Detected existing skills: ${ARSENAL_SKILLS[*]}"
else
    echo -e "${YELLOW}[INFO]${NC} No ai-security-arsenal skills detected (DastAutomation, ApiSecurity, etc.)"
    echo "       The core BugBountyHunter system will still work, but attack agents"
    echo "       reference these skills for deeper testing. Consider installing:"
    echo "       https://github.com/YOUR_USERNAME/ai-security-arsenal"
fi

# ─────────────────────────────────────────────
# Step 2: Install new standalone skills (symlinks)
# ─────────────────────────────────────────────

echo ""
echo -e "${BOLD}--- Installing Core Skills ---${NC}"

install_skill_symlink() {
    local skill_name="$1"
    local source_dir="$SCRIPT_DIR/skills/$skill_name"
    local target_link="$SKILLS_DIR/$skill_name"

    if [ -L "$target_link" ]; then
        # Symlink exists -- check if it points to us
        local current_target
        current_target=$(readlink -f "$target_link")
        local our_target
        our_target=$(readlink -f "$source_dir")
        if [ "$current_target" = "$our_target" ]; then
            echo -e "  ${GREEN}[OK]${NC}  $skill_name (already linked)"
            return 0
        else
            echo -e "  ${YELLOW}[UPDATE]${NC}  $skill_name (updating symlink)"
            rm "$target_link"
        fi
    elif [ -d "$target_link" ]; then
        echo -e "  ${YELLOW}[SKIP]${NC}  $skill_name (directory exists -- not overwriting)"
        echo "         Remove $target_link manually if you want to use the symlink."
        return 0
    fi

    ln -s "$source_dir" "$target_link"
    echo -e "  ${GREEN}[OK]${NC}  $skill_name -> $source_dir"
}

install_skill_symlink "BugBountyHunter"

# Payloads goes under Security/
PAYLOADS_LINK="$SECURITY_DIR/Payloads"
if [ -L "$PAYLOADS_LINK" ]; then
    current=$(readlink -f "$PAYLOADS_LINK")
    ours=$(readlink -f "$SCRIPT_DIR/skills/Payloads")
    if [ "$current" = "$ours" ]; then
        echo -e "  ${GREEN}[OK]${NC}  Security/Payloads (already linked)"
    else
        echo -e "  ${YELLOW}[UPDATE]${NC}  Security/Payloads (updating symlink)"
        rm "$PAYLOADS_LINK"
        ln -s "$SCRIPT_DIR/skills/Payloads" "$PAYLOADS_LINK"
        echo -e "  ${GREEN}[OK]${NC}  Security/Payloads -> $SCRIPT_DIR/skills/Payloads"
    fi
elif [ -d "$PAYLOADS_LINK" ]; then
    echo -e "  ${YELLOW}[SKIP]${NC}  Security/Payloads (directory exists -- not overwriting)"
else
    ln -s "$SCRIPT_DIR/skills/Payloads" "$PAYLOADS_LINK"
    echo -e "  ${GREEN}[OK]${NC}  Security/Payloads -> $SCRIPT_DIR/skills/Payloads"
fi

# ImpactValidator goes under Security/
IV_LINK="$SECURITY_DIR/ImpactValidator"
if [ -L "$IV_LINK" ]; then
    current=$(readlink -f "$IV_LINK")
    ours=$(readlink -f "$SCRIPT_DIR/skills/ImpactValidator")
    if [ "$current" = "$ours" ]; then
        echo -e "  ${GREEN}[OK]${NC}  Security/ImpactValidator (already linked)"
    else
        echo -e "  ${YELLOW}[UPDATE]${NC}  Security/ImpactValidator (updating symlink)"
        rm "$IV_LINK"
        ln -s "$SCRIPT_DIR/skills/ImpactValidator" "$IV_LINK"
        echo -e "  ${GREEN}[OK]${NC}  Security/ImpactValidator -> $SCRIPT_DIR/skills/ImpactValidator"
    fi
elif [ -d "$IV_LINK" ]; then
    echo -e "  ${YELLOW}[SKIP]${NC}  Security/ImpactValidator (directory exists -- not overwriting)"
else
    ln -s "$SCRIPT_DIR/skills/ImpactValidator" "$IV_LINK"
    echo -e "  ${GREEN}[OK]${NC}  Security/ImpactValidator -> $SCRIPT_DIR/skills/ImpactValidator"
fi

# TechniqueFetcher goes under Security/
TF_LINK="$SECURITY_DIR/TechniqueFetcher"
if [ -L "$TF_LINK" ]; then
    current=$(readlink -f "$TF_LINK")
    ours=$(readlink -f "$SCRIPT_DIR/skills/TechniqueFetcher")
    if [ "$current" = "$ours" ]; then
        echo -e "  ${GREEN}[OK]${NC}  Security/TechniqueFetcher (already linked)"
    else
        echo -e "  ${YELLOW}[UPDATE]${NC}  Security/TechniqueFetcher (updating symlink)"
        rm "$TF_LINK"
        ln -s "$SCRIPT_DIR/skills/TechniqueFetcher" "$TF_LINK"
        echo -e "  ${GREEN}[OK]${NC}  Security/TechniqueFetcher -> $SCRIPT_DIR/skills/TechniqueFetcher"
    fi
elif [ -d "$TF_LINK" ]; then
    echo -e "  ${YELLOW}[SKIP]${NC}  Security/TechniqueFetcher (directory exists -- not overwriting)"
else
    ln -s "$SCRIPT_DIR/skills/TechniqueFetcher" "$TF_LINK"
    echo -e "  ${GREEN}[OK]${NC}  Security/TechniqueFetcher -> $SCRIPT_DIR/skills/TechniqueFetcher"
fi

# ─────────────────────────────────────────────
# Step 3: Copy new workflows into existing skill directories
# ─────────────────────────────────────────────

echo ""
echo -e "${BOLD}--- Installing New Workflows ---${NC}"

# Recon workflows
RECON_WF_DIR="$SECURITY_DIR/Recon/Workflows"
if [ -d "$SECURITY_DIR/Recon" ]; then
    mkdir -p "$RECON_WF_DIR"
    for wf in JsAnalysis.md HistoricalUrls.md DorkGeneration.md CloudAssetDiscovery.md; do
        src="$SCRIPT_DIR/skills/Recon/Workflows/$wf"
        dst="$RECON_WF_DIR/$wf"
        if [ -f "$dst" ]; then
            if diff -q "$src" "$dst" > /dev/null 2>&1; then
                echo -e "  ${GREEN}[OK]${NC}  Recon/Workflows/$wf (already up to date)"
            else
                cp "$src" "$dst"
                echo -e "  ${YELLOW}[UPDATE]${NC}  Recon/Workflows/$wf (updated)"
            fi
        else
            cp "$src" "$dst"
            echo -e "  ${GREEN}[OK]${NC}  Recon/Workflows/$wf (installed)"
        fi
    done
elif [ ! -d "$SECURITY_DIR/Recon" ]; then
    echo -e "  ${YELLOW}[SKIP]${NC}  Recon workflows -- Security/Recon/ directory not found"
    echo "         Install the Security/Recon skill first, then re-run this installer."
fi

# IdorPentest workflows
IDOR_WF_DIR="$SKILLS_DIR/IdorPentest/Workflows"
if [ -d "$SKILLS_DIR/IdorPentest" ]; then
    mkdir -p "$IDOR_WF_DIR"
    for wf in ImpactValidation.md ChainExploitation.md; do
        src="$SCRIPT_DIR/skills/IdorPentestUpgrades/Workflows/$wf"
        dst="$IDOR_WF_DIR/$wf"
        if [ -f "$dst" ]; then
            if diff -q "$src" "$dst" > /dev/null 2>&1; then
                echo -e "  ${GREEN}[OK]${NC}  IdorPentest/Workflows/$wf (already up to date)"
            else
                cp "$src" "$dst"
                echo -e "  ${YELLOW}[UPDATE]${NC}  IdorPentest/Workflows/$wf (updated)"
            fi
        else
            cp "$src" "$dst"
            echo -e "  ${GREEN}[OK]${NC}  IdorPentest/Workflows/$wf (installed)"
        fi
    done
else
    echo -e "  ${YELLOW}[SKIP]${NC}  IdorPentest workflows -- IdorPentest/ directory not found"
    echo "         The IdorPentest skill is part of ai-security-arsenal."
fi

# ─────────────────────────────────────────────
# Step 4: Check and install required tools
# ─────────────────────────────────────────────

echo ""
echo -e "${BOLD}--- Checking Required Tools ---${NC}"

MISSING_REQUIRED=0
MISSING_RECOMMENDED=0

check_tool() {
    local tool="$1"
    local required="$2"
    local install_cmd="$3"

    if command -v "$tool" &>/dev/null; then
        printf "  ${GREEN}[OK]${NC}  %-22s %s\n" "$tool" "$(command -v "$tool")"
    else
        if [ "$required" = "required" ]; then
            printf "  ${RED}[MISSING]${NC}  %-22s\n" "$tool"
            MISSING_REQUIRED=$((MISSING_REQUIRED + 1))
        else
            printf "  ${YELLOW}[MISSING]${NC}  %-22s\n" "$tool"
            MISSING_RECOMMENDED=$((MISSING_RECOMMENDED + 1))
        fi
        echo "         Install: $install_cmd"
    fi
}

# Required tools
check_tool "dev-browser" "required" "npm install -g @anthropic-ai/dev-browser"
check_tool "subfinder" "required" "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
check_tool "httpx" "required" "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
check_tool "nuclei" "required" "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
check_tool "katana" "required" "go install github.com/projectdiscovery/katana/cmd/katana@latest"
check_tool "ffuf" "required" "go install github.com/ffuf/ffuf/v2@latest"
check_tool "nmap" "required" "sudo pacman -S nmap  OR  sudo apt install nmap"
check_tool "curl" "required" "(usually pre-installed)"
check_tool "jq" "required" "sudo pacman -S jq  OR  sudo apt install jq"

echo ""
echo -e "${BOLD}--- Checking Recommended Tools ---${NC}"

check_tool "sqlmap" "recommended" "pip install sqlmap  OR  sudo pacman -S sqlmap"
check_tool "arjun" "recommended" "pip install arjun"
check_tool "gau" "recommended" "go install github.com/lc/gau/v2/cmd/gau@latest"
check_tool "dalfox" "recommended" "go install github.com/hahwul/dalfox/v2@latest"
check_tool "interactsh-client" "recommended" "go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
check_tool "unfurl" "recommended" "go install github.com/tomnomnom/unfurl@latest"

# ─────────────────────────────────────────────
# Step 5: SecLists wordlists
# ─────────────────────────────────────────────

echo ""
echo -e "${BOLD}--- Checking Wordlists ---${NC}"

SECLISTS=""
for path in "$HOME/SecLists" "/usr/share/wordlists/seclists" "/usr/share/seclists" "/opt/seclists"; do
    if [ -d "$path" ]; then
        SECLISTS="$path"
        break
    fi
done

if [ -n "$SECLISTS" ]; then
    echo -e "  ${GREEN}[OK]${NC}  SecLists: $SECLISTS"
else
    echo -e "  ${YELLOW}[MISSING]${NC}  SecLists not found"
    echo ""
    read -r -p "  Clone SecLists to ~/SecLists? (~2GB) [y/N] " response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        echo "  Cloning SecLists (this may take a few minutes)..."
        git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$HOME/SecLists"
        echo -e "  ${GREEN}[OK]${NC}  SecLists cloned to ~/SecLists"
    else
        echo "  Skipped. Install later: git clone https://github.com/danielmiessler/SecLists.git ~/SecLists"
    fi
fi

# ─────────────────────────────────────────────
# Step 6: Upgrade instructions for existing skills
# ─────────────────────────────────────────────

if [ "$ARSENAL_INSTALLED" = true ]; then
    echo ""
    echo -e "${BOLD}========================================${NC}"
    echo -e "${BOLD}  Upgrade Instructions${NC}"
    echo -e "${BOLD}========================================${NC}"
    echo ""
    echo "The following existing skills have upgrade patches available."
    echo "These are modifications to SKILL.md files that add bug bounty"
    echo "hunting capabilities. Review and apply manually:"
    echo ""

    for skill in "${ARSENAL_SKILLS[@]}"; do
        readme="$SCRIPT_DIR/skills/${skill}Upgrades/README.md"
        if [ -f "$readme" ]; then
            echo -e "  ${BLUE}-->  ${skill}${NC}"
            echo "       See: skills/${skill}Upgrades/README.md"
        fi
    done

    echo ""
    echo "These patches add WAF bypasses, autonomous auth, business logic"
    echo "testing, and other enhancements. See each README for copy-paste"
    echo "content blocks."
fi

# ─────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────

echo ""
echo -e "${BOLD}========================================${NC}"
echo -e "${BOLD}  Installation Summary${NC}"
echo -e "${BOLD}========================================${NC}"
echo ""

SYMLINKS_INSTALLED=0
for check in "$SKILLS_DIR/BugBountyHunter" "$SECURITY_DIR/Payloads" "$SECURITY_DIR/ImpactValidator" "$SECURITY_DIR/TechniqueFetcher"; do
    if [ -L "$check" ] || [ -d "$check" ]; then
        SYMLINKS_INSTALLED=$((SYMLINKS_INSTALLED + 1))
    fi
done

echo -e "  Skills installed:     ${GREEN}$SYMLINKS_INSTALLED/4${NC}"

if [ "$MISSING_REQUIRED" -gt 0 ]; then
    echo -e "  Required tools:       ${RED}$MISSING_REQUIRED missing${NC}"
else
    echo -e "  Required tools:       ${GREEN}All present${NC}"
fi

if [ "$MISSING_RECOMMENDED" -gt 0 ]; then
    echo -e "  Recommended tools:    ${YELLOW}$MISSING_RECOMMENDED missing${NC} (non-blocking)"
else
    echo -e "  Recommended tools:    ${GREEN}All present${NC}"
fi

echo ""
echo -e "  ${BOLD}Restart Claude Code for skills to take effect.${NC}"
echo ""
echo "  Usage:"
echo '    pentest target.com scope=*.target.com creds=user:pass@login program=https://hackerone.com/target'
echo ""
echo -e "${BOLD}========================================${NC}"
