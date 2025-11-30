#!/bin/bash

# --- COLORS FOR OUTPUT ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# --- SETUP & CHECKS ---
CHECKER_SCRIPT="./sbom_threat_matcher.py"
TEMP_DIR="temp_scan_artifacts"

# 1. Check Arguments
if [ "$#" -ne 2 ]; then
    echo -e "${RED}Usage: $0 <GITHUB_ORG_OR_USER> <PATH_TO_VULN_LIST.txt>${NC}"
    echo "Example: $0 my-company-org ./shai_hulud_list.txt"
    exit 1
fi

ORG_NAME=$1
VULN_LIST=$2

# 2. Check Prerequisites
if ! command -v gh &> /dev/null; then
    echo -e "${RED}Error: GitHub CLI (gh) is not installed.${NC}"
    exit 1
fi
if ! command -v jq &> /dev/null; then
    echo -e "${RED}Error: jq is not installed.${NC}"
    exit 1
fi
if [ ! -f "$CHECKER_SCRIPT" ]; then
    echo -e "${RED}Error: Python script $CHECKER_SCRIPT not found.${NC}"
    exit 1
fi

# 3. Create Temp Directory & Log file
mkdir -p "$TEMP_DIR"
REPORT_FILE="scan_report_$(date +%Y%m%d_%H%M%S).log"
touch "$REPORT_FILE"

echo -e "${CYAN}======================================================${NC}"
echo -e "${CYAN}   GitHub Organization Vulnerability Scanner          ${NC}"
echo -e "${CYAN}   Target: $ORG_NAME                                  ${NC}"
echo -e "${CYAN}   List:   $VULN_LIST                                 ${NC}"
echo -e "${CYAN}======================================================${NC}"

# 4. Fetch Repository List
echo "🔍 Fetching repository list for $ORG_NAME..."
REPOS=$(gh repo list "$ORG_NAME" --limit 4000 --json name,isArchived --jq '.[] | select(.isArchived == false) | .name')

if [ -z "$REPOS" ]; then
    echo -e "${RED}❌ No repositories found or access denied.${NC}"
    exit 1
fi

# Initialize counters
TOTAL_SCANNED=0
INFECTED_COUNT=0

# --- SCAN LOOP ---
for REPO in $REPOS; do
    echo "---------------------------------------------------"
    echo -e "Processing: ${YELLOW}$REPO${NC}"
    
    TARGET_FILE=""
    SOURCE_TYPE=""

    # --- PRIORITY 1: GitHub Dependency Graph SBOM ---
    # We try to fetch the generated SBOM first.
    if gh api "/repos/$ORG_NAME/$REPO/dependency-graph/sbom" > "$TEMP_DIR/$REPO.sbom.json" 2>/dev/null; then
        # Check if file is not empty and valid JSON
        if [ -s "$TEMP_DIR/$REPO.sbom.json" ]; then
            TARGET_FILE="$TEMP_DIR/$REPO.sbom.json"
            SOURCE_TYPE="Dependency Graph SBOM"
        fi
    fi

    # --- PRIORITY 2: package-lock.json (Fallback) ---
    # If SBOM failed, try to get raw package-lock.json
    if [ -z "$TARGET_FILE" ]; then
        if gh api "/repos/$ORG_NAME/$REPO/contents/package-lock.json" -H "Accept: application/vnd.github.raw" > "$TEMP_DIR/$REPO.lock.json" 2>/dev/null; then
             TARGET_FILE="$TEMP_DIR/$REPO.lock.json"
             SOURCE_TYPE="package-lock.json"
        fi
    fi

    # --- PRIORITY 3: package.json (Last Resort) ---
    # If lockfile failed, try package.json
    if [ -z "$TARGET_FILE" ]; then
        if gh api "/repos/$ORG_NAME/$REPO/contents/package.json" -H "Accept: application/vnd.github.raw" > "$TEMP_DIR/$REPO.package.json" 2>/dev/null; then
             TARGET_FILE="$TEMP_DIR/$REPO.package.json"
             SOURCE_TYPE="package.json (Shallow Scan)"
        fi
    fi

    # --- EXECUTE SCAN ---
    if [ -n "$TARGET_FILE" ]; then
        echo -e "   ↳ Source: $SOURCE_TYPE"
        
        # Run the Python script and capture output
        OUTPUT=$(python3 "$CHECKER_SCRIPT" "$TARGET_FILE" "$VULN_LIST")
        
        # Check for DANGER in output
        if [[ "$OUTPUT" == *"DANGER"* ]]; then
            echo -e "${RED}   🚨 VULNERABILITIES FOUND!${NC}"
            echo "$OUTPUT"
            
            # Log to report file
            echo "repo: $REPO ($SOURCE_TYPE)" >> "$REPORT_FILE"
            echo "$OUTPUT" >> "$REPORT_FILE"
            echo "-------------------" >> "$REPORT_FILE"
            ((INFECTED_COUNT++))
        else
            echo -e "${GREEN}   ✅ Clean${NC}"
        fi
        
        ((TOTAL_SCANNED++))
    else
        echo -e "${YELLOW}   ⚠️  Skipped: No SBOM, package-lock, or package.json found.${NC}"
    fi

    # Cleanup temp files for this repo to save space
    rm -f "$TEMP_DIR/$REPO"*

done

# --- FINAL SUMMARY ---
echo -e "\n${CYAN}======================================================${NC}"
echo -e "${CYAN}               FINAL MISSION REPORT                   ${NC}"
echo -e "${CYAN}======================================================${NC}"
echo "Repositories Scanned: $TOTAL_SCANNED"

if [ "$INFECTED_COUNT" -eq 0 ]; then
    echo -e "${GREEN}RESULT: ALL SYSTEMS CLEAN. No compromised packages found.${NC}"
else
    echo -e "${RED}RESULT: COMPROMISED PACKAGES DETECTED.${NC}"
    echo -e "${RED}Infected Repositories: $INFECTED_COUNT${NC}"
    echo "See details below or in $REPORT_FILE:"
    echo ""
    cat "$REPORT_FILE"
fi

# Final cleanup
rm -rf "$TEMP_DIR"
