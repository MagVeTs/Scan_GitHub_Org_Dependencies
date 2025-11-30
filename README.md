# scan_github_org_dependencies
An automation wrapper for the `SBOM Threat Matcher` (https://github.com/MagVeTs/SBOM_Threat_Matcher) that scans an entire GitHub organization or user account.

## Features
* **Auto-Discovery:** Fetches all non-archived repositories from the target account.
* **Smart Fallback Strategy:**
    1.  Attempts to download a full **Dependency Graph SBOM**.
    2.  If unavailable, downloads `package-lock.json` (Deep scan).
    3.  If unavailable, downloads `package.json` (Shallow scan).
* **Reporting:** distinct color-coded output and a final summary report of affected repositories.

## Usage

```bash
./scan_github_org_dependencies.sh <GITHUB_ORG_OR_USER> <PATH_TO_THREAT_LIST.txt>
```

## Example
```bash
./scan_github_org_dependencies.sh "netflix" "./shai_hulud_list.txt"
```

## Requirements
- GitHub CLI (`gh`): Must be installed and authenticated (`gh auth login`).

- `jq`: Required for parsing repository lists.

- Python 3: To run the underlying `sbom_threat_matcher.py` script.

- `sbom_threat_matcher.py` (found here: https://github.com/MagVeTs/SBOM_Threat_Matcher) - installed in same directory as `scan_github_org_dependencies.sh`

- List of compromised or vulnerable packages/dependencies stored as .txt file






