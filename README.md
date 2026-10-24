# AWMZA Security endpoint agent

Open source (Apache-2.0) agent for [AWMZA Security](https://security.awmza.com/).
It watches a computer for ransomware and other attacks and reports to the AWMZA dashboard.
The service behind it (dashboard, alerts, reports) is a paid product; this agent is free to read, audit and build.

## What it does
- Processes: ransomware precursors (shadow copy / backup deletion), reverse shells, crypto miners, script droppers.
- Files in Documents, Desktop, Pictures, Downloads: canary (decoy) files, mass changes, encrypted-looking files, ransom notes.
- New executables: only MD5 + SHA-256 + size are compared with the ClamAV hash list on the server.
- Inventory: OS, firewall, disk encryption, antivirus, listening ports, admin group members.
- Isolation on request: the OS firewall blocks everything except the AWMZA server.

**No file content ever leaves the computer.** See [PRIVACY.md](PRIVACY.md).

## Install
Make an install token in the dashboard (Endpoints > Add computer), then:

| System | Command |
|---|---|
| Windows 10/11 | download `AWMZA-Security-Setup.exe`, run it, paste the token. Silent: `AWMZA-Security-Setup.exe /VERYSILENT /TOKEN=awe_...` |
| macOS (Apple silicon + Intel) | `curl -fsSL https://security.awmza.com/agent/install.sh \| sudo sh -s -- --token awe_...` |
| Linux x86_64 | same command as macOS, or `sudo python3 awmza-agent.py install --token awe_...` |

Then give `awmza-agent` Full Disk Access on macOS (System Settings > Privacy & Security).
Every download has a SHA-256 in `SHA256SUMS`; `install.sh` refuses a file that does not match.

## Build it yourself
Only the Python standard library is used (Python 3.8+). Builds run in GitHub Actions
(`.github/workflows/build.yml`): PyInstaller 6.11.1, Inno Setup 6 for the Windows setup.

## Security
Report vulnerabilities as described in [SECURITY.md](SECURITY.md). Code signing: [CODE_SIGNING_POLICY.md](CODE_SIGNING_POLICY.md).

Maintainer: AWMZA - HUSSAIN MUHAMMAD MAJID, P.IVA IT14191810960, Italy.
