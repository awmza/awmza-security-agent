# Code signing policy

Windows releases of this project are signed. Free code signing is provided by
[SignPath.io](https://about.signpath.io/), certificate by [SignPath Foundation](https://signpath.org/)
(once the project is accepted; until then the files are unsigned and only SHA-256 checked).

- Only files built by the GitHub Actions workflow in this repository, from the tagged source, are signed.
- Committers and reviewers: HUSSAIN MUHAMMAD MAJID (AWMZA). Approver of every signing request: the same.
- All maintainers use multi-factor authentication on GitHub and SignPath.
- macOS binaries are ad-hoc signed and installed with `install.sh` (SHA-256 checked).

Privacy: see [PRIVACY.md](PRIVACY.md). This program will not transfer any information to other
networked systems except the AWMZA server it was registered with, as described there.
