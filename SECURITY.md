# Security policy

Please report a vulnerability privately to **security@awmza.com** (or the contact in
https://security.awmza.com/.well-known/security.txt). Do not open a public issue for it.

- We answer within 3 working days and aim to fix critical issues within 14 days.
- Good-faith research is welcome; please do not access other customers' data or disrupt the service.
- Supported version: the latest release only.

Design rules the agent keeps:
- runs as SYSTEM / root from a folder only administrators can change (Program Files on Windows,
  a 0700 root folder on macOS and Linux);
- talks only to the AWMZA server over TLS with certificate checks; the device key is stored root-only;
- sends hashes and metadata, never file content;
- install tokens are single-purpose and expire; uninstall releases isolation and removes canary files.
