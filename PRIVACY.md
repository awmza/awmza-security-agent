# Privacy

This program sends data only to the AWMZA Security server the computer was registered with
(default https://security.awmza.com), and only after an administrator installs it with a token.

What is sent: computer name, OS and version, agent version, heartbeat, security events
(process name and command line of a suspicious process, file paths of changed canary or
suspicious files, MD5/SHA-256/size of new executables), inventory (firewall, disk encryption,
antivirus, listening ports, admin group members).

What is never sent: file contents, documents, browsing history, keystrokes, screenshots.

Data is processed under the AWMZA Security privacy policy (https://awmza.com/privacy.html, GDPR).
Uninstall stops all sending; deleting the device in the dashboard deletes its data.
