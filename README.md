# UXUY Internal Content Workspace

https://ethan-chunqi.github.io/uxuy-content/

This repository contains a password screen and an authenticated AES-256-GCM encrypted application bundle. The authored bilingual content, application and workspace styles are encrypted before publication. The fixed access password and decrypted source are never committed here.

Keys are derived with PBKDF2-SHA256 (600,000 iterations) and a random salt. Decryption runs locally after entering the internal access password. A tab may retain its derived key for 12 hours; signing out clears it. The password itself has no expiry.

Only encrypted release files belong in this repository. The source archive remains private. Font licensing is in OFL.txt.
