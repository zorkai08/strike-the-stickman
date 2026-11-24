# Strike the Stickman V13.2 — Player Accounts

## Option 1: Play just the HTML file

Open `index.html`. Select **LOG IN / SIGN UP → CREATE ACCOUNT**, enter a new username and password. This creates a **local-only profile** and keeps weapons, coins, hits, combo, deaths, resets, best combo, skin, map, and name in **this browser's local storage**. You can log out and log into another local profile. If you clear browser data or switch devices, local profiles **do not transfer**. Browser profiles are not a substitute for secure online accounts.

## Option 2: Real cloud accounts across devices

Run **Node.js 20+** with these files together in the same folder:

```
node server.js
```

Visit `http://localhost:3000`, then select **LOG IN / SIGN UP → CREATE ACCOUNT**. When hosted online, deploy `index.html` and `server.js` as a running Node web service and access it over **HTTPS**. Other devices must use the **same hosted server** to see the account. Static-only hosts, such as GitHub Pages, cannot run `server.js`, so they cannot provide cross-device accounts by themselves.

- The server saves profiles in `data/accounts.json`. Keep this file private and back it up.
- Set a persistent writable `STICKMAN_DATA_DIR` environment directory on hosting that otherwise resets its filesystem on deployment. Do not put this directory in a public web folder or Git repository.
- Set `PORT` if required by your host; the server defaults to port `3000`.
- Passwords are stored as salted `scrypt` hashes, not plaintext. Login sessions use HTTP-only, SameSite cookies and expire after seven days (also expire if the server restarts). Rate limits are basic; for a large public game add production-grade protections, email recovery/verification, moderation, abuse prevention, and monitoring.
- You should use a **unique password** and avoid entering passwords used for any other website.

## Account progress behavior

- **Create account:** imports your current guest session's game progress into that new account.
- **Log in:** loads that account's existing game progress, replacing the active guest view without deleting the guest save.
- **Save:** automatically after progress changes; cloud profiles save after a short debounce and can also use **Save now**.
- **Log out:** restores the browser guest progress. Other users must log in to access their accounts.
- **Weapons:** weapon unlock order and the unlocked/locked distinction are preserved.

Game physics and spawned objects are not saved when you close the page; the permanent stats, profile choices, and unlocks are saved.

## Profile picture

Sign in, open **ACCOUNT**, then choose Upload picture or Remove. Images are center-cropped and compressed in the browser to a small JPEG; no original image or metadata is uploaded. The avatar is saved with the private account progress, not a public gallery. Update both index.html and server.js for cloud avatar support. Keep your existing data directory to retain existing accounts.
