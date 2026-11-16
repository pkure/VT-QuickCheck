# VirusTotal Check: how to use it

**Highlight text anywhere on the Mac → right-click → VirusTotal Check.** Chrome opens the VirusTotal page for
each link, domain, IP address or file hash in what you highlighted (up to 5 tabs).

- On some apps the item sits under **right-click → Services → VirusTotal Check**.
- Works on defanged text from PhishFinder or reports: `hxxps://evil[.]com` is read as `https://evil.com`.
- It only **looks things up**. Nothing is uploaded or submitted for scanning, and no API key is used (it opens
  VirusTotal's own website, where you're signed in).
- VirusTotal does see what you look up. So the tool won't send a link that has an email address or a personal
  token in it; it looks up just the domain and tells you so. Private addresses (192.168.x.x, 10.x...) and file
  names like `Invoice.pdf` are skipped.
- If nothing recognizable is selected, a notification says so and nothing is sent.

**Keyboard shortcut (optional):** System Settings → Keyboard → Keyboard Shortcuts → Services → Text →
VirusTotal Check → double-click to add a shortcut (for example ⌃⌥V).

**Not showing up?** Run `/usr/bin/python3 ~/hal/code/vt-check/install.py` again, then quit and reopen the app
you're highlighting in. **Remove it:** delete `~/Library/Services/VirusTotal Check.workflow`.

**Tests:** `cd ~/hal/code/vt-check && /usr/bin/python3 -m unittest discover -s tests`
