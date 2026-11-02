# Night Tech Business Tools

In-house software for **Night Tech Solutions**' Business IT & Security services (https://nighttech.solutions/business-it/).
All our own code: the tools read what Windows itself reports and do their own checking and reporting. No third-party
security products are bundled. See `docs/ROADMAP.md` for every service line and the tool planned for it.

| Project | What it is | Status |
|---|---|---|
| `src/NightTech.Business.Core` | Shared: branding, logging, the Security Checkup rules and reports | v0.1 |
| `src/NightTech.SecurityCheckup` | **Night Tech Security Checkup**: checks a business computer's security and writes a plain-language report | v0.1 |
| `tests/NightTech.Business.Tests` | Automated tests (run on every push) | |

## Night Tech Security Checkup

Run on each computer at a business (from the USB kit or installed). Read only: nothing is changed, and passwords are
never read (for automatic sign-in it only notes whether a password is stored).

- **Device protection:** BitLocker, antivirus on and current, Defender real-time and tamper protection, firewall on every
  network type, Windows still supported, recent updates, Secure Boot, TPM
- **Accounts:** UAC, whether the signed-in person uses an admin account daily, admin accounts, built-in Administrator and
  Guest, accounts allowed a blank password, password length and lockout rules, automatic sign-in, screen lock
- **Network exposure:** Remote Desktop and Network Level Authentication, SMBv1, PowerShell 2.0, FTP/Telnet/VNC listening,
  shared folders, AutoRun
- **Software:** remote-control programs to confirm with the owner, software that no longer gets security fixes
- **Owner questions** (a computer can't show these): multi-factor sign-in on email and money accounts, password manager,
  off-site backup and restore tests, guest Wi-Fi, router password, removing former staff, scam awareness

Windows support dates come from a table by build and edition (`WindowsSupport.cs`); keep it current as Microsoft
publishes new versions. Each result is PASS, IMPROVE, FIX SOON, NOTE or NOT CHECKED (anything that couldn't be read
is shown as NOT CHECKED, never left out), with what was found and how to fix it. Reports: `.html` for
the owner (fixes in order), `.txt` for the Hub ticket, `.json` to combine. **Business summary** combines every computer's
report into one page ("BitLocker off on 2 of 3 computers: FRONT, OFFICE").

In portable mode the USB stick holds every client's reports: encrypt it with BitLocker To Go.

## Install and build

Download from this repository's **Releases** page: `NightTechSecurityCheckup-Setup.exe`, or `NightTechBusinessKit-USB.zip`
to run from a USB stick. Every push to `main` tests and builds on GitHub; publishing a Release attaches the files.
On a Windows PC: install the .NET 8 SDK and Inno Setup 6, then run `powershell -ExecutionPolicy Bypass -File .\build.ps1`.

Copyright (c) Night Tech Solutions. All rights reserved.
