# Night Tech Business Tools

In-house software for **Night Tech Solutions**' Business IT & Security services (https://nighttech.solutions/business-it/).
All our own code: the tools read what Windows itself reports and do their own checking and reporting. No third-party
security products are bundled. See `docs/ROADMAP.md` for every service line and the tool planned for it.

| Project | What it is | Status |
|---|---|---|
| `src/NightTech.Business.Core` | Shared: branding, logging, the Security Checkup rules and reports | v0.1 |
| `src/NightTech.SecurityCheckup` | **Night Tech Security Checkup**: checks a business computer's security and writes a plain-language report | v0.1 |
| `src/NightTech.PrivateAi` | **Night Tech Private AI**: the private AI chat app that runs on the customer's computer, for their network only | v0.1 |
| `src/NightTech.AiSetup` | **Night Tech AI Setup**: technician tool that checks the hardware and installs Private AI | v0.1 |
| `tests/NightTech.Business.Tests` | Automated tests (run on every push) | |

## Night Tech Private AI

An AI assistant that runs on a computer the customer owns. Our own app on top of Ollama (the open-source engine that
runs the model); the model is an open one (Gemma, Llama, Qwen, Phi, gpt-oss, Mistral) downloaded once.

- **Network only:** answers only computers on the same network (private ranges and the computer's own network prefixes),
  and only by this computer's own name or address. Firewall rule limited to the local subnet, Private/Domain networks.
- **Sign-ins:** each person has an account (salted PBKDF2-SHA256; passwords are never stored). 12-hour sessions; changing
  a password or admin status ends that person's sign-ins. Wrong passwords lock a name for 5 minutes after 5 tries.
- **Chats** are private to each person (`chats\<user>\*.json`). Answers stream in as they're written.
- **Document library:** administrators add PDF, Word, Excel, PowerPoint, text and web pages. Our own readers extract the
  text (no outside libraries), it's split into passages and indexed with a small local "embedding" model. With
  "Answer from our documents" on, the AI answers from the closest passages and shows which file and page each came from.
- **Data:** `C:\ProgramData\Night Tech Private AI` (settings, accounts, chats, library, logs), limited to administrators
  and Windows itself. Models in `C:\ProgramData\Night Tech Private AI Models` (read-only for users).
- Runs as a startup task (as Windows itself) so it works before anyone signs in, and starts the AI engine itself when
  needed. The page has a strict Content-Security-Policy and builds everything with DOM calls (no HTML injection).
- Command line for the setup tool: `NightTechPrivateAi.exe add-user <name> [--admin] [--display "Name"]` and
  `set-password <name>` (password on standard input), `status`.

## Night Tech AI Setup

Run as administrator on the customer's computer (installed, or from the USB kit). It reads the processor, memory, graphics
cards (real memory size from the driver registry and `nvidia-smi`) and disk, recommends a model, then: installs Ollama
under Program Files (only after Windows confirms the installer is signed by Ollama), downloads the models, copies Private
AI to Program Files, saves settings and locks the data folder, creates the administrator, registers the startup task,
adds the firewall rule and checks it answers. Every step is logged and re-runnable. Writes a setup report (`.txt` for the
customer, `.json` for the Hub ticket). "Remove Private AI" takes it off again.

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
