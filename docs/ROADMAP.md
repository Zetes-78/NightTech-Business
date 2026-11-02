# Business IT & Security tooling roadmap

Every tool is our own code, with a Windows installer and a GitHub build, like the shop tools in NightTech-Tools.
Tools read what Windows and the business's own systems report; no third-party security products are bundled.

| Service line | Tool | Phase |
|---|---|---|
| Security Checkup | **Security Checkup** (Windows): device, account and exposure checks, owner questions, written report, business summary | 1 (v0.1 built) |
| Security Checkup | **Security Checkup: Microsoft 365 / Google Workspace**: which users lack multi-factor sign-in, admin count, mail forwarding rules (read-only, owner signs in) | 2 |
| Managed IT Plans | **Sentinel**: small read-only agent on client PCs: drive health, disk space, updates, antivirus, backup status; alerts and a monthly client report | 2 |
| Managed IT Plans | **Hub business module**: business clients, plans, sites, equipment list, monthly report, renewal reminders; Square stays the payment system | 2 |
| Backup & Recovery Setup | **Backup Buddy** finished for business use, plus backup monitoring in Sentinel | 2 |
| Network & Wi-Fi Support | **Network documenter**: device discovery, Wi-Fi survey, DHCP/DNS/gateway, open-port summary, network map report (only with the owner's permission) | 3 |
| New Computer Setup | **Move kit**: copies user files and browser bookmarks, records installed programs, checklist and handoff report | 3 |
| Website Care Plans | **Site monitor**: uptime, SSL certificate and domain expiry checks for client sites, monthly report | 3 |
| Private AI Setup | **Private AI kit**: hardware sizing check, local AI setup script, privacy checklist | 3 |
| IT Consulting | Equipment age and replacement planning from Field Kit and Sentinel data, in the Hub business module | 3 |
| POS System Support | POS computers in Sentinel (uptime, disk, updates), printer and network checks, POS notes in the Hub | 3 |

## Standing rules
- Read-only by default. Anything that changes a client system asks first and is logged.
- Never store client passwords. Reports never include passwords or keys.
- Network scanning only on networks the owner has given permission to check.
- Reports describe what was checked; they are not a guarantee a business can't be breached.
