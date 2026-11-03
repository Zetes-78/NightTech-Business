NIGHT TECH BUSINESS KIT (USB)
Night Tech Solutions · (864) 381-8510 · nighttech.solutions

Copy everything in this zip to the top of a USB stick. Nothing needs installing on the client's computers.
Reports and logs are saved on the stick (inside each tool's folder), not on the client's computer.
The "portable.txt" file next to each program is what tells it to do that. Don't delete it.

SECURITY CHECKUP
1. Open "Security Checkup\NightTechSecurityCheckup.exe" on a business computer.
2. Enter the business name, the Hub ticket number and your name.
3. Ask the owner the questions once. The answers are saved with the reports and carry over to each computer
   you check that day, including after "Restart as administrator". "Start a new visit" clears them.
4. Click "Restart as administrator", then "Run the checkup". It changes nothing.
5. "Open the owner's report" shows a plain-language report with the fixes in order.
6. After checking every computer: "Business summary" combines them into one page for the owner.
Attach the .txt reports to the Hub ticket.

NETWORK SCAN (network documenter)
Only scan a network the owner or manager has said you may check.
1. On a computer connected to the business network, open "Network Scan\NightTechNetworkScan.exe".
2. Enter the business, site, Hub ticket, your name and who gave permission. Tick the permission box and click
   "Scan this network" (1 to 3 minutes). The Range box has this network filled in: change it to scan part of
   it (192.168.1.100-150) or add other local networks such as a camera VLAN (192.168.1.0/24, 192.168.20.0/24). It pings, knocks on common ports and reads devices' own front pages.
   It never logs in or changes anything.
3. Devices tab: label what the owner names ("Front desk printer") and ask about anything Unknown.
4. Programs tab: this PC is read automatically. "Read Windows PCs over the network" works where your signed-in
   account is an administrator on them. Otherwise run Network Scan on each PC, click "Save this PC's programs to
   a file", and import those files (Field Kit reports work too).
5. Report tab: "Save and open the report". The .html is for the owner, the .csv spreadsheets list every device and
   program, and the .json goes on the Hub ticket.

AI SETUP (Private AI)
1. On the computer that will run the customer's AI, open "AI Setup\NightTechAiSetup.exe" and click Yes to the
   administrator prompt. It checks the computer and recommends an AI model.
2. Enter the name to show, the Hub ticket number, your name, and the customer's administrator user name and password.
   Let the customer type the password, or have them change it at first sign-in. Never write it down or keep it.
3. Click "Install Private AI". It installs the AI engine (Ollama, after checking its digital signature), downloads
   the model (several GB: use a fast connection), installs Night Tech Private AI, starts it with Windows and opens
   the firewall to this network only.
4. Open Private AI, sign in as the administrator, add the other people (Settings and users) and the documents.
Attach the setup report (.txt and .json in "AI Setup\Reports") to the Hub ticket.

The stick holds every client's security reports. Encrypt it (BitLocker To Go: right-click the stick in File Explorer,
"Turn on BitLocker") and keep it with you. Copy reports to the Hub ticket after each visit, then delete them from the stick.

Windows SmartScreen may warn the first time because the programs aren't code-signed yet:
click "More info", then "Run anyway".
