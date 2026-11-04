# Sentinel server on the home Windows Server 2025

The plan: run the Sentinel server in a small Ubuntu virtual machine (Hyper-V) on the Server 2025 box at home, reached from
the internet through **Cloudflare Tunnel**. Nothing is opened on the router, a changing Spectrum IP doesn't matter, and the
home IP stays hidden.

Later, when clients depend on it, the same setup can move to a cloud server (Oracle Always Free or a $6–12 VPS) by copying
the Docker data volume and pointing the hostname at the new tunnel.

## Before starting: the domain

The tunnel needs the domain's DNS to be managed in Cloudflare.

- If **nighttech.solutions** is already in Cloudflare: use `sentinel.nighttech.solutions`.
- If it isn't: don't move it in a hurry (the website and email records would all have to be copied exactly). Buy a cheap
  second domain through Cloudflare (about $10/year, for example `nighttech-sentinel.com`) and use that.

## 1. The virtual machine (Server 2025, PowerShell as administrator)

```powershell
Install-WindowsFeature -Name Hyper-V -IncludeManagementTools -Restart
```

After the restart, download the Ubuntu Server 24.04 ISO from ubuntu.com, then:

```powershell
$nic = (Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -First 1).Name
New-VMSwitch -Name "External" -NetAdapterName $nic -AllowManagementOS $true
New-VM -Name "Sentinel" -Generation 2 -MemoryStartupBytes 2GB -NewVHDPath "C:\Hyper-V\Sentinel.vhdx" -NewVHDSizeBytes 30GB -SwitchName "External"
Set-VMProcessor -VMName "Sentinel" -Count 2
Set-VMFirmware -VMName "Sentinel" -SecureBootTemplate MicrosoftUEFICertificateAuthority
Add-VMDvdDrive -VMName "Sentinel" -Path "C:\ISO\ubuntu-24.04-live-server-amd64.iso"
Set-VMFirmware -VMName "Sentinel" -FirstBootDevice (Get-VMDvdDrive -VMName "Sentinel")
Set-VM -Name "Sentinel" -AutomaticStartAction Start -AutomaticStopAction ShutDown
Start-VM "Sentinel"
```

- Change the ISO path to wherever it was saved.
- Creating the switch drops the server's network for a few seconds; that's normal.
- Open the VM in Hyper-V Manager and install Ubuntu: choose **Install OpenSSH server** and automatic networking.

## 2. The tunnel (Cloudflare dashboard)

1. Zero Trust > Networks > Tunnels > **Create a tunnel** > Cloudflared. Name it `sentinel`.
2. Copy the **token** (the long string after `--token` in the install command shown). Don't run that command; Docker runs
   the tunnel.
3. Add a **public hostname**: `sentinel.<domain>`, service type **HTTP**, URL **`sentinel:8080`**.

## 3. Sentinel inside the VM

SSH in (`ssh <user>@<VM IP>`; the IP shows on the VM's login screen), then:

```bash
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER && newgrp docker
git clone --recurse-submodules https://github.com/Zetes-78/NightTech-Business.git
cd NightTech-Business/deploy/sentinel
cp .env.example .env
nano .env     # SENTINEL_DOMAIN=sentinel.<domain>  and  CLOUDFLARE_TUNNEL_TOKEN=<token>
docker compose --profile tunnel up -d --build
docker compose logs sentinel | grep -i "setup code"
```

## 4. First sign-in and first PC

1. Open `https://sentinel.<domain>`, enter the setup code, create the account, and add the two-step key to NightKey.
2. Start **Sentinel Signer** (`NightTechSentinelSigner.exe` from the release), put the server address in its Settings, and
   register its public key in the console: Settings > Sentinel Signer keys. Check the key ID matches.
3. In the Signer, make an enrollment code for a test client, and install `NightTechSentinel-Setup.exe` on a spare PC.
4. Test: Request help from the tray icon, one action (Shield scan), a remote shell and a remote desktop session.

## Upkeep

- Update: `cd ~/NightTech-Business && git pull --recurse-submodules && cd deploy/sentinel && docker compose --profile tunnel up -d --build`
- Logs: `docker compose logs -f sentinel`
- The VM starts with the server, and the tunnel reconnects by itself after an internet outage.
- Back up the `sentinel-data` Docker volume (it holds clients, PCs, technicians and the activity log).
