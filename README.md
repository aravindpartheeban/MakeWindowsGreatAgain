<div align="center">
  
# MakeWindowsGreatAgain
</div>


<p align="center">
  <img src="docs/logo.png" alt="Logo" width="256" height="256">
</p>

<p align="center">
  <strong>A powerful, all-in-one Windows optimization toolkit</strong>
</p>

---

## Overview

MakeWindowsGreatAgain is a comprehensive Windows optimization utility that helps you debloat your system, apply performance and privacy tweaks, install applications quickly, and configure network settings—all through a modern dark-themed interface.

## Download

Download the latest `MakeWindowsGreatAgain.exe` from the [Releases](https://github.com/aravindpartheeban/MakeWindowsGreatAgain/releases/download/latest/MakeWindowsGreatAgain_V1.0.zip) page and run as Administrator.

## Requirements

- Windows 10 (1903+) or Windows 11
- Administrator privileges

---

## Features

### 📊 Dashboard
- System info: CPU, GPU, RAM and Disk
- Windows version and build information
- Quick access to optimization categories

### 📦 Install Apps
One-click installation of 100+ popular applications via winget, organized by category:
- **Browsers**: Chrome, Firefox, Brave, Edge, Vivaldi, Opera, Tor
- **Utilities**: 7-Zip, WinRAR, PowerToys, Everything Search, TreeSize
- **Development**: VS Code, Git, Python, Node.js, Docker, WSL
- **Gaming**: Steam, Epic Games, GOG Galaxy, Discord
- **Media**: VLC, Spotify, OBS Studio, Audacity, GIMP
- **And many more...**

---

## Tweaks Reference

### Essential Tweaks

| Tweak | Description |
|-------|-------------|
| Delete Temporary Files | Clears Windows and user temp folders |
| Disable Hibernation | Disables hibernation to save disk space (recommended for desktops) |
| Disable Activity History | Stops Windows from collecting activity history |
| Run Disk Cleanup | Silently runs disk cleanup and DISM component cleanup |
| Enable End Task on Taskbar | Adds "End Task" option when right-clicking apps in taskbar |
| Disable Explorer Auto-Discovery | Stops Explorer from guessing folder types (improves performance) |
| Debloat Microsoft Edge | Disables Edge telemetry, shopping features, and promotions |

### Advanced Tweaks ⚠️

| Tweak | Description |
|-------|-------------|
| Set Classic Right-Click Menu | Restores Windows 10 context menu on Windows 11 |
| Remove Home from Explorer | Removes Home page and sets This PC as default |
| Remove Gallery from Explorer | Removes Gallery from Explorer navigation |
| Set Time to UTC | Fixes time sync issues for dual-boot with Linux |
| Set Display for Performance | Disables visual effects for better performance |
| Disable Storage Sense | Prevents automatic temp file deletion |
| Disable Notification Tray | Disables notification center and calendar |
| Adobe Network Block | Blocks Adobe activation and telemetry servers |
| Block Razer Software | Prevents automatic Razer software installation |
| Prefer IPv4 over IPv6 | Sets IPv4 preference for potential latency benefits |
| Disable Teredo | Disables IPv6 tunneling (may improve gaming latency) |
| Disable IPv6 | Completely disables IPv6 |
| Disable Background Apps | Prevents Store apps from running in background |
| Disable Fullscreen Optimizations | Disables FSO for all applications |
| Disable Windows Platform Binary Table | Prevents vendor software auto-installation |

### Customize Preferences (Toggles)

| Setting | Description |
|---------|-------------|
| Dark Theme | Enable/disable Windows dark mode |
| NumLock on Startup | Toggle NumLock state at boot |
| Verbose Logon Messages | Show detailed messages during login |
| Remove Settings Home Page | Hides Home page in Windows Settings |
| Snap Window | Enable/disable window snapping |
| Snap Assist Flyout | Toggle snap preview on maximize button hover |
| Snap Assist Suggestion | Toggle snap suggestions for remaining space |
| Mouse Acceleration | Enable/disable pointer precision |
| Sticky Keys | Enable/disable sticky keys accessibility feature |
| Center Taskbar Items | Toggle taskbar alignment (Windows 11) |
| Disable Multiplane Overlay | Fixes some graphics card issues |
| Cross-Device Resume | Toggle activity resume across devices |
| Ultimate Performance | Enables hidden Ultimate Performance power plan |

---

## Privacy Settings

| Setting | Description |
|---------|-------------|
| Disable Telemetry | Stops Windows data collection and disables DiagTrack service |
| Disable Activity History | Prevents activity history collection |
| Disable Location Tracking | Disables location services |
| Disable Advertising ID | Stops personalized advertising |
| Disable Cortana | Disables Cortana assistant |
| Disable Consumer Features | Prevents auto-installation of suggested apps |
| Disable PowerShell 7 Telemetry | Opts out of PowerShell telemetry |
| Disable Bing Search | Removes Bing from Start menu search |
| Disable Feedback Notifications | Stops Windows feedback requests |
| Disable Tailored Experiences | Prevents diagnostic data-based suggestions |
| Disable Error Reporting | Disables Windows Error Reporting |
| Disable App Launch Tracking | Stops tracking which apps you launch |

---

## Debloat

Remove pre-installed Microsoft apps selectively:
- 3D Viewer, 3D Builder
- Bing Weather, News, Finance
- Clipchamp, Cortana
- Get Help, Get Started
- Mail and Calendar
- Maps, Mixed Reality Portal
- Office Hub, OneNote
- Paint 3D, People
- Phone Link, Photos (legacy)
- Skype, Solitaire Collection
- Sticky Notes, Tips
- To Do, Voice Recorder
- Xbox apps, Zune apps
- And more...

---

## Network Tools

### DNS Providers

| Provider | Primary | Secondary | DoH Support |
|----------|---------|-----------|-------------|
| Cloudflare | 1.1.1.1 | 1.0.0.1 | ✅ |
| Cloudflare (Malware) | 1.1.1.2 | 1.0.0.2 | ✅ |
| Cloudflare (Family) | 1.1.1.3 | 1.0.0.3 | ✅ |
| Google | 8.8.8.8 | 8.8.4.4 | ✅ |
| Quad9 | 9.9.9.9 | 149.112.112.112 | ✅ |
| Quad9 (Unfiltered) | 9.9.9.10 | 149.112.112.10 | ✅ |
| OpenDNS | 208.67.222.222 | 208.67.220.220 | ✅ |
| OpenDNS (Family) | 208.67.222.123 | 208.67.220.123 | ✅ |
| AdGuard | 94.140.14.14 | 94.140.15.15 | ✅ |
| AdGuard (Family) | 94.140.14.15 | 94.140.15.16 | ✅ |
| NextDNS | 45.90.28.167 | 45.90.30.167 | ✅ |
| Control D | 76.76.2.0 | 76.76.10.0 | ✅ |
| Mullvad | 194.242.2.2 | - | ✅ |

### Network Repair Tools

| Tool | Description |
|------|-------------|
| Flush DNS | Clears DNS resolver cache |
| Reset TCP/IP | Resets TCP/IP stack to default |
| Release/Renew IP | Releases and renews DHCP lease |
| Reset Winsock | Resets Winsock catalog to clean state |

---

## Credits

- Chris Titus's WinUtil
- Rapphire's Debloat Script

## Notes

- ⚠️ **Create a restore point** before applying advanced tweaks
- 🔄 Some changes require a **restart** or **sign-out**
- 📝 All operations are logged to `log.txt`
- 🛡️ Run as **Administrator** for full functionality

---

<p align="center">
  Made with ❤️ for a better Windows experience
</p>
