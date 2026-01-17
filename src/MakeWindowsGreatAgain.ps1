# ==============================================================================
# WINDOWS OPTIMIZER (PowerShell + WPF)
# ==============================================================================
# Sections: BOOTSTRAP | STATE | LOGGING | HELPERS | TWEAK CORE | INSTALLERS |
#           DATA | UI | ENTRY POINT
# ==============================================================================

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

# ==============================================================================
# SECTION 1: BOOTSTRAP (Admin Check, Assemblies, DPI)
# ==============================================================================
# Robust detection: If $PSCommandPath is set, we are a script. If it's empty, we are typically an EXE.
if ($PSCommandPath) {
  # Running as .ps1 script
  $IsExe = $false
  $ScriptPath = Split-Path -Parent $PSCommandPath
  $ExePath = $PSCommandPath
}
else {
  # Running as compiled .exe
  $IsExe = $true
  $ScriptPath = [System.AppDomain]::CurrentDomain.BaseDirectory
  $ExePath = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
}

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "Elevating privileges..."
  if ($IsExe) {
    # Relaunch the EXE itself as Admin
    Start-Process -FilePath $ExePath -Verb RunAs
  }
  else {
    # Relaunch the script
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$ExePath`"" -Verb RunAs
  }
  Exit
}

# ==============================================================================
# SECTION 9: ENTRY POINT (Main execution wrapped in try/catch)
# ==============================================================================
try {

  Add-Type -AssemblyName PresentationFramework
  Add-Type -AssemblyName System.Windows.Forms
  [System.Windows.Forms.Application]::EnableVisualStyles()

  # Enable Per-Monitor DPI Awareness for sharp rendering on high-DPI displays
  Add-Type -TypeDefinition @"
    using System;
    using System.Runtime.InteropServices;
    public class DpiAwareness {
        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool SetProcessDpiAwarenessContext(int value);
        public const int DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = -4;
    }
"@
  try {
    [DpiAwareness]::SetProcessDpiAwarenessContext([DpiAwareness]::DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) | Out-Null
  }
  catch {
    # Fallback for older Windows versions - ignore if not supported
  }

  $ScriptDir = $ScriptPath

  # ==============================================================================
  # SECTION 2: STATE (Global state object)
  # ==============================================================================
  $Global:OptimizerState = @{
    IsAdmin             = $true  # Already checked above
    ProcessRunning      = $false
    AppliedTweaks       = @()
    Errors              = @()
    LogFile             = Join-Path $ScriptDir "log.txt"
    LastStatusUpdate    = [DateTime]::MinValue
    ToggleInitialStates = @{}
    EssentialItems      = @()
    PrivacyItems        = @()
    DebloatItems        = @()
  }

  # ==============================================================================
  # SECTION 3: LOGGING
  # ==============================================================================
  $script:LogFile = $Global:OptimizerState.LogFile
  
  function Write-Log {
    param(
      [string]$Message,
      [ValidateSet("INFO", "SUCCESS", "WARNING", "ERROR", "SKIPPED")]
      [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$timestamp] [$Level] $Message"
    Add-Content -Path $script:LogFile -Value $entry -Encoding UTF8
  }
  
  # Write session header
  Write-Log "========================================"
  Write-Log "Windows Optimizer Session Started"
  Write-Log "OS: $([Environment]::OSVersion.VersionString)"
  Write-Log "========================================"
    
  # ==============================================================================
  # SECTION 4: HELPERS (Registry, Services, Explorer, UI)
  # ==============================================================================

  # Unified registry setter - replaces duplicate code throughout
  function Set-RegistryValue {
    param(
      [Parameter(Mandatory)][string]$Path,
      [Parameter(Mandatory)][string]$Name,
      [Parameter(Mandatory)]$Value,
      [string]$Type = "DWord"
    )
    
    $fullPath = $Path -replace "HKLM:", "Registry::HKEY_LOCAL_MACHINE" `
      -replace "HKCU:", "Registry::HKEY_CURRENT_USER"
    
    if (-not (Test-Path $fullPath)) {
      New-Item -Path $fullPath -Force | Out-Null
    }
    Set-ItemProperty -Path $fullPath -Name $Name -Value $Value -Type $Type -Force
    Write-Log "Registry: $fullPath\$Name = $Value" "SUCCESS"
  }

  # Unified service configuration
  function Set-ServiceState {
    param(
      [Parameter(Mandatory)][string]$Name,
      [Parameter(Mandatory)][string]$StartupType
    )
    
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $svc) {
      Write-Log "Service not found: $Name" "SKIPPED"
      return $false
    }
    
    if ($StartupType -eq "AutomaticDelayedStart") {
      sc.exe config $Name start= delayed-auto | Out-Null
    }
    else {
      Set-Service -Name $Name -StartupType $StartupType -ErrorAction Stop
    }
    
    if ($StartupType -eq "Disabled") {
      Stop-Service -Name $Name -ErrorAction SilentlyContinue
    }
    Write-Log "Service: $Name -> $StartupType" "SUCCESS"
    return $true
  }

  # Single explorer restart - call once at end of all tweaks
  function Restart-Explorer {
    try {
      Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
      Start-Sleep -Milliseconds 500
      Start-Process explorer.exe
      Write-Log "Explorer restarted" "INFO"
    }
    catch {
      Write-Log "Explorer restart failed: $_" "WARNING"
    }
  }

  # Debounced UI status update (100ms throttle)
  function Update-Status {
    param([string]$Message)
    $now = [DateTime]::Now
    if (($now - $Global:OptimizerState.LastStatusUpdate).TotalMilliseconds -gt 100) {
      if ($null -ne $StatusText) {
        $Window.Dispatcher.Invoke({ $StatusText.Text = $Message })
      }
      $Global:OptimizerState.LastStatusUpdate = $now
    }
  }

  # ==============================================================================
  # SECTION 4B: HANDLER FUNCTIONS
  # ==============================================================================
  
  # Tweak handler - processes registry, service, script, scheduledtask

  
  # App install handler - uses winget (Supports batch)
  function Invoke-AppInstallHandler {
    param(
      [Parameter(Mandatory)][Object[]]$App,
      [switch]$WhatIf
    )
    
    if (-not $App) { return @{ Success = $false; Error = "No apps provided" } }

    # 1. Ensure Winget is available
    if (-not $WhatIf) {
      $wingetInstalled = Install-WinUtilWinget
      if (-not $wingetInstalled) {
        return @{ Success = $false; Error = "Winget installation failed" }
      }
    }

    # 2. Extract IDs
    $ids = @()
    foreach ($item in $App) {
      if ($item -is [String]) { $ids += $item }
      elseif ($item.winget) { $ids += $item.winget }
      elseif ($item.Tag) { $ids += $item.Tag }
    }

    if ($ids.Count -eq 0) {
      return @{ Success = $false; Error = "No valid Winget IDs found" }
    }
    
    if ($WhatIf) {
      return @{ Success = $true; Info = "Would install: $($ids -join ', ')" }
    }
    
    # 3. Batch Install
    $failed = Install-WinUtilProgramWinget -Programs $ids -Action "Install"
    
    if ($failed.Count -eq 0) {
      return @{ Success = $true }
    }
    else {
      return @{ Success = $false; Error = "Failed to install: $($failed -join ', ')" }
    }
  }
  
  # Debloat handler - removes various types of apps
  function Invoke-DebloatHandler {
    param(
      [Parameter(Mandatory)][string]$PackageName,
      [string]$Type,
      [string]$DisplayName,
      [switch]$WhatIf
    )
    
    if (-not $PackageName) {
      Write-Log "Skipping $($DisplayName) (no package name)" "WARNING"
      return @{ Success = $false; Error = "No package name" }
    }
    
    if ($WhatIf) {
      return @{ Success = $true }
    }

    Write-Log "Removing $($DisplayName) [$Type] ($PackageName)"

    switch ($Type) {
      "appx" {
        try {
          Get-AppxPackage -Name "*$PackageName*" -ErrorAction Stop |
          Remove-AppxPackage -ErrorAction Stop
          Write-Log "Removed (AppX): $($DisplayName)" "SUCCESS"
          return @{ Success = $true }
        }
        catch {
          Write-Log "Failed (AppX): $($DisplayName) - $($_.Exception.Message)" "ERROR"
          return @{ Success = $false; Error = $_.Exception.Message }
        }
      }

      "provisioned" {
        $errorMsg = ""
        # PRIMARY: current user AppX removal
        try {
          Get-AppxPackage -Name "*$PackageName*" -ErrorAction Stop |
          Remove-AppxPackage -ErrorAction Stop
          Write-Log "Removed (AppX): $($DisplayName)" "SUCCESS"
        }
        catch {
          Write-Log "Failed (AppX): $($DisplayName) - $($_.Exception.Message)" "ERROR"
          $errorMsg = $_.Exception.Message
        }

        # SECONDARY: provisioned removal (best effort, silent)
        try {
          Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue |
          Where-Object { $_.PackageName -like "*$PackageName*" } |
          ForEach-Object {
            Remove-AppxProvisionedPackage `
              -Online `
              -PackageName $_.PackageName `
              -ErrorAction SilentlyContinue
          }
        }
        catch {}
        
        if ($errorMsg) { return @{ Success = $false; Error = $errorMsg } }
        return @{ Success = $true }
      }

      "win32" {
        switch ($PackageName) {
          "OneDrive" {
            try {
              Stop-Process -Name "OneDrive" -Force -ErrorAction SilentlyContinue
              $setup = "$env:SystemRoot\SysWOW64\OneDriveSetup.exe"
              if (-not (Test-Path $setup)) {
                $setup = "$env:SystemRoot\System32\OneDriveSetup.exe"
              }

              if (Test-Path $setup) {
                Start-Process -FilePath $setup -ArgumentList "/uninstall" -Wait -WindowStyle Hidden
                Remove-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\OneDrive" -ErrorAction SilentlyContinue
                Write-Log "Removed (Win32): $($DisplayName)" "SUCCESS"
                return @{ Success = $true }
              }
              else {
                Write-Log "OneDrive uninstaller not found" "ERROR"
                return @{ Success = $false; Error = "Uninstaller not found" }
              }
            }
            catch {
              Write-Log "Failed (Win32): $($DisplayName) - $($_.Exception.Message)" "ERROR"
              return @{ Success = $false; Error = $_.Exception.Message }
            }
          }
          default {
            Write-Log "No Win32 handler defined for $($DisplayName)" "WARNING"
            return @{ Success = $false; Error = "No handler" }
          }
        }
      }

      default {
        Write-Log "Unknown type '$Type' for $($DisplayName)" "WARNING"
        return @{ Success = $false; Error = "Unknown type" }
      }
    }
  }
  
  # DNS handler - configures DNS on adapter
  function Invoke-DnsHandler {
    param(
      [Parameter(Mandatory)][PSObject]$DnsProvider,
      [Parameter(Mandatory)][string]$AdapterName,
      [switch]$WhatIf
    )
    
    if (-not $DnsProvider.servers -or $DnsProvider.servers.Count -eq 0) {
      return @{ Success = $false; Error = "Missing DNS servers" }
    }
    
    if (-not $WhatIf) {
      Set-DnsClientServerAddress -InterfaceAlias $AdapterName -ServerAddresses $DnsProvider.servers
      Write-Log "DNS set to: $($DnsProvider.servers -join ', ')" "SUCCESS"
      
      # Enable DoH if template available
      if ($DnsProvider.doh) {
        try {
          foreach ($server in $DnsProvider.servers) {
            Set-DnsClientDohServerAddress -ServerAddress $server -DohTemplate $DnsProvider.doh -AllowFallbackToUdp $true -ErrorAction SilentlyContinue
          }
          # Create global setting if possible, but don't fail if parameter missing
          # Set-DnsClientGlobalSetting -DohOptions 2 -ErrorAction SilentlyContinue
          Write-Log "DoH enabled: $($DnsProvider.doh)" "SUCCESS"
        }
        catch {
          Write-Log "DoH configuration failed: $_" "WARNING"
        }
      }
    }
    
    return @{ Success = $true }
  }
  
  # Network handler - processes command/registry based on item type
  function Invoke-NetworkHandler {
    param(
      [Parameter(Mandatory)][PSObject]$Item,
      [switch]$WhatIf
    )
    
    $result = @{ Success = $true }
    $itemType = if ($Item.PSObject.Properties.Name -contains 'type') { $Item.type } else { '' }
    
    switch ($itemType) {
      "command" {
        if (-not $WhatIf) {
          Start-Process cmd.exe -ArgumentList "/c $($Item.script)" -WindowStyle Hidden -Wait -Verb RunAs
        }
      }
      "registry" {
        if (-not $WhatIf) {
          $path = $Item.path.Replace("HKLM\", "HKLM:\").Replace("HKCU\", "HKCU:\")
          Set-RegistryValue -Path $path -Name $Item.name -Value $Item.value -Type $Item.value_type
        }
      }
      "registry_group" {
        if ($Item.entries) {
          foreach ($entry in $Item.entries.PSObject.Properties) {
            if (-not $WhatIf) {
              $path = $Item.path.Replace("HKLM\", "HKLM:\").Replace("HKCU\", "HKCU:\")
              Set-RegistryValue -Path $path -Name $entry.Name -Value $entry.Value.value -Type $entry.Value.value_type
            }
          }
        }
      }
      default {
        Write-Log "Unknown network item type: $itemType" "WARNING"
        $result.Success = $false
      }
    }
    
    return $result
  }
  
  # Main dispatcher - routes to appropriate handler based on handler property
  function Invoke-Handler {
    param(
      [Parameter(Mandatory)][PSObject]$Entry,
      [string]$Key = "",
      [string]$AdapterName = "",
      [bool]$ToggleState = $false,
      [switch]$WhatIf
    )
    
    # Try to access handler property (works for both Hashtable and PSObject)
    $handler = $Entry.handler
    
    if (-not $handler) {
      Write-Log "No handler defined for entry" "WARNING"
      return @{ Success = $false; Error = "No handler" }
    }
    
    switch ($handler) {
      "tweak" { 
        # Use existing Invoke-Tweak for compatibility
        return Invoke-Tweak -TweakId $Key -TweakData $Entry -WhatIf:$WhatIf 
      }
      "toggle" { 
        # Use existing Invoke-Tweak with IsUndo based on toggle state
        return Invoke-Tweak -TweakId $Key -TweakData $Entry -IsUndo:(-not $ToggleState) -WhatIf:$WhatIf 
      }
      "app-install" { return Invoke-AppInstallHandler -App $Entry -WhatIf:$WhatIf }
      "debloat" { return Invoke-DebloatHandler -PackageName $Key -Type $Entry.Type -DisplayName $Entry.Name -WhatIf:$WhatIf }
      "dns" { return Invoke-DnsHandler -DnsProvider $Entry -AdapterName $AdapterName -WhatIf:$WhatIf }
      "network-repair" { return Invoke-NetworkHandler -Item $Entry -WhatIf:$WhatIf }
      "network-gaming" { return Invoke-NetworkHandler -Item $Entry -WhatIf:$WhatIf }
      "advanced-TCP" { return Invoke-NetworkHandler -Item $Entry -WhatIf:$WhatIf }
      default {
        Write-Log "Unknown handler: $handler" "WARNING"
        return @{ Success = $false; Error = "Unknown handler: $handler" }
      }
    }
  }

  # ==============================================================================
  # SECTION 5: DATA (Embedded JSON)
  # ==============================================================================
  $AppsJson = @'
{
  "7zip": {
    "Content": "7-Zip",
    "Description": "7-Zip is a file archiver with a high compression ratio.",
    "category": "Utilities",
    "winget": "7zip.7zip",
    "link": "https://www.7-zip.org/",
    "handler": "app-install"
  },
  "androidplatformtools": {
    "Content": "Android Platform Tools",
    "Description": "Android SDK Platform-Tools is a component for the Android SDK.",
    "category": "Utilities",
    "winget": "Google.PlatformTools",
    "link": "https://developer.android.com/studio/releases/platform-tools",
    "handler": "app-install"
  },
  "anydesk": {
    "Content": "AnyDesk",
    "Description": "AnyDesk is a remote desktop application taking a new approach to remote desktop.",
    "category": "Utilities",
    "winget": "AnyDeskSoftwareGmbH.AnyDesk",
    "link": "https://anydesk.com/",
    "handler": "app-install"
  },
  "audacity": {
    "Content": "Audacity",
    "Description": "Audacity is a free, easy-to-use, multi-track audio editor and recorder.",
    "category": "Multimedia",
    "winget": "Audacity.Audacity",
    "link": "https://www.audacityteam.org/",
    "handler": "app-install"
  },
  "autohotkey": {
    "Content": "AutoHotkey",
    "Description": "AutoHotkey is a free, open-source custom scripting language for Windows.",
    "category": "Utilities",
    "winget": "AutoHotkey.AutoHotkey",
    "link": "https://www.autohotkey.com/",
    "handler": "app-install"
  },
  "axcrypt": {
    "Content": "AxCrypt",
    "Description": "AxCrypt is a file encryption software.",
    "category": "Utilities",
    "winget": "AxCrypt.AxCrypt",
    "link": "https://www.axcrypt.net/",
    "handler": "app-install"
  },
  "balenaetcher": {
    "Content": "balenaEtcher",
    "Description": "Flash OS images to SD cards & USB drives, safely and easily.",
    "category": "Utilities",
    "winget": "Balena.Etcher",
    "link": "https://www.balena.io/etcher/",
    "handler": "app-install"
  },
  "bitwarden": {
    "Content": "Bitwarden",
    "Description": "Bitwarden is an open-source password management solution. It allows users to store and manage their passwords in a secure and encrypted vault, accessible across multiple devices.",
    "category": "Utilities",
    "winget": "Bitwarden.Bitwarden",
    "link": "https://bitwarden.com/",
    "handler": "app-install"
  },
  "BorderlessGaming": {
    "Content": "Borderless Gaming",
    "Description": "Play your favorite games in a borderless window; no more time consuming alt-tabs.",
    "category": "Utilities",
    "winget": "Codeusa.BorderlessGaming",
    "link": "https://github.com/Codeusa/Borderless-Gaming",
    "handler": "app-install"
  },
  "bulkcrapuninstaller": {
    "Content": "Bulk Crap Uninstaller",
    "Description": "Bulk Crap Uninstaller is a free and open-source uninstaller utility for Windows. It helps users remove unwanted programs and clean up their system by uninstalling multiple applications at once.",
    "category": "Utilities",
    "winget": "Klocman.BulkCrapUninstaller",
    "link": "https://www.bcuninstaller.com/",
    "handler": "app-install"
  },
  "bulkrenameutility": {
    "Content": "Bulk Rename Utility",
    "Description": "Bulk Rename Utility allows you to easily rename files and folders recursively based upon find-replace, character place, fields, sequences, regular expressions, EXIF data, and more.",
    "category": "Utilities",
    "winget": "TGRMNSoftware.BulkRenameUtility",
    "link": "https://www.bulkrenameutility.co.uk",
    "handler": "app-install"
  },
  "capframex": {
    "Content": "CapFrameX",
    "Description": "Frametimes capture and analysis tool based on Intel's PresentMon. Overlay provided by Rivatuner Statistics Server.",
    "category": "Utilities",
    "winget": "CXWorld.CapFrameX",
    "link": "https://www.capframex.com/",
    "handler": "app-install"
  },
  "cpuz": {
    "Content": "CPU-Z",
    "Description": "CPU-Z is a system monitoring and diagnostic tool for Windows. It provides detailed information about the computer's hardware components, including the CPU, memory, and motherboard.",
    "category": "Utilities",
    "winget": "CPUID.CPU-Z",
    "link": "https://www.cpuid.com/softwares/cpu-z.html",
    "handler": "app-install"
  },
  "croc": {
    "Content": "croc",
    "Description": "Easily and securely send things from one computer to another.",
    "category": "Utilities",
    "winget": "schollz.croc",
    "link": "https://github.com/schollz/croc",
    "handler": "app-install"
  },
  "crystaldiskinfo": {
    "Content": "Crystal Disk Info",
    "Description": "Crystal Disk Info is a disk health monitoring tool that provides information about the status and performance of hard drives. It helps users anticipate potential issues and monitor drive health.",
    "category": "Utilities",
    "winget": "CrystalDewWorld.CrystalDiskInfo",
    "link": "https://crystalmark.info/en/software/crystaldiskinfo/",
    "handler": "app-install"
  },
  "crystaldiskmark": {
    "Content": "Crystal Disk Mark",
    "Description": "Crystal Disk Mark is a disk benchmarking tool that measures the read and write speeds of storage devices. It helps users assess the performance of their hard drives and SSDs.",
    "category": "Utilities",
    "winget": "CrystalDewWorld.CrystalDiskMark",
    "link": "https://crystalmark.info/en/software/crystaldiskmark/",
    "handler": "app-install"
  },
  "ddu": {
    "Content": "Display Driver Uninstaller",
    "Description": "Display Driver Uninstaller (DDU) is a tool for completely uninstalling graphics drivers from NVIDIA, AMD, and Intel. It is useful for troubleshooting graphics driver-related issues.",
    "category": "Utilities",
    "winget": "Wagnardsoft.DisplayDriverUninstaller",
    "link": "https://www.wagnardsoft.com/display-driver-uninstaller-DDU-",
    "handler": "app-install"
  },
  "devtoys": {
    "Content": "DevToys",
    "Description": "DevToys is a collection of development-related utilities and tools for Windows. It includes tools for file management, code formatting, and productivity enhancements for developers.",
    "category": "Utilities",
    "winget": "DevToys-app.DevToys",
    "link": "https://devtoys.app/",
    "handler": "app-install"
  },
  "enteauth": {
    "Content": "Ente Auth",
    "Description": "Ente Auth is a free, cross-platform, end-to-end encrypted authenticator app.",
    "category": "Utilities",
    "winget": "ente-io.auth-desktop",
    "link": "https://ente.io/auth/",
    "handler": "app-install"
  },
  "esearch": {
    "Content": "Everything Search",
    "Description": "Everything Search is a fast and efficient file search utility for Windows.",
    "category": "Utilities",
    "winget": "voidtools.Everything",
    "link": "https://www.voidtools.com/",
    "handler": "app-install"
  },
  "ExifCleaner": {
    "Content": "ExifCleaner",
    "Description": "Desktop app to clean metadata from images, videos, PDFs, and other files.",
    "category": "Utilities",
    "winget": "szTheory.exifcleaner",
    "link": "https://github.com/szTheory/exifcleaner",
    "handler": "app-install"
  },
  "fancontrol": {
    "Content": "FanControl",
    "Description": "Fan Control is a free and open-source software that allows the user to control his CPU, GPU and case fans using temperatures.",
    "category": "Utilities",
    "winget": "Rem0o.FanControl",
    "link": "https://getfancontrol.com/",
    "handler": "app-install"
  },
  "fastfetch": {
    "Content": "Fastfetch",
    "Description": "Fastfetch is a neofetch-like tool for fetching system information and displaying them in a pretty way",
    "category": "Utilities",
    "winget": "Fastfetch-cli.Fastfetch",
    "link": "https://github.com/fastfetch-cli/fastfetch/",
    "handler": "app-install"
  },
  "fileconverter": {
    "Content": "File-Converter",
    "Description": "File Converter is a very simple tool which allows you to convert and compress one or several file(s) using the context menu in windows explorer.",
    "category": "Utilities",
    "winget": "AdrienAllard.FileConverter",
    "link": "https://file-converter.io/",
    "handler": "app-install"
  },
  "files": {
    "Content": "Files",
    "Description": "Alternative file explorer.",
    "category": "Utilities",
    "winget": "Files-community.Files",
    "link": "https://github.com/files-community/Files",
    "handler": "app-install"
  },
  "flow": {
    "Content": "Flow launcher",
    "Description": "Keystroke launcher for Windows to search, manage and launch files, folders bookmarks, websites and more.",
    "category": "Utilities",
    "winget": "Flow-Launcher.Flow-Launcher",
    "link": "https://www.flowlauncher.com/",
    "handler": "app-install"
  },
  "flux": {
    "Content": "F.lux",
    "Description": "f.lux adjusts the color temperature of your screen to reduce eye strain during nighttime use.",
    "category": "Utilities",
    "winget": "flux.flux",
    "link": "https://justgetflux.com/",
    "handler": "app-install"
  },
  "glazewm": {
    "Content": "GlazeWM",
    "Description": "GlazeWM is a tiling window manager for Windows inspired by i3 and Polybar",
    "category": "Utilities",
    "winget": "glzr-io.glazewm",
    "link": "https://github.com/glzr-io/glazewm",
    "handler": "app-install"
  },
  "gpuz": {
    "Content": "GPU-Z",
    "Description": "GPU-Z provides detailed information about your graphics card and GPU.",
    "category": "Utilities",
    "winget": "TechPowerUp.GPU-Z",
    "link": "https://www.techpowerup.com/gpuz/",
    "handler": "app-install"
  },
  "hwinfo": {
    "Content": "HWiNFO",
    "Description": "HWiNFO provides comprehensive hardware information and diagnostics for Windows.",
    "category": "Utilities",
    "winget": "REALiX.HWiNFO",
    "link": "https://www.hwinfo.com/",
    "handler": "app-install"
  },
  "hwmonitor": {
    "Content": "HWMonitor",
    "Description": "HWMonitor is a hardware monitoring program that reads PC systems main health sensors.",
    "category": "Utilities",
    "winget": "CPUID.HWMonitor",
    "link": "https://www.cpuid.com/softwares/hwmonitor.html",
    "handler": "app-install"
  },
  "keepass": {
    "Content": "KeePassXC",
    "Description": "KeePassXC is a cross-platform, open-source password manager with strong encryption features.",
    "category": "Utilities",
    "winget": "KeePassXCTeam.KeePassXC",
    "link": "https://keepassxc.org/",
    "handler": "app-install"
  },
  "livelywallpaper": {
    "Content": "Lively Wallpaper",
    "Description": "Free and open-source software that allows users to set animated desktop wallpapers and screensavers.",
    "category": "Utilities",
    "winget": "rocksdanister.LivelyWallpaper",
    "link": "https://www.rocksdanister.com/lively/",
    "handler": "app-install"
  },
  "localsend": {
    "Content": "LocalSend",
    "Description": "An open source cross-platform alternative to AirDrop.",
    "category": "Utilities",
    "winget": "LocalSend.LocalSend",
    "link": "https://localsend.org/",
    "handler": "app-install"
  },
  "magicwormhole": {
    "Content": "Magic Wormhole",
    "Description": "get things from one computer to another, safely",
    "category": "Utilities",
    "winget": "magic-wormhole.magic-wormhole",
    "link": "https://github.com/magic-wormhole/magic-wormhole",
    "handler": "app-install"
  },
  "malwarebytes": {
    "Content": "Malwarebytes",
    "Description": "Malwarebytes is an anti-malware software that provides real-time protection against threats.",
    "category": "Utilities",
    "winget": "Malwarebytes.Malwarebytes",
    "link": "https://www.malwarebytes.com/",
    "handler": "app-install"
  },
  "msedgeredirect": {
    "Content": "MSEdgeRedirect",
    "Description": "A Tool to Redirect News, Search, Widgets, Weather, and More to Your Default Browser.",
    "category": "Utilities",
    "winget": "rcmaehl.MSEdgeRedirect",
    "link": "https://github.com/rcmaehl/MSEdgeRedirect",
    "handler": "app-install"
  },
  "msiafterburner": {
    "Content": "MSI Afterburner",
    "Description": "MSI Afterburner is a graphics card overclocking utility with advanced features.",
    "category": "Utilities",
    "winget": "Guru3D.Afterburner",
    "link": "https://www.msi.com/Landing/afterburner",
    "handler": "app-install"
  },
  "nanazip": {
    "Content": "NanaZip",
    "Description": "NanaZip is a fast and efficient file compression and decompression tool.",
    "category": "Utilities",
    "winget": "M2Team.NanaZip",
    "link": "https://github.com/M2Team/NanaZip",
    "handler": "app-install"
  },
  "neofetchwin": {
    "Content": "Neofetch",
    "Description": "Neofetch is a command-line utility for displaying system information in a visually appealing way.",
    "category": "Utilities",
    "winget": "nepnep.neofetch-win",
    "link": "https://github.com/nepnep39/neofetch-win",
    "handler": "app-install"
  },
  "nushell": {
    "Content": "Nushell",
    "Description": "Nushell is a new shell that takes advantage of modern hardware and systems to provide a powerful, expressive, and fast experience.",
    "category": "Utilities",
    "winget": "Nushell.Nushell",
    "link": "https://www.nushell.sh/",
    "handler": "app-install"
  },
  "nvclean": {
    "Content": "NVCleanstall",
    "Description": "NVCleanstall is a tool designed to customize NVIDIA driver installations, allowing advanced users to control more aspects of the installation process.",
    "category": "Utilities",
    "winget": "TechPowerUp.NVCleanstall",
    "link": "https://www.techpowerup.com/nvcleanstall/",
    "handler": "app-install"
  },
  "OFGB": {
    "Content": "OFGB (Oh Frick Go Back)",
    "Description": "GUI Tool to remove ads from various places around Windows 11",
    "category": "Utilities",
    "winget": "xM4ddy.OFGB",
    "link": "https://github.com/xM4ddy/OFGB",
    "handler": "app-install"
  },
  "OPAutoClicker": {
    "Content": "OPAutoClicker",
    "Description": "A full-fledged autoclicker with two modes of autoclicking, at your dynamic cursor location or at a prespecified location.",
    "category": "Utilities",
    "winget": "OPAutoClicker.OPAutoClicker",
    "link": "https://www.opautoclicker.com",
    "handler": "app-install"
  },
  "openshell": {
    "Content": "Open Shell (Start Menu)",
    "Description": "Open Shell is a Windows Start Menu replacement with enhanced functionality and customization options.",
    "category": "Utilities",
    "winget": "Open-Shell.Open-Shell-Menu",
    "link": "https://github.com/Open-Shell/Open-Shell-Menu",
    "handler": "app-install"
  },
  "OVirtualBox": {
    "Content": "Oracle VirtualBox",
    "Description": "Oracle VirtualBox is a powerful and free open-source virtualization tool for x86 and AMD64/Intel64 architectures.",
    "category": "Utilities",
    "winget": "Oracle.VirtualBox",
    "link": "https://www.virtualbox.org/",
    "handler": "app-install"
  },
  "parsec": {
    "Content": "Parsec",
    "Description": "Parsec is a low-latency, high-quality remote desktop sharing application for collaborating and gaming across devices.",
    "category": "Utilities",
    "winget": "Parsec.Parsec",
    "link": "https://parsec.app/",
    "handler": "app-install"
  },
  "piimager": {
    "Content": "Raspberry Pi Imager",
    "Description": "Raspberry Pi Imager is a utility for writing operating system images to SD cards for Raspberry Pi devices.",
    "category": "Utilities",
    "winget": "RaspberryPiFoundation.RaspberryPiImager",
    "link": "https://www.raspberrypi.com/software/",
    "handler": "app-install"
  },
  "processlasso": {
    "Content": "Process Lasso",
    "Description": "Process Lasso is a system optimization and automation tool that improves system responsiveness and stability by adjusting process priorities and CPU affinities.",
    "category": "Utilities",
    "winget": "BitSum.ProcessLasso",
    "link": "https://bitsum.com/",
    "handler": "app-install"
  },
  "qbittorrent": {
    "Content": "qBittorrent",
    "Description": "qBittorrent is a free and open-source BitTorrent client that aims to provide a feature-rich and lightweight alternative to other torrent clients.",
    "category": "Utilities",
    "winget": "qBittorrent.qBittorrent",
    "link": "https://www.qbittorrent.org/",
    "handler": "app-install"
  },
  "rainmeter": {
    "Content": "Rainmeter",
    "Description": "Rainmeter is a desktop customization tool that allows you to create and share customizable skins for your desktop.",
    "category": "Utilities",
    "winget": "Rainmeter.Rainmeter",
    "link": "https://www.rainmeter.net/",
    "handler": "app-install"
  },
  "revo": {
    "Content": "Revo Uninstaller",
    "Description": "Revo Uninstaller is an advanced uninstaller tool that helps you remove unwanted software and clean up your system.",
    "category": "Utilities",
    "winget": "RevoUninstaller.RevoUninstaller",
    "link": "https://www.revouninstaller.com/",
    "handler": "app-install"
  },
  "ripgrep": {
    "Content": "Ripgrep",
    "Description": "Fast and powerful commandline search tool",
    "category": "Utilities",
    "winget": "BurntSushi.ripgrep.MSVC",
    "link": "https://github.com/BurntSushi/ripgrep/",
    "handler": "app-install"
  },
  "rufus": {
    "Content": "Rufus Imager",
    "Description": "Rufus is a utility that helps format and create bootable USB drives, such as USB keys or pen drives.",
    "category": "Utilities",
    "winget": "Rufus.Rufus",
    "link": "https://rufus.ie/",
    "handler": "app-install"
  },
  "sandboxie": {
    "Content": "Sandboxie Plus",
    "Description": "Sandboxie Plus is a sandbox-based isolation program that provides enhanced security by running applications in an isolated environment.",
    "category": "Utilities",
    "winget": "Sandboxie.Plus",
    "link": "https://github.com/sandboxie-plus/Sandboxie",
    "handler": "app-install"
  },
  "sdio": {
    "Content": "Snappy Driver Installer Origin",
    "Description": "Snappy Driver Installer Origin is a free and open-source driver updater with a vast driver database for Windows.",
    "category": "Utilities",
    "winget": "GlennDelahoy.SnappyDriverInstallerOrigin",
    "link": "https://www.glenn.delahoy.com/snappy-driver-installer-origin/",
    "handler": "app-install"
  },
  "signalrgb": {
    "Content": "SignalRGB",
    "Description": "SignalRGB lets you control and sync your favorite RGB devices with one free application.",
    "category": "Utilities",
    "winget": "WhirlwindFX.SignalRgb",
    "link": "https://www.signalrgb.com/",
    "handler": "app-install"
  },
  "spacedrive": {
    "Content": "Spacedrive File Manager",
    "Description": "Spacedrive is a file manager that offers cloud storage integration and file synchronization across devices.",
    "category": "Utilities",
    "winget": "spacedrive.Spacedrive",
    "link": "https://www.spacedrive.com/",
    "handler": "app-install"
  },
  "superf4": {
    "Content": "SuperF4",
    "Description": "SuperF4 is a utility that allows you to terminate programs instantly by pressing a customizable hotkey.",
    "category": "Utilities",
    "winget": "StefanSundin.Superf4",
    "link": "https://stefansundin.github.io/superf4/",
    "handler": "app-install"
  },
  "syncthingtray": {
    "Content": "Syncthingtray",
    "Description": "Might be the alternative for Synctrayzor. Windows tray utility / filesystem watcher / launcher for Syncthing",
    "category": "Utilities",
    "winget": "Martchus.syncthingtray",
    "link": "https://github.com/Martchus/syncthingtray",
    "handler": "app-install"
  },
  "synctrayzor": {
    "Content": "SyncTrayzor",
    "Description": "Windows tray utility / filesystem watcher / launcher for Syncthing",
    "category": "Utilities",
    "winget": "GermanCoding.SyncTrayzor",
    "link": "https://github.com/GermanCoding/SyncTrayzor",
    "handler": "app-install"
  },
  "tabby": {
    "Content": "Tabby.sh",
    "Description": "Tabby is a highly configurable terminal emulator, SSH and serial client for Windows, macOS and Linux",
    "category": "Utilities",
    "winget": "Eugeny.Tabby",
    "link": "https://tabby.sh/",
    "handler": "app-install"
  },
  "tailscale": {
    "Content": "Tailscale",
    "Description": "Tailscale is a secure and easy-to-use VPN solution for connecting your devices and networks.",
    "category": "Utilities",
    "winget": "tailscale.tailscale",
    "link": "https://tailscale.com/",
    "handler": "app-install"
  },
  "ttaskbar": {
    "Content": "TranslucentTB",
    "Description": "TranslucentTB is a tool that allows you to customize the transparency of the Windows taskbar.",
    "category": "Utilities",
    "winget": "9PF4KZ2VN4W9",
    "link": "https://github.com/TranslucentTB/TranslucentTB",
    "handler": "app-install"
  },
  "Windhawk": {
    "Content": "Windhawk",
    "Description": "The customization marketplace for Windows programs",
    "category": "Utilities",
    "winget": "RamenSoftware.Windhawk",
    "link": "https://windhawk.net",
    "handler": "app-install"
  },
  "windowsfirewallcontrol": {
    "Content": "Windows Firewall Control",
    "Description": "Windows Firewall Control is a powerful tool which extends the functionality of Windows Firewall and provides new extra features which makes Windows Firewall better.",
    "category": "Utilities",
    "winget": "BiniSoft.WindowsFirewallControl",
    "link": "https://www.binisoft.org/wfc",
    "handler": "app-install"
  },
  "windowspchealth": {
    "Content": "Windows PC Health Check",
    "Description": "Windows PC Health Check is a tool that helps you check if your PC meets the system requirements for Windows 11.",
    "category": "Utilities",
    "winget": "Microsoft.WindowsPCHealthCheck",
    "link": "https://support.microsoft.com/en-us/windows/how-to-use-the-pc-health-check-app-9c8abd9b-03ba-4e67-81ef-36f37caa7844",
    "handler": "app-install"
  },
  "wingetui": {
    "Content": "UniGetUI",
    "Description": "UniGetUI is a GUI for Winget, Chocolatey, and other Windows CLI package managers.",
    "category": "Utilities",
    "winget": "MartiCliment.UniGetUI",
    "link": "https://www.marticliment.com/wingetui/",
    "handler": "app-install"
  },
  "winrar": {
    "Content": "WinRAR",
    "Description": "WinRAR is a powerful archive manager that allows you to create, manage, and extract compressed files.",
    "category": "Utilities",
    "winget": "RARLab.WinRAR",
    "link": "https://www.win-rar.com/",
    "handler": "app-install"
  },
  "wiztree": {
    "Content": "WizTree",
    "Description": "WizTree is a fast disk space analyzer that helps you quickly find the files and folders consuming the most space on your hard drive.",
    "category": "Utilities",
    "winget": "AntibodySoftware.WizTree",
    "link": "https://wiztreefree.com/",
    "handler": "app-install"
  },
  "xnview": {
    "Content": "XnView classic",
    "Description": "XnView is an efficient image viewer, browser and converter for Windows.",
    "category": "Utilities",
    "winget": "XnSoft.XnView.Classic",
    "link": "https://www.xnview.com/en/xnview/",
    "handler": "app-install"
  },
  "zerotierone": {
    "Content": "ZeroTier One",
    "Description": "ZeroTier One is a software-defined networking tool that allows you to create secure and scalable networks.",
    "category": "Utilities",
    "winget": "ZeroTier.ZeroTierOne",
    "link": "https://zerotier.com/",
    "handler": "app-install"
  },
  "zoomit": {
    "Content": "ZoomIt",
    "Description": "A screen zoom, annotation, and recording tool for technical presentations and demos",
    "category": "Utilities",
    "winget": "Microsoft.Sysinternals.ZoomIt",
    "link": "https://learn.microsoft.com/en-us/sysinternals/downloads/zoomit",
    "handler": "app-install"
  },
  "zoxide": {
    "Content": "Zoxide",
    "Description": "Zoxide is a fast and efficient directory changer (cd) that helps you navigate your file system with ease.",
    "category": "Utilities",
    "winget": "ajeetdsouza.zoxide",
    "link": "https://github.com/ajeetdsouza/zoxide",
    "handler": "app-install"
  },
  "brave": {
    "Content": "Brave Browser",
    "Description": "Brave is a free and open-source web browser developed by Brave Software, Inc. based on the Chromium web browser.",
    "category": "Browsers",
    "winget": "Brave.Brave",
    "link": "https://brave.com/",
    "handler": "app-install"
  },
  "chrome": {
    "Content": "Google Chrome",
    "Description": "Google Chrome is a cross-platform web browser developed by Google.",
    "category": "Browsers",
    "winget": "Google.Chrome",
    "link": "https://www.google.com/chrome/",
    "handler": "app-install"
  },
  "chromium": {
    "Content": "Chromium",
    "Description": "Chromium is a free and open-source web browser project, principally developed and maintained by Google.",
    "category": "Browsers",
    "winget": "M89SR9922C05",
    "link": "https://www.chromium.org/Home",
    "handler": "app-install"
  },
  "discord": {
    "Content": "Discord",
    "Description": "Discord is a VoIP, instant messaging and digital distribution platform designed for creating communities.",
    "category": "Communications",
    "winget": "Discord.Discord",
    "link": "https://discord.com/",
    "handler": "app-install"
  },
  "epicgames": {
    "Content": "Epic Games Launcher",
    "Description": "The Epic Games Launcher is a digital distribution platform developed by Epic Games.",
    "category": "Gaming",
    "winget": "EpicGames.EpicGamesLauncher",
    "link": "https://www.epicgames.com/store/en-US/download",
    "handler": "app-install"
  },
  "firefox": {
    "Content": "Mozilla Firefox",
    "Description": "Mozilla Firefox, or simply Firefox, is a free and open-source web browser developed by the Mozilla Foundation and its subsidiary, the Mozilla Corporation.",
    "category": "Browsers",
    "winget": "Mozilla.Firefox",
    "link": "https://www.mozilla.org/en-US/firefox/new/",
    "handler": "app-install"
  },
  "gimp": {
    "Content": "GIMP",
    "Description": "GIMP is a free and open-source raster graphics editor used for image manipulation and image editing, free-form drawing, transcoding between different image file formats, and more.",
    "category": "Multimedia",
    "winget": "GIMP.GIMP",
    "link": "https://www.gimp.org/",
    "handler": "app-install"
  },
  "git": {
    "Content": "Git",
    "Description": "Git is a free and open source distributed version control system designed to handle everything from small to very large projects with speed and efficiency.",
    "category": "Development",
    "winget": "Git.Git",
    "link": "https://git-scm.com/",
    "handler": "app-install"
  },
  "googledrive": {
    "Content": "Google Drive",
    "Description": "Google Drive is a file storage and synchronization service developed by Google.",
    "category": "Utilities",
    "winget": "Google.Drive",
    "link": "https://www.google.com/drive/",
    "handler": "app-install"
  },
  "handbrake": {
    "Content": "HandBrake",
    "Description": "HandBrake is a free and open-source transcoder for digital video files.",
    "category": "Multimedia",
    "winget": "HandBrake.HandBrake",
    "link": "https://handbrake.fr/",
    "handler": "app-install"
  },
  "inkscape": {
    "Content": "Inkscape",
    "Description": "Inkscape is a free and open-source vector graphics editor.",
    "category": "Multimedia",
    "winget": "Inkscape.Inkscape",
    "link": "https://inkscape.org/",
    "handler": "app-install"
  },
  "irfanview": {
    "Content": "IrfanView",
    "Description": "IrfanView is an image viewer, editor, organiser and converter program for Microsoft Windows.",
    "category": "Multimedia",
    "winget": "IrfanSkiljan.IrfanView",
    "link": "https://www.irfanview.com/",
    "handler": "app-install"
  },
  "java": {
    "Content": "Java (Oracle)",
    "Description": "Java is a class-based, object-oriented programming language that is designed to have as few implementation dependencies as possible.",
    "category": "Development",
    "winget": "Oracle.JavaRuntimeEnvironment",
    "link": "https://www.java.com/en/",
    "handler": "app-install"
  },
  "krita": {
    "Content": "Krita",
    "Description": "Krita is a free and open-source raster graphics editor designed primarily for digital painting and 2D animation.",
    "category": "Multimedia",
    "winget": "Krita.Krita",
    "link": "https://krita.org/",
    "handler": "app-install"
  },
  "librewolf": {
    "Content": "LibreWolf",
    "Description": "LibreWolf is a fork of Firefox, focused on privacy, security and freedom.",
    "category": "Browsers",
    "winget": "LibreWolf.LibreWolf",
    "link": "https://librewolf.net/",
    "handler": "app-install"
  },
  "lightshot": {
    "Content": "Lightshot",
    "Description": "Lightshot is a screenshot tool for Windows and Mac.",
    "category": "Utilities",
    "winget": "Skillbrains.Lightshot",
    "link": "https://app.prntscr.com/en/index.html",
    "handler": "app-install"
  },
  "mpc-hc": {
    "Content": "MPC-HC",
    "Description": "Media Player Classic - Home Cinema is a light-weight media player for Windows.",
    "category": "Multimedia",
    "winget": "clsid2.mpc-hc",
    "link": "https://github.com/clsid2/mpc-hc",
    "handler": "app-install"
  },
  "musescore": {
    "Content": "MuseScore",
    "Description": "MuseScore is a scorewriter for Windows, macOS, and Linux.",
    "category": "Multimedia",
    "winget": "MuseScore.MuseScore",
    "link": "https://musescore.org/",
    "handler": "app-install"
  },
  "notepadplusplus": {
    "Content": "Notepad++",
    "Description": "Notepad++ is a free source code editor and Notepad replacement that supports several languages.",
    "category": "Development",
    "winget": "Notepad++.Notepad++",
    "link": "https://notepad-plus-plus.org/",
    "handler": "app-install"
  },
  "obsstudio": {
    "Content": "OBS Studio",
    "Description": "OBS Studio is a free and open-source software for video recording and live streaming.",
    "category": "Multimedia",
    "winget": "OBSProject.OBSStudio",
    "link": "https://obsproject.com/",
    "handler": "app-install"
  },
  "opera": {
    "Content": "Opera",
    "Description": "Opera is a web browser for Windows, macOS, and Linux operating systems.",
    "category": "Browsers",
    "winget": "Opera.Opera",
    "link": "https://www.opera.com/",
    "handler": "app-install"
  },
  "operagx": {
    "Content": "Opera GX",
    "Description": "Opera GX is a special version of the Opera browser built specifically for gamers.",
    "category": "Browsers",
    "winget": "Opera.OperaGX",
    "link": "https://www.opera.com/gx",
    "handler": "app-install"
  },
  "paint.net": {
    "Content": "Paint.NET",
    "Description": "Paint.NET is image and photo editing software for PCs that run Windows.",
    "category": "Multimedia",
    "winget": "dotPDN.PaintDotNet",
    "link": "https://www.getpaint.net/",
    "handler": "app-install"
  },
  "powertoys": {
    "Content": "PowerToys",
    "Description": "Microsoft PowerToys is a set of utilities for power users to tune and streamline their Windows 10/11 experience.",
    "category": "Utilities",
    "winget": "Microsoft.PowerToys",
    "link": "https://github.com/microsoft/PowerToys",
    "handler": "app-install"
  },
  "python": {
    "Content": "Python",
    "Description": "Python is an interpreted high-level general-purpose programming language.",
    "category": "Development",
    "winget": "Python.Python.3.12",
    "link": "https://www.python.org/",
    "handler": "app-install"
  },
  "sharex": {
    "Content": "ShareX",
    "Description": "ShareX is a free and open source program that lets you capture or record any area of your screen and share it with a single press of a key.",
    "category": "Utilities",
    "winget": "ShareX.ShareX",
    "link": "https://getsharex.com/",
    "handler": "app-install"
  },
  "slack": {
    "Content": "Slack",
    "Description": "Slack is a proprietary business communication platform developed by American software company Slack Technologies.",
    "category": "Communications",
    "winget": "SlackTechnologies.Slack",
    "link": "https://slack.com/",
    "handler": "app-install"
  },
  "steam": {
    "Content": "Steam",
    "Description": "Steam is a video game digital distribution service by Valve.",
    "category": "Gaming",
    "winget": "Valve.Steam",
    "link": "https://store.steampowered.com/about/",
    "handler": "app-install"
  },
  "telegram": {
    "Content": "Telegram",
    "Description": "Telegram is a cloud-based instant messaging and voice over IP service.",
    "category": "Communications",
    "winget": "Telegram.TelegramDesktop",
    "link": "https://telegram.org/",
    "handler": "app-install"
  },
  "thunderbird": {
    "Content": "Thunderbird",
    "Description": "Mozilla Thunderbird is a free and open-source email client, personal information manager, news client, RSS and chat client.",
    "category": "Communications",
    "winget": "Mozilla.Thunderbird",
    "link": "https://www.thunderbird.net/",
    "handler": "app-install"
  },
  "vlc": {
    "Content": "VLC Media Player",
    "Description": "VLC is a free and open source cross-platform multimedia player and framework that plays most multimedia files as well as DVDs, Audio CDs, VCDs, and various streaming protocols.",
    "category": "Multimedia",
    "winget": "VideoLAN.VLC",
    "link": "https://www.videolan.org/vlc/",
    "handler": "app-install"
  },
  "vscode": {
    "Content": "Visual Studio Code",
    "Description": "Visual Studio Code is a source-code editor made by Microsoft for Windows, Linux and macOS.",
    "category": "Development",
    "winget": "Microsoft.VisualStudioCode",
    "link": "https://code.visualstudio.com/",
    "handler": "app-install"
  },
  "whatsapp": {
    "Content": "WhatsApp",
    "Description": "WhatsApp is a free, multiplatform messaging app for video and voice calling, text messaging, and more.",
    "category": "Communications",
    "winget": "WhatsApp.WhatsApp",
    "link": "https://www.whatsapp.com/",
    "handler": "app-install"
  },
  "winamp": {
    "Content": "Winamp",
    "Description": "Winamp is a media player for Windows, macOS and Android-based devices, developed by Radionomy.",
    "category": "Multimedia",
    "winget": "Radionomy.Winamp",
    "link": "https://www.winamp.com/",
    "handler": "app-install"
  },
  "wireguard": {
    "Content": "WireGuard",
    "Description": "WireGuard is a communication protocol and free and open-source software for virtual private networks.",
    "category": "Utilities",
    "winget": "WireGuard.WireGuard",
    "link": "https://www.wireguard.com/",
    "handler": "app-install"
  },
  "wireshark": {
    "Content": "Wireshark",
    "Description": "Wireshark is a free and open-source packet analyzer.",
    "category": "Utilities",
    "winget": "WiresharkFoundation.Wireshark",
    "link": "https://www.wireshark.org/",
    "handler": "app-install"
  },
  "eaapp": {
    "Content": "EA App",
    "Description": "EA App is a platform for accessing and playing Electronic Arts games.",
    "category": "Gaming",
    "winget": "ElectronicArts.EADesktop",
    "link": "https://www.ea.com/ea-app",
    "handler": "app-install"
  },
  "emulationstation": {
    "Content": "Emulation Station",
    "Description": "Emulation Station is a graphical and themeable emulator front-end that allows you to access all your favorite games in one place.",
    "category": "Gaming",
    "winget": "Emulationstation.Emulationstation",
    "link": "https://emulationstation.org/",
    "handler": "app-install"
  },
  "geforcenow": {
    "Content": "GeForce NOW",
    "Description": "GeForce NOW is a cloud gaming service that allows you to play high-quality PC games on your device.",
    "category": "Gaming",
    "winget": "Nvidia.GeForceNow",
    "link": "https://www.nvidia.com/en-us/geforce-now/",
    "handler": "app-install"
  },
  "gog": {
    "Content": "GOG Galaxy",
    "Description": "GOG Galaxy is a gaming client that offers DRM-free games, additional content, and more.",
    "category": "Gaming",
    "winget": "GOG.Galaxy",
    "link": "https://www.gog.com/galaxy",
    "handler": "app-install"
  },
  "heroiclauncher": {
    "Content": "Heroic Games Launcher",
    "Description": "Heroic Games Launcher is an open-source alternative game launcher for Epic Games Store.",
    "category": "Gaming",
    "winget": "HeroicGamesLauncher.HeroicGamesLauncher",
    "link": "https://heroicgameslauncher.com/",
    "handler": "app-install"
  },
  "itch": {
    "Content": "Itch.io",
    "Description": "Itch.io is a digital distribution platform for indie games and creative projects.",
    "category": "Gaming",
    "winget": "ItchIo.Itch",
    "link": "https://itch.io/",
    "handler": "app-install"
  },
  "ubisoft": {
    "Content": "Ubisoft Connect",
    "Description": "Ubisoft Connect is Ubisoft's digital distribution and online gaming service, providing access to Ubisoft's games and services.",
    "category": "Gaming",
    "winget": "Ubisoft.Connect",
    "link": "https://ubisoftconnect.com/",
    "handler": "app-install"
  },
  "floorp": {
    "Content": "Floorp",
    "Description": "Floorp is an open-source web browser project that aims to provide a simple and fast browsing experience.",
    "category": "Browsers",
    "winget": "Ablaze.Floorp",
    "link": "https://floorp.app/",
    "handler": "app-install"
  },
  "mullvadbrowser": {
    "Content": "Mullvad Browser",
    "Description": "Mullvad Browser is a privacy-focused web browser, developed in partnership with the Tor Project.",
    "category": "Browsers",
    "winget": "MullvadVPN.MullvadBrowser",
    "link": "https://mullvad.net/browser",
    "handler": "app-install"
  },
  "thorium": {
    "Content": "Thorium Browser AVX2",
    "Description": "Browser built for speed over vanilla Chromium. It is built with AVX2 optimizations and is the fastest browser on the market.",
    "category": "Browsers",
    "winget": "Alex313031.Thorium.AVX2",
    "link": "https://thorium.rocks/",
    "handler": "app-install"
  },
  "tor": {
    "Content": "Tor Browser",
    "Description": "Tor Browser is designed for anonymous web browsing, utilizing the Tor network to protect user privacy and security.",
    "category": "Browsers",
    "winget": "TorProject.TorBrowser",
    "link": "https://www.torproject.org/",
    "handler": "app-install"
  },
  "ungoogled": {
    "Content": "Ungoogled Chromium",
    "Description": "Ungoogled Chromium is a version of Chromium without Google's integration for enhanced privacy and control.",
    "category": "Browsers",
    "winget": "eloston.ungoogled-chromium",
    "link": "https://github.com/Eloston/ungoogled-chromium",
    "handler": "app-install"
  },
  "waterfox": {
    "Content": "Waterfox",
    "Description": "Waterfox is a fast, privacy-focused web browser based on Firefox, designed to preserve user choice and privacy.",
    "category": "Browsers",
    "winget": "Waterfox.Waterfox",
    "link": "https://www.waterfox.net/",
    "handler": "app-install"
  }
}
'@

  $TweaksJson = @'
{
  "WPFTweaksHiber": {
    "Content": "Disable Hibernation",
    "handler": "tweak",
    "Description": "Hibernation is really meant for laptops as it saves what's in memory before turning the pc off. It really should never be used",
    "category": "Essential Tweaks",
    "registry": [
      {
        "Path": "HKLM:\\System\\CurrentControlSet\\Control\\Session Manager\\Power",
        "Name": "HibernateEnabled",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "1"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FlyoutMenuSettings",
        "Name": "ShowHibernateOption",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "1"
      }
    ],
    "InvokeScript": [
      "powercfg.exe /hibernate off"
    ],
    "UndoScript": [
      "powercfg.exe /hibernate on"
    ]
  },
  "WPFTweaksLaptopHibernation": {
    "Content": "Set Hibernation as default (good for laptops)",
    "handler": "tweak",
    "Description": "Most modern laptops have connected standby enabled which drains the battery, this sets hibernation as default which will not drain the battery.",
    "category": "Advanced",
    "registry": [
      {
        "Path": "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Power\\PowerSettings\\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\\7bc4a2f9-d8fc-4469-b07b-33eb785aaca0",
        "OriginalValue": "1",
        "Name": "Attributes",
        "Value": "2",
        "Type": "DWord"
      },
      {
        "Path": "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Power\\PowerSettings\\abfc2519-3608-4c2a-94ea-171b0ed546ab\\94ac6d29-73ce-41a6-809f-6363ba21b47e",
        "OriginalValue": "0",
        "Name": "Attributes ",
        "Value": "2",
        "Type": "DWord"
      }
    ],
    "InvokeScript": [
      "\n      powercfg.exe /hibernate on 2>&1 | Out-Null\n      powercfg.exe change standby-timeout-ac 60 2>&1 | Out-Null\n      powercfg.exe change standby-timeout-dc 60 2>&1 | Out-Null\n      powercfg.exe change monitor-timeout-ac 10 2>&1 | Out-Null\n      powercfg.exe change monitor-timeout-dc 1 2>&1 | Out-Null\n      "
    ],
    "UndoScript": [
      "\n      powercfg.exe /hibernate off 2>&1 | Out-Null\n      powercfg.exe change standby-timeout-ac 15 2>&1 | Out-Null\n      powercfg.exe change standby-timeout-dc 15 2>&1 | Out-Null\n      powercfg.exe change monitor-timeout-ac 15 2>&1 | Out-Null\n      powercfg.exe change monitor-timeout-dc 15 2>&1 | Out-Null\n      "
    ]
  },
  "WPFTweaksServices": {
    "Content": "Set Services to Manual",
    "handler": "tweak",
    "Description": "Turns a bunch of system services to manual that don't need to be running all the time. This is pretty harmless as if the service is needed, it will simply start on demand.",
    "category": "Essential Tweaks",
    "service": [
      {
        "Name": "ALG",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "AppMgmt",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "AppReadiness",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "AppVClient",
        "StartupType": "Disabled",
        "OriginalType": "Disabled"
      },
      {
        "Name": "Appinfo",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "AssignedAccessManagerSvc",
        "StartupType": "Disabled",
        "OriginalType": "Manual"
      },
      {
        "Name": "AudioEndpointBuilder",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "AudioSrv",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "Audiosrv",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "AxInstSV",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "BDESVC",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "BITS",
        "StartupType": "AutomaticDelayedStart",
        "OriginalType": "Automatic"
      },
      {
        "Name": "BTAGService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "BthAvctpSvc",
        "StartupType": "Automatic",
        "OriginalType": "Manual"
      },
      {
        "Name": "CDPSvc",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      },
      {
        "Name": "COMSysApp",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "CertPropSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "CryptSvc",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "CscService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "DPS",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "DevQueryBroker",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "DeviceAssociationService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "DeviceInstall",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "Dhcp",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "DiagTrack",
        "StartupType": "Disabled",
        "OriginalType": "Automatic"
      },
      {
        "Name": "DialogBlockingService",
        "StartupType": "Disabled",
        "OriginalType": "Disabled"
      },
      {
        "Name": "DispBrokerDesktopSvc",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "DisplayEnhancementService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "EFS",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "EapHost",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "EventLog",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "EventSystem",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "FDResPub",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "FontCache",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "FrameServer",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "FrameServerMonitor",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "GraphicsPerfSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "HvHost",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "IKEEXT",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "InstallService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "InventorySvc",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      },
      {
        "Name": "IpxlatCfgSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "KeyIso",
        "StartupType": "Automatic",
        "OriginalType": "Manual"
      },
      {
        "Name": "KtmRm",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "LanmanServer",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "LanmanWorkstation",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "LicenseManager",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "LxpSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "MSDTC",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "MSiSCSI",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "MapsBroker",
        "StartupType": "AutomaticDelayedStart",
        "OriginalType": "Automatic"
      },
      {
        "Name": "McpManagementService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "MicrosoftEdgeElevationService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "NaturalAuthentication",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "NcaSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "NcbService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "NcdAutoSetup",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "NetSetupSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "NetTcpPortSharing",
        "StartupType": "Disabled",
        "OriginalType": "Disabled"
      },
      {
        "Name": "Netman",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "NlaSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "PcaSvc",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      },
      {
        "Name": "PeerDistSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "PerfHost",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "PhoneSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "PlugPlay",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "PolicyAgent",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "Power",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "PrintNotify",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "ProfSvc",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "PushToInstall",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "QWAVE",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "RasAuto",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "RasMan",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "RemoteAccess",
        "StartupType": "Disabled",
        "OriginalType": "Disabled"
      },
      {
        "Name": "RemoteRegistry",
        "StartupType": "Disabled",
        "OriginalType": "Disabled"
      },
      {
        "Name": "RetailDemo",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "RmSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "RpcLocator",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "SCPolicySvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "SCardSvr",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "SDRSVC",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "SEMgrSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "SENS",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "SNMPTRAP",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "SNMPTrap",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "SSDPSRV",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "SamSs",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "ScDeviceEnum",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "SensorDataService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "SensorService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "SensrSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "SessionEnv",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "SharedAccess",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "ShellHWDetection",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "SmsRouter",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "Spooler",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "SstpSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "StiSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "StorSvc",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      },
      {
        "Name": "SysMain",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "TapiSrv",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "TermService",
        "StartupType": "Automatic",
        "OriginalType": "Manual"
      },
      {
        "Name": "Themes",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "TieringEngineService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "TokenBroker",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "TrkWks",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "TroubleshootingSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "TrustedInstaller",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "UevAgentService",
        "StartupType": "Disabled",
        "OriginalType": "Disabled"
      },
      {
        "Name": "UmRdpService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "UserManager",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "UsoSvc",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      },
      {
        "Name": "VSS",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "VaultSvc",
        "StartupType": "Automatic",
        "OriginalType": "Manual"
      },
      {
        "Name": "W32Time",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WEPHOSTSVC",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WFDSConMgrSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WMPNetworkSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WManSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WPDBusEnum",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WSearch",
        "StartupType": "AutomaticDelayedStart",
        "OriginalType": "Automatic"
      },
      {
        "Name": "WalletService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WarpJITSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WbioSrvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "Wcmsvc",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "WdiServiceHost",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WdiSystemHost",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WebClient",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "Wecsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WerSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WiaRpc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WinRM",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "Winmgmt",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "WpcMonSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WpnService",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      },
      {
        "Name": "XblAuthManager",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "XblGameSave",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "XboxGipSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "XboxNetApiSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "autotimesvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "bthserv",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "camsvc",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      },
      {
        "Name": "cloudidsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "dcsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "defragsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "diagsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "dmwappushservice",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "dot3svc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "edgeupdate",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      },
      {
        "Name": "edgeupdatem",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "fdPHost",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "fhsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "hidserv",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "icssvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "iphlpsvc",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "lfsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "lltdsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "lmhosts",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "netprofm",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "nsi",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "perceptionsimulation",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "pla",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "seclogon",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "shpamsvc",
        "StartupType": "Disabled",
        "OriginalType": "Disabled"
      },
      {
        "Name": "smphost",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "ssh-agent",
        "StartupType": "Disabled",
        "OriginalType": "Disabled"
      },
      {
        "Name": "svsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "swprv",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "tzautoupdate",
        "StartupType": "Disabled",
        "OriginalType": "Disabled"
      },
      {
        "Name": "upnphost",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "vds",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "vmicguestinterface",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "vmicheartbeat",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "vmickvpexchange",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "vmicrdv",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "vmicshutdown",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "vmictimesync",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "vmicvmsession",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "vmicvss",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "wbengine",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "wcncsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "webthreatdefsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "wercplsupport",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "wisvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "wlidsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "wlpasvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "wmiApSrv",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "workfolderssvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "wuauserv",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      }
    ]
  },
  "WPFTweaksBraveDebloat": {
    "Content": "Brave Debloat",
    "handler": "tweak",
    "Description": "Disables various annoyances like Brave Rewards,Leo AI,Crypto Wallet and VPN",
    "category": "Advanced",
    "registry": [
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\BraveSoftware\\Brave",
        "Name": "BraveRewardsDisabled",
        "Type": "DWord",
        "Value": "1",
        "OriginalValue": "<RemoveEntry>"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\BraveSoftware\\Brave",
        "Name": "BraveWalletDisabled",
        "Type": "DWord",
        "Value": "1",
        "OriginalValue": "<RemoveEntry>"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\BraveSoftware\\Brave",
        "Name": "BraveVPNDisabled",
        "Type": "DWord",
        "Value": "1",
        "OriginalValue": "<RemoveEntry>"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\BraveSoftware\\Brave",
        "Name": "BraveAIChatEnabled",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "<RemoveEntry>"
      }
    ]
  },
  "WPFTweaksEdgeDebloat": {
    "Content": "Edge Debloat",
    "handler": "tweak",
    "Description": "Disables various telemetry options, popups, and other annoyances in Edge.",
    "category": "Advanced",
    "registry": [
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\EdgeUpdate",
        "Name": "CreateDesktopShortcutDefault",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "<RemoveEntry>"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
        "Name": "PersonalizationReportingEnabled",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "<RemoveEntry>"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
        "Name": "ShowRecommendationsEnabled",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "<RemoveEntry>"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
        "Name": "HideFirstRunExperience",
        "Type": "DWord",
        "Value": "1",
        "OriginalValue": "<RemoveEntry>"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
        "Name": "UserFeedbackAllowed",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "<RemoveEntry>"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
        "Name": "ConfigureDoNotTrack",
        "Type": "DWord",
        "Value": "1",
        "OriginalValue": "<RemoveEntry>"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
        "Name": "AlternateErrorPagesEnabled",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "<RemoveEntry>"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
        "Name": "EdgeCollectionsEnabled",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "<RemoveEntry>"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
        "Name": "EdgeShoppingAssistantEnabled",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "<RemoveEntry>"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
        "Name": "MicrosoftEdgeInsiderPromotionEnabled",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "<RemoveEntry>"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
        "Name": "ShowMicrosoftRewards",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "<RemoveEntry>"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
        "Name": "WebWidgetAllowed",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "<RemoveEntry>"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
        "Name": "DiagnosticData",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "<RemoveEntry>"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
        "Name": "EdgeAssetDeliveryServiceEnabled",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "<RemoveEntry>"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
        "Name": "WalletDonationEnabled",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "<RemoveEntry>"
      }
    ]
  },
  "WPFTweaksUTC": {
    "Content": "Set Time to UTC (Dual Boot)",
    "handler": "tweak",
    "Description": "Essential for computers that are dual booting. Fixes the time sync with Linux Systems.",
    "category": "Advanced",
    "registry": [
      {
        "Path": "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation",
        "Name": "RealTimeIsUniversal",
        "Type": "DWord",
        "Value": "1",
        "OriginalValue": "0"
      }
    ]
  },
  "WPFTweaksRemoveHome": {
    "Content": "Remove Home from Explorer",
    "handler": "tweak",
    "Description": "Removes the Home from Explorer and sets This PC as default",
    "category": "Advanced",
    "InvokeScript": [
      "\n      Remove-Item \"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Desktop\\NameSpace\\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}\" -Recurse -Force -ErrorAction SilentlyContinue\n      Set-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" -Name LaunchTo -Value 1 -ErrorAction SilentlyContinue\n      "
    ],
    "UndoScript": [
      "\n      New-Item \"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Desktop\\NameSpace\\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}\" -Force -ErrorAction SilentlyContinue\n      Set-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" -Name LaunchTo -Value 0 -ErrorAction SilentlyContinue\n      "
    ]
  },
  "WPFTweaksRemoveGallery": {
    "Content": "Remove Gallery from explorer",
    "handler": "tweak",
    "Description": "Removes the Gallery from Explorer and sets This PC as default",
    "category": "Advanced",
    "InvokeScript": [
      "\n      Remove-Item \"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Desktop\\NameSpace\\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}\" -Recurse -Force -ErrorAction SilentlyContinue\n      "
    ],
    "UndoScript": [
      "\n      New-Item \"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Desktop\\NameSpace\\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}\" -Force -ErrorAction SilentlyContinue\n      "
    ]
  },
  "WPFTweaksDisplay": {
    "Content": "Set Display for Performance",
    "handler": "tweak",
    "Description": "Sets the system preferences to performance. You can do this manually with sysdm.cpl as well.",
    "category": "Advanced",
    "registry": [
      {
        "Path": "HKCU:\\Control Panel\\Desktop",
        "OriginalValue": "1",
        "Name": "DragFullWindows",
        "Value": "0",
        "Type": "String"
      },
      {
        "Path": "HKCU:\\Control Panel\\Desktop",
        "OriginalValue": "400",
        "Name": "MenuShowDelay",
        "Value": "200",
        "Type": "String"
      },
      {
        "Path": "HKCU:\\Control Panel\\Desktop\\WindowMetrics",
        "OriginalValue": "1",
        "Name": "MinAnimate",
        "Value": "0",
        "Type": "String"
      },
      {
        "Path": "HKCU:\\Control Panel\\Keyboard",
        "OriginalValue": "1",
        "Name": "KeyboardDelay",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        "OriginalValue": "1",
        "Name": "ListviewAlphaSelect",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        "OriginalValue": "1",
        "Name": "ListviewShadow",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        "OriginalValue": "1",
        "Name": "TaskbarAnimations",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VisualEffects",
        "OriginalValue": "1",
        "Name": "VisualFXSetting",
        "Value": "3",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\DWM",
        "OriginalValue": "1",
        "Name": "EnableAeroPeek",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        "OriginalValue": "1",
        "Name": "TaskbarMn",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        "OriginalValue": "1",
        "Name": "ShowTaskViewButton",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Search",
        "OriginalValue": "1",
        "Name": "SearchboxTaskbarMode",
        "Value": "0",
        "Type": "DWord"
      }
    ],
    "InvokeScript": [
      "Set-ItemProperty -Path \"HKCU:\\Control Panel\\Desktop\" -Name \"UserPreferencesMask\" -Type Binary -Value ([byte[]](144,18,3,128,16,0,0,0))"
    ],
    "UndoScript": [
      "Remove-ItemProperty -Path \"HKCU:\\Control Panel\\Desktop\" -Name \"UserPreferencesMask\""
    ]
  },
  "WPFTweaksEndTaskOnTaskbar": {
    "Content": "Enable End Task With Right Click",
    "handler": "tweak",
    "Description": "Enables option to end task when right clicking a program in the taskbar",
    "category": "Essential Tweaks",
    "registry": [
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\TaskbarDeveloperSettings",
        "Name": "TaskbarEndTask",
        "Type": "DWord",
        "Value": "1",
        "OriginalValue": "<RemoveEntry>"
      }
    ]
  },
  "WPFTweaksStorage": {
    "Content": "Disable Storage Sense",
    "handler": "tweak",
    "Description": "Storage Sense deletes temp files automatically.",
    "category": "Advanced",
    "registry": [
      {
        "Path": "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\StorageSense\\Parameters\\StoragePolicy",
        "Name": "01",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "1"
      }
    ]
  },
  "WPFTweaksWPBT": {
    "Content": "Disable Windows Platform Binary Table (WPBT)",
    "handler": "tweak",
    "Description": "If enabled then allows your computer vendor to execute a program each time it boots. It enables computer vendors to force install anti-theft software, software drivers, or a software program conveniently. This could also be a security risk.",
    "category": "Advanced",
    "registry": [
      {
        "Path": "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager",
        "Name": "DisableWpbtExecution",
        "Value": "1",
        "OriginalValue": "<RemoveEntry>",
        "Type": "DWord"
      }
    ]
  },
  "WPFTweaksRazerBlock": {
    "Content": "Block Razer Software Installs",
    "handler": "tweak",
    "Description": "Blocks ALL Razer Software installations. The hardware works fine without any software. WARNING: this will also block all Windows third-party driver installations.",
    "category": "Advanced",
    "registry": [
      {
        "Path": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DriverSearching",
        "Name": "SearchOrderConfig",
        "Value": "0",
        "OriginalValue": "1",
        "Type": "DWord"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Device Installer",
        "Name": "DisableCoInstallers",
        "Value": "1",
        "OriginalValue": "0",
        "Type": "DWord"
      }
    ],
    "InvokeScript": [
      "\n      $RazerPath = \"C:\\Windows\\Installer\\Razer\"\n\n      if (Test-Path $RazerPath) {\n        Remove-Item $RazerPath\\* -Recurse -Force -ErrorAction SilentlyContinue\n      }\n      else {\n        New-Item -Path $RazerPath -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null\n      }\n\n      icacls $RazerPath /deny \"Everyone:(W)\" 2>&1 | Out-Null\n      "
    ],
    "UndoScript": [
      "\n      icacls \"C:\\Windows\\Installer\\Razer\" /remove:d Everyone 2>&1 | Out-Null\n      "
    ]
  },
  "WPFTweaksDisableNotifications": {
    "Content": "Disable Notification Tray/Calendar",
    "handler": "tweak",
    "Description": "Disables all Notifications INCLUDING Calendar",
    "category": "Advanced",
    "registry": [
      {
        "Path": "HKCU:\\Software\\Policies\\Microsoft\\Windows\\Explorer",
        "Name": "DisableNotificationCenter",
        "Type": "DWord",
        "Value": "1",
        "OriginalValue": "<RemoveEntry>"
      },
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\PushNotifications",
        "Name": "ToastEnabled",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "1"
      }
    ]
  },
  "WPFTweaksBlockAdobeNet": {
    "Content": "Adobe Network Block",
    "handler": "tweak",
    "Description": "Reduce user interruptions by selectively blocking connections to Adobe's activation and telemetry servers. Credit: Ruddernation-Designs",
    "category": "Advanced",
    "InvokeScript": [
      "\n      $hostsUrl = \"https://github.com/Ruddernation-Designs/Adobe-URL-Block-List/raw/refs/heads/master/hosts\"\n      $hosts = \"$env:SystemRoot\\System32\\drivers\\etc\\hosts\"\n\n      Copy-Item $hosts \"$hosts.bak\" -Force -ErrorAction SilentlyContinue\n      Invoke-WebRequest $hostsUrl -OutFile $hosts -ErrorAction SilentlyContinue\n      ipconfig /flushdns 2>&1 | Out-Null\n      "
    ],
    "UndoScript": [
      "\n      $hosts = \"$env:SystemRoot\\System32\\drivers\\etc\\hosts\"\n      $backup = \"$hosts.bak\"\n\n      Copy-Item $backup $hosts -Force -ErrorAction SilentlyContinue\n      Remove-Item $backup -Force -ErrorAction SilentlyContinue\n      ipconfig /flushdns 2>&1 | Out-Null\n      "
    ]
  },
  "WPFTweaksRightClickMenu": {
    "Content": "Set Classic Right-Click Menu ",
    "handler": "tweak",
    "Description": "Great Windows 11 tweak to bring back good context menus when right clicking things in explorer.",
    "category": "Advanced",
    "InvokeScript": [
      "\n      New-Item -Path \"HKCU:\\Software\\Classes\\CLSID\\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\" -Name \"InprocServer32\" -Force -Value \"\" -ErrorAction SilentlyContinue | Out-Null\n      Stop-Process -Name \"explorer\" -Force -ErrorAction SilentlyContinue\n      "
    ],
    "UndoScript": [
      "\n      Remove-Item -Path \"HKCU:\\Software\\Classes\\CLSID\\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\" -Recurse -Confirm:$false -Force -ErrorAction SilentlyContinue\n      Stop-Process -Name \"explorer\" -Force -ErrorAction SilentlyContinue\n      "
    ]
  },
  "WPFTweaksDiskCleanup": {
    "Content": "Run Disk Cleanup",
    "handler": "tweak",
    "Description": "Runs Disk Cleanup on Drive C: and removes old Windows Updates.",
    "category": "Essential Tweaks",
    "InvokeScript": [
      "\n      # Run Disk Cleanup silently using SAGERUN\n      # First, set up cleanup profile 99 with all options\n      $cleanupPath = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VolumeCaches'\n      if (Test-Path $cleanupPath) {\n        Get-ChildItem $cleanupPath | ForEach-Object {\n          Set-ItemProperty -Path $_.PSPath -Name 'StateFlags0099' -Value 2 -Type DWord -ErrorAction SilentlyContinue\n        }\n      }\n      # Run cleanup with profile 99 (runs in background without prompts)\n      Start-Process -FilePath 'cleanmgr.exe' -ArgumentList '/SAGERUN:99' -Wait -WindowStyle Hidden\n      # Run DISM cleanup silently\n      Start-Process -FilePath 'Dism.exe' -ArgumentList '/online /Cleanup-Image /StartComponentCleanup /ResetBase /Quiet' -Wait -WindowStyle Hidden\n      "
    ]
  },
  "WPFTweaksDeleteTempFiles": {
    "Content": "Delete Temporary Files",
    "handler": "tweak",
    "Description": "Erases TEMP Folders",
    "category": "Essential Tweaks",
    "InvokeScript": [
      "\n      Remove-Item -Path \"$Env:Temp\\*\" -Recurse -Force -ErrorAction SilentlyContinue\n      Remove-Item -Path \"$Env:SystemRoot\\Temp\\*\" -Recurse -Force -ErrorAction SilentlyContinue\n      "
    ]
  },
  "WPFTweaksIPv46": {
    "Content": "Prefer IPv4 over IPv6",
    "handler": "tweak",
    "Description": "To set the IPv4 preference can have latency and security benefits on private networks where IPv6 is not configured.",
    "category": "Advanced",
    "registry": [
      {
        "Path": "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters",
        "Name": "DisabledComponents",
        "Value": "32",
        "OriginalValue": "0",
        "Type": "DWord"
      }
    ]
  },
  "WPFTweaksTeredo": {
    "Content": "Disable Teredo",
    "handler": "tweak",
    "Description": "Teredo network tunneling is a ipv6 feature that can cause additional latency, but may cause problems with some games",
    "category": "Advanced",
    "registry": [
      {
        "Path": "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters",
        "Name": "DisabledComponents",
        "Value": "1",
        "OriginalValue": "0",
        "Type": "DWord"
      }
    ],
    "InvokeScript": [
      "netsh interface teredo set state disabled"
    ],
    "UndoScript": [
      "netsh interface teredo set state default"
    ]
  },
  "WPFTweaksDisableIPv6": {
    "Content": "Disable IPv6",
    "handler": "tweak",
    "Description": "Disables IPv6.",
    "category": "Advanced",
    "registry": [
      {
        "Path": "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters",
        "Name": "DisabledComponents",
        "Value": "255",
        "OriginalValue": "0",
        "Type": "DWord"
      }
    ],
    "InvokeScript": [
      "Disable-NetAdapterBinding -Name * -ComponentID ms_tcpip6"
    ],
    "UndoScript": [
      "Enable-NetAdapterBinding -Name * -ComponentID ms_tcpip6"
    ]
  },
  "WPFTweaksDisableBGapps": {
    "Content": "Disable Background Apps",
    "handler": "tweak",
    "Description": "Disables all Microsoft Store apps from running in the background, which has to be done individually since Win11",
    "category": "Advanced",
    "registry": [
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\BackgroundAccessApplications",
        "Name": "GlobalUserDisabled",
        "Value": "1",
        "OriginalValue": "0",
        "Type": "DWord"
      }
    ]
  },
  "WPFTweaksDisableFSO": {
    "Content": "Disable Fullscreen Optimizations",
    "handler": "tweak",
    "Description": "Disables FSO in all applications. NOTE: This will disable Color Management in Exclusive Fullscreen",
    "category": "Advanced",
    "registry": [
      {
        "Path": "HKCU:\\System\\GameConfigStore",
        "Name": "GameDVR_DXGIHonorFSEWindowsCompatible",
        "Value": "1",
        "OriginalValue": "0",
        "Type": "DWord"
      }
    ]
  },
  "WPFToggleDarkMode": {
    "Content": "Dark Theme for Windows",
    "Description": "Enable/Disable Dark Mode.",
    "category": "Customize Preferences",
    "handler": "toggle",
    "registry": [
      {
        "Path": "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
        "Name": "AppsUseLightTheme",
        "Value": "0",
        "OriginalValue": "1",
        "DefaultState": "false",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
        "Name": "SystemUsesLightTheme",
        "Value": "0",
        "OriginalValue": "1",
        "DefaultState": "false",
        "Type": "DWord"
      }
    ],
    "InvokeScript": [
      "\n      try { Invoke-ExplorerUpdate } catch { }\n      "
    ],
    "UndoScript": [
      "\n      try { Invoke-ExplorerUpdate } catch { }\n      "
    ]
  },
  "WPFToggleNumLock": {
    "Content": "NumLock on Startup",
    "Description": "Toggle the Num Lock key state when your computer starts.",
    "category": "Customize Preferences",
    "handler": "toggle",
    "registry": [
      {
        "Path": "HKU:\\.Default\\Control Panel\\Keyboard",
        "Name": "InitialKeyboardIndicators",
        "Value": "2",
        "OriginalValue": "0",
        "DefaultState": "false",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Control Panel\\Keyboard",
        "Name": "InitialKeyboardIndicators",
        "Value": "2",
        "OriginalValue": "0",
        "DefaultState": "false",
        "Type": "DWord"
      }
    ]
  },
  "WPFToggleVerboseLogon": {
    "Content": "Verbose Messages During Logon",
    "Description": "Show detailed messages during the login process for troubleshooting and diagnostics.",
    "category": "Customize Preferences",
    "handler": "toggle",
    "registry": [
      {
        "Path": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        "Name": "VerboseStatus",
        "Value": "1",
        "OriginalValue": "0",
        "DefaultState": "false",
        "Type": "DWord"
      }
    ]
  },
  "WPFToggleHideSettingsHome": {
    "Content": "Remove Settings Home Page",
    "Description": "Removes the Home page in the Windows Settings app.",
    "category": "Customize Preferences",
    "handler": "toggle",
    "registry": [
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
        "Name": "SettingsPageVisibility",
        "Type": "String",
        "Value": "hide:home",
        "OriginalValue": "show:home",
        "DefaultState": "false"
      }
    ]
  },
  "WPFToggleSnapWindow": {
    "Content": "Snap Window",
    "Description": "If enabled you can align windows by dragging them. | Relogin Required",
    "category": "Customize Preferences",
    "handler": "toggle",
    "registry": [
      {
        "Path": "HKCU:\\Control Panel\\Desktop",
        "Name": "WindowArrangementActive",
        "Value": "1",
        "OriginalValue": "0",
        "DefaultState": "true",
        "Type": "String"
      }
    ]
  },
  "WPFToggleSnapFlyout": {
    "Content": "Snap Assist Flyout",
    "Description": "If disabled then Snap preview is disabled when maximize button is hovered.",
    "category": "Customize Preferences",
    "handler": "toggle",
    "registry": [
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        "Name": "EnableSnapAssistFlyout",
        "Value": "1",
        "OriginalValue": "0",
        "DefaultState": "true",
        "Type": "DWord"
      }
    ],
    "InvokeScript": [
      "\n      try { Invoke-ExplorerUpdate } catch { }\n      "
    ],
    "UndoScript": [
      "\n      try { Invoke-ExplorerUpdate } catch { }\n      "
    ]
  },
  "WPFToggleSnapSuggestion": {
    "Content": "Snap Assist Suggestion",
    "Description": "If enabled then you will get suggestions to snap other applications in the left over spaces.",
    "category": "Customize Preferences",
    "handler": "toggle",
    "registry": [
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        "Name": "SnapAssist",
        "Value": "1",
        "OriginalValue": "0",
        "DefaultState": "true",
        "Type": "DWord"
      }
    ],
    "InvokeScript": [
      "\n      try { Invoke-ExplorerUpdate } catch { }\n      "
    ],
    "UndoScript": [
      "\n      try { Invoke-ExplorerUpdate } catch { }\n      "
    ]
  },
  "WPFToggleMouseAcceleration": {
    "Content": "Mouse Acceleration",
    "Description": "If Enabled then Cursor movement is affected by the speed of your physical mouse movements.",
    "category": "Customize Preferences",
    "handler": "toggle",
    "registry": [
      {
        "Path": "HKCU:\\Control Panel\\Mouse",
        "Name": "MouseSpeed",
        "Value": "1",
        "OriginalValue": "0",
        "DefaultState": "true",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Control Panel\\Mouse",
        "Name": "MouseThreshold1",
        "Value": "6",
        "OriginalValue": "0",
        "DefaultState": "true",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Control Panel\\Mouse",
        "Name": "MouseThreshold2",
        "Value": "10",
        "OriginalValue": "0",
        "DefaultState": "true",
        "Type": "DWord"
      }
    ]
  },
  "WPFToggleStickyKeys": {
    "Content": "Sticky Keys",
    "Description": "If Enabled then Sticky Keys is activated - Sticky keys is an accessibility feature of some graphical user interfaces which assists users who have physical disabilities or help users reduce repetitive strain injury.",
    "category": "Customize Preferences",
    "handler": "toggle",
    "registry": [
      {
        "Path": "HKCU:\\Control Panel\\Accessibility\\StickyKeys",
        "Name": "Flags",
        "Value": "510",
        "OriginalValue": "58",
        "DefaultState": "true",
        "Type": "DWord"
      }
    ]
  },
  "WPFToggleNewOutlook": {
    "Content": "New Outlook",
    "Description": "If disabled it removes the toggle for new Outlook, disables the new Outlook migration and makes sure the Outlook Application actually uses the old Outlook.",
    "category": "Customize Preferences",
    "handler": "toggle",
    "registry": [
      {
        "Path": "HKCU:\\SOFTWARE\\Microsoft\\Office\\16.0\\Outlook\\Preferences",
        "Name": "UseNewOutlook",
        "Value": "1",
        "OriginalValue": "0",
        "DefaultState": "true",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Software\\Microsoft\\Office\\16.0\\Outlook\\Options\\General",
        "Name": "HideNewOutlookToggle",
        "Value": "0",
        "OriginalValue": "1",
        "DefaultState": "true",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Software\\Policies\\Microsoft\\Office\\16.0\\Outlook\\Options\\General",
        "Name": "DoNewOutlookAutoMigration",
        "Value": "0",
        "OriginalValue": "0",
        "DefaultState": "false",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Software\\Policies\\Microsoft\\Office\\16.0\\Outlook\\Preferences",
        "Name": "NewOutlookMigrationUserSetting",
        "Value": "0",
        "OriginalValue": "<RemoveEntry>",
        "DefaultState": "true",
        "Type": "DWord"
      }
    ]
  },
  "WPFToggleMultiplaneOverlay": {
    "Content": "Disable Multiplane Overlay",
    "Description": "Disable the Multiplane Overlay which can sometimes cause issues with Graphics Cards.",
    "category": "Customize Preferences",
    "handler": "toggle",
    "registry": [
      {
        "Path": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\Dwm",
        "Name": "OverlayTestMode",
        "Value": "5",
        "OriginalValue": "<RemoveEntry>",
        "DefaultState": "false",
        "Type": "DWord"
      }
    ]
  },
  "WPFToggleTaskbarAlignment": {
    "Content": "Center Taskbar Items",
    "Description": "[Windows 11] If Enabled then the Taskbar Items will be shown on the Center, otherwise the Taskbar Items will be shown on the Left.",
    "category": "Customize Preferences",
    "handler": "toggle",
    "registry": [
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        "Name": "TaskbarAl",
        "Value": "1",
        "OriginalValue": "0",
        "DefaultState": "true",
        "Type": "DWord"
      }
    ]
  },
  "WPFToggleHiddenFiles": {
    "Content": "Show Hidden Files",
    "Description": "If Enabled then Hidden Files will be shown.",
    "category": "Customize Preferences",
    "handler": "toggle",
    "registry": [
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        "Name": "Hidden",
        "Value": "1",
        "OriginalValue": "0",
        "DefaultState": "false",
        "Type": "DWord"
      }
    ],
    "InvokeScript": [
      "\n      Invoke-ExplorerUpdate -action \"restart\"\n      "
    ],
    "UndoScript": [
      "\n      Invoke-ExplorerUpdate -action \"restart\"\n      "
    ]
  },
  "WPFToggleShowExt": {
    "Content": "Show File Extensions",
    "Description": "If enabled then File extensions (e.g., .txt, .jpg) are visible.",
    "category": "Customize Preferences",
    "handler": "toggle",
    "registry": [
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        "Name": "HideFileExt",
        "Value": "0",
        "OriginalValue": "1",
        "DefaultState": "false",
        "Type": "DWord"
      }
    ],
    "InvokeScript": [
      "\n      Invoke-ExplorerUpdate -action \"restart\"\n      "
    ],
    "UndoScript": [
      "\n      Invoke-ExplorerUpdate -action \"restart\"\n      "
    ]
  },
  "WPFToggleDetailedBSoD": {
    "Content": "Detailed BSoD",
    "Description": "If Enabled then you will see a detailed Blue Screen of Death (BSOD) with more information.",
    "category": "Customize Preferences",
    "handler": "toggle",
    "registry": [
      {
        "Path": "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CrashControl",
        "Name": "DisplayParameters",
        "Value": "1",
        "OriginalValue": "0",
        "DefaultState": "false",
        "Type": "DWord"
      },
      {
        "Path": "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CrashControl",
        "Name": "DisableEmoticon",
        "Value": "1",
        "OriginalValue": "0",
        "DefaultState": "false",
        "Type": "DWord"
      }
    ]
  },
  "WPFToggleS3Sleep": {
    "Content": "S3 Sleep",
    "Description": "Toggles between Modern Standby and S3 sleep.",
    "category": "Customize Preferences",
    "handler": "toggle",
    "registry": [
      {
        "Path": "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Power",
        "Name": "PlatformAoAcOverride",
        "Value": "0",
        "OriginalValue": "<RemoveEntry>",
        "DefaultState": "false",
        "Type": "DWord"
      }
    ]
  },
  "WPFToggleUltPerf": {
    "Content": "Ultimate Performance Mode",
    "category": "Customize Preferences",
    "handler": "toggle",
    "Description": "Enables the Ultimate Performance power plan for maximum performance.",
    "InvokeScript": [
      "$output = powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61; $guid = ($output -replace '.*([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}).*', '$1'); powercfg -setactive $guid"
    ],
    "UndoScript": [
      "powercfg -setactive 381b4222-f694-41f0-9685-ff5bb260df2e; $plans = powercfg -list; foreach ($line in $plans) { if ($line -match 'Ultimate Performance') { $guid = ($line -replace '.*([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}).*', '$1'); powercfg -delete $guid } }"
    ]
  },
  "WPFTweaksDisableExplorerAutoDiscovery": {
    "Content": "Disable Explorer Automatic Folder Discovery",
    "handler": "tweak",
    "Description": "Windows Explorer automatically tries to guess the type of the folder based on its contents, slowing down the browsing experience.",
    "category": "Essential Tweaks",
    "InvokeScript": [
      "\n      # Previously detected folders\n      $bags = \"HKCU:\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\Bags\"\n\n      # Folder types lookup table\n      $bagMRU = \"HKCU:\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU\"\n\n      # Flush Explorer view database\n      Remove-Item -Path $bags -Recurse -Force -ErrorAction SilentlyContinue\n\n      Remove-Item -Path $bagMRU -Recurse -Force -ErrorAction SilentlyContinue\n\n      # Every folder\n      $allFolders = \"HKCU:\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\Bags\\AllFolders\\Shell\"\n\n      if (!(Test-Path $allFolders)) {\n        New-Item -Path $allFolders -Force -ErrorAction SilentlyContinue | Out-Null\n      }\n\n      # Generic view\n      New-ItemProperty -Path $allFolders -Name \"FolderType\" -Value \"NotSpecified\" -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null\n      "
    ],
    "UndoScript": [
      "\n      # Previously detected folders\n      $bags = \"HKCU:\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\Bags\"\n\n      # Folder types lookup table\n      $bagMRU = \"HKCU:\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU\"\n\n      # Flush Explorer view database\n      Remove-Item -Path $bags -Recurse -Force -ErrorAction SilentlyContinue\n\n      Remove-Item -Path $bagMRU -Recurse -Force -ErrorAction SilentlyContinue\n      "
    ]
  },
  "WPFToggleDisableCrossDeviceResume": {
    "Content": "Cross-Device Resume",
    "Description": "This tweak controls the Resume function in Windows 11 24H2 and later, which allows you to resume an activity from a mobile device and vice-versa.",
    "category": "Customize Preferences",
    "handler": "toggle",
    "registry": [
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\CrossDeviceResume\\Configuration",
        "Name": "IsResumeAllowed",
        "Value": "1",
        "OriginalValue": "0",
        "DefaultState": "true",
        "Type": "DWord"
      }
    ]
  }
}
'@

  $DebloatJson = @'
{
  "Clipchamp.Clipchamp": {
    "Name": "Clipchamp Video Editor",
    "Type": "provisioned",
    "Recommended": true,
    "handler": "debloat"
  },
  "Microsoft.3DBuilder": {
    "Name": "3D Builder",
    "Type": "provisioned",
    "Recommended": true,
    "handler": "debloat"
  },
  "Microsoft.549981C3F5F10": {
    "Name": "Cortana",
    "Type": "provisioned",
    "Recommended": true,
    "handler": "debloat"
  },
  "Microsoft.BingFinance": {
    "Name": "Bing Finance",
    "Type": "provisioned",
    "Recommended": true,
    "handler": "debloat"
  },
  "Microsoft.BingFoodAndDrink": {
    "Name": "Bing Food & Drink",
    "Type": "provisioned",
    "Recommended": true,
    "handler": "debloat"
  },
  "Microsoft.BingHealthAndFitness": {
    "Name": "Bing Health & Fitness",
    "Type": "provisioned",
    "Recommended": true,
    "handler": "debloat"
  },
  "Microsoft.BingNews": {
    "Name": "Bing News",
    "Type": "provisioned",
    "Recommended": true,
    "handler": "debloat"
  },
  "Microsoft.BingSports": {
    "Name": "Bing Sports",
    "Type": "provisioned",
    "Recommended": true,
    "handler": "debloat"
  },
  "Microsoft.BingTranslator": {
    "Name": "Bing Translator",
    "Type": "provisioned",
    "Recommended": true,
    "handler": "debloat"
  },
  "Microsoft.BingTravel": {
    "Name": "Bing Travel",
    "Type": "provisioned",
    "Recommended": true,
    "handler": "debloat"
  },
  "Microsoft.BingWeather": {
    "Name": "Bing Weather",
    "Type": "provisioned",
    "Recommended": true,
    "handler": "debloat"
  },
  "Microsoft.Windows.DevHome": {
    "Name": "Dev Home",
    "Type": "provisioned",
    "Recommended": false,
    "handler": "debloat"
  },
  "Microsoft.Copilot": {
    "Name": "Microsoft Copilot",
    "Type": "provisioned",
    "Recommended": true,
    "handler": "debloat"
  },
  "Microsoft.Getstarted": {
    "Name": "Get Started (Tips)",
    "Type": "provisioned",
    "Recommended": true,
    "handler": "debloat"
  },
  "Microsoft.Messaging": {
    "Name": "Microsoft Messaging",
    "Type": "provisioned",
    "Recommended": true,
    "handler": "debloat"
  },
  "Microsoft.Microsoft3DViewer": {
    "Name": "3D Viewer",
    "Type": "provisioned",
    "Recommended": true,
    "handler": "debloat"
  },
  "Microsoft.MicrosoftJournal": {
    "Name": "Microsoft Journal",
    "Type": "provisioned",
    "Recommended": false,
    "handler": "debloat"
  },
  "Microsoft.MicrosoftOfficeHub": {
    "Name": "Office Hub",
    "Type": "provisioned",
    "Recommended": true,
    "handler": "debloat"
  },
  "Microsoft.MicrosoftPowerBIForWindows": {
    "Name": "Power BI",
    "Type": "provisioned",
    "Recommended": false,
    "handler": "debloat"
  },
  "Microsoft.PowerAutomateDesktop": {
    "Name": "Power Automate",
    "Type": "provisioned",
    "Recommended": false,
    "handler": "debloat"
  },
  "Microsoft.MicrosoftSolitaireCollection": {
    "Name": "Solitaire Collection",
    "Type": "provisioned",
    "Recommended": true,
    "handler": "debloat"
  },
  "Microsoft.MicrosoftStickyNotes": {
    "Name": "Sticky Notes",
    "Type": "provisioned",
    "Recommended": false,
    "handler": "debloat"
  },
  "Microsoft.MixedReality.Portal": {
    "Name": "Mixed Reality Portal",
    "Type": "provisioned",
    "Recommended": true,
    "handler": "debloat"
  },
  "Microsoft.News": {
    "Name": "Microsoft News",
    "Type": "provisioned",
    "Recommended": true,
    "handler": "debloat"
  },
  "Microsoft.Office.OneNote": {
    "Name": "OneNote",
    "Type": "provisioned",
    "Recommended": false,
    "handler": "debloat"
  },
  "Microsoft.Office.Sway": {
    "Name": "Office Sway",
    "Type": "provisioned",
    "Recommended": true,
    "handler": "debloat"
  },
  "Microsoft.OneConnect": {
    "Name": "OneConnect",
    "Type": "provisioned",
    "Recommended": true,
    "handler": "debloat"
  },
  "Microsoft.Paint": {
    "Name": "Paint",
    "Type": "provisioned",
    "Recommended": false,
    "handler": "debloat"
  },
  "Microsoft.Print3D": {
    "Name": "Print 3D",
    "Type": "provisioned",
    "Recommended": true,
    "handler": "debloat"
  },
  "Microsoft.SkypeApp": {
    "Name": "Skype",
    "Type": "provisioned",
    "Recommended": true,
    "handler": "debloat"
  },
  "Microsoft.Todos": {
    "Name": "Microsoft To Do",
    "Type": "provisioned",
    "Recommended": false,
    "handler": "debloat"
  },
  "Microsoft.WindowsAlarms": {
    "Name": "Alarms & Clock",
    "Type": "provisioned",
    "Recommended": false,
    "handler": "debloat"
  },
  "Microsoft.WindowsCamera": {
    "Name": "Camera",
    "Type": "provisioned",
    "Recommended": false,
    "handler": "debloat"
  },
  "Microsoft.WindowsFeedbackHub": {
    "Name": "Feedback Hub",
    "Type": "provisioned",
    "Recommended": true,
    "handler": "debloat"
  },
  "Microsoft.WindowsMaps": {
    "Name": "Maps",
    "Type": "provisioned",
    "Recommended": true,
    "handler": "debloat"
  },
  "Microsoft.WindowsNotepad": {
    "Name": "Notepad",
    "Type": "provisioned",
    "Recommended": false,
    "handler": "debloat"
  },
  "Microsoft.WindowsSoundRecorder": {
    "Name": "Sound Recorder",
    "Type": "provisioned",
    "Recommended": false,
    "handler": "debloat"
  },

  "Microsoft.ZuneVideo": {
    "Name": "Movies & TV",
    "Type": "provisioned",
    "Recommended": true,
    "handler": "debloat"
  },
  "MicrosoftCorporationII.MicrosoftFamily": {
    "Name": "Microsoft Family",
    "Type": "provisioned",
    "Recommended": true,
    "handler": "debloat"
  },
  "MicrosoftTeams": {
    "Name": "Microsoft Teams",
    "Type": "provisioned",
    "Recommended": true,
    "handler": "debloat"
  },
  "MSTeams": {
    "Name": "Teams",
    "Type": "provisioned",
    "Recommended": true,
    "handler": "debloat"
  },
  "Microsoft.WindowsCalculator": {
    "Name": "Calculator",
    "Type": "provisioned",
    "Recommended": false,
    "handler": "debloat"
  },
  "Microsoft.Windows.Photos": {
    "Name": "Photos",
    "Type": "provisioned",
    "Recommended": false,
    "handler": "debloat"
  },
  "microsoft.windowscommunicationsapps": {
    "Name": "Mail & Calendar",
    "Type": "provisioned",
    "Recommended": true,
    "handler": "debloat"
  },

  "Microsoft.OneDrive": {
    "Name": "Microsoft OneDrive",
    "Type": "win32",
    "PackageName": "OneDrive",
    "Recommended": false,
    "handler": "debloat",
    "Notes": "Uninstalls OneDrive using the official uninstaller and disables future reinstalls."
  },
  "Microsoft.Xbox": {
    "Name": "Xbox (All Components)",
    "Type": "provisioned",
    "PackageName": "Microsoft.Xbox*,Microsoft.GamingApp*,Microsoft.GamingServices*,Microsoft.Xbox.TCUI*",
    "Recommended": false,
    "handler": "debloat",
    "Notes": "Removes Xbox app, Xbox Live UI, overlays, and prevents reinstallation by removing provisioned packages."
  },
  "Microsoft.OutlookForWindows": {
    "Name": "Outlook (New)",
    "Type": "provisioned",
    "PackageName": "Microsoft.OutlookForWindows",
    "Recommended": false,
    "handler": "debloat",
    "Notes": "Removes the new Microsoft Store-based Outlook app. Does not affect classic Outlook (Office)."
  },
  "Microsoft.QuickAssist": {
    "Name": "Quick Assist",
    "Type": "provisioned",
    "PackageName": "MicrosoftCorporationII.QuickAssist",
    "Recommended": false,
    "handler": "debloat",
    "Notes": "Removes Quick Assist remote support app and prevents automatic reinstallation."
  },
  "Amazon.com.Amazon": {
    "Name": "Amazon",
    "Type": "appx",
    "Recommended": true,
    "handler": "debloat"
  },
  "9P1J8S7CCWWT": {
    "Name": "Clipchamp (Store)",
    "Type": "appx",
    "Recommended": true,
    "handler": "debloat"
  },
  "AmazonVideo.PrimeVideo": {
    "Name": "Prime Video",
    "Type": "appx",
    "Recommended": true,
    "handler": "debloat"
  },
  "Disney": {
    "Name": "Disney+",
    "Type": "appx",
    "Recommended": true,
    "handler": "debloat"
  },
  "Duolingo-LearnLanguagesforFree": {
    "Name": "Duolingo",
    "Type": "appx",
    "Recommended": true,
    "handler": "debloat"
  },
  "Facebook": {
    "Name": "Facebook",
    "Type": "appx",
    "Recommended": true,
    "handler": "debloat"
  },
  "FarmVille2CountryEscape": {
    "Name": "FarmVille 2",
    "Type": "appx",
    "Recommended": true,
    "handler": "debloat"
  },
  "Instagram": {
    "Name": "Instagram",
    "Type": "appx",
    "Recommended": true,
    "handler": "debloat"
  },
  "Netflix": {
    "Name": "Netflix",
    "Type": "appx",
    "Recommended": true,
    "handler": "debloat"
  },
  "PandoraMediaInc.Pandora": {
    "Name": "Pandora",
    "Type": "appx",
    "Recommended": true,
    "handler": "debloat"
  },
  "Spotify": {
    "Name": "Spotify",
    "Type": "appx",
    "Recommended": false,
    "handler": "debloat"
  },
  "Twitter": {
    "Name": "Twitter",
    "Type": "appx",
    "Recommended": true,
    "handler": "debloat"
  },
  "TwitterUniversal": {
    "Name": "Twitter (Universal)",
    "Type": "appx",
    "Recommended": true,
    "handler": "debloat"
  },
  "YouTube": {
    "Name": "YouTube",
    "Type": "appx",
    "Recommended": true,
    "handler": "debloat"
  },
  "Plex": {
    "Name": "Plex",
    "Type": "appx",
    "Recommended": true,
    "handler": "debloat"
  },
  "TikTok": {
    "Name": "TikTok",
    "Type": "appx",
    "Recommended": true,
    "handler": "debloat"
  },
  "TuneInRadio": {
    "Name": "TuneIn Radio",
    "Type": "appx",
    "Recommended": true,
    "handler": "debloat"
  },
  "king.com.BubbleWitch3Saga": {
    "Name": "Bubble Witch 3 Saga",
    "Type": "appx",
    "Recommended": true,
    "handler": "debloat"
  },
  "king.com.CandyCrushSaga": {
    "Name": "Candy Crush Saga",
    "Type": "appx",
    "Recommended": true,
    "handler": "debloat"
  },
  "king.com.CandyCrushSodaSaga": {
    "Name": "Candy Crush Soda Saga",
    "Type": "appx",
    "Recommended": true,
    "handler": "debloat"
  }
}
'@

  $DnsJson = @'
{
  "Google": {
    "category": "Gaming",
	"handler": "dns",
    "servers": ["8.8.8.8", "8.8.4.4"],
    "doh": "https://dns.google/dns-query"
  },

  "Cloudflare": {
    "category": "Gaming",
	"handler": "dns",
    "servers": ["1.1.1.1", "1.0.0.1"],
    "doh": "https://cloudflare-dns.com/dns-query",
    "recommended": true
  },

  "Quad9": {
    "category": "Privacy",
	"handler": "dns",
    "servers": ["9.9.9.9", "149.112.112.112"],
    "doh": "https://dns.quad9.net/dns-query"
  },

  "Mullvad": {
    "category": "Privacy",
	"handler": "dns",
    "servers": ["194.242.2.2", "194.242.2.4"],
    "doh": "https://dns.mullvad.net/dns-query"
  },

  "ControlD": {
    "category": "Privacy",
	"handler": "dns",
    "servers": ["76.76.2.0", "76.76.10.0"],
    "doh": "https://dns.controld.com/p0"
  },

  "AdGuard": {
    "category": "Ad-Block",
	"handler": "dns",
    "servers": ["94.140.14.14", "94.140.15.15"],
    "doh": "https://dns.adguard-dns.com/dns-query"
  },

  "Mullvad Ad-Block": {
    "category": "Ad-Block",
	"handler": "dns",
    "servers": ["194.242.2.3"],
    "doh": "https://dns.mullvad.net/Ad-Block"
  },

  "ControlD Ad-Block": {
    "category": "Ad-Block",
	"handler": "dns",
    "servers": ["76.76.2.2", "76.76.10.2"],
    "doh": "https://dns.controld.com/p2"
  },

  "ControlD Hagezi Pro": {
    "category": "Ad-Block",
	"handler": "dns",
    "servers": ["76.76.2.41", "76.76.10.41"],
    "doh": "https://dns.controld.com/p41"
  },

  "ControlD Hagezi Ultimate": {
    "category": "Ad-Block",
	"handler": "dns",
    "servers": ["76.76.2.45", "76.76.10.45"],
    "doh": "https://dns.controld.com/p45"
  },

  "ControlD Hagezi TIF": {
    "category": "Ad-Block",
	"handler": "dns",
    "servers": ["76.76.2.46", "76.76.10.46"],
    "doh": "https://dns.controld.com/p46"
  },

  "ControlD OISD Full": {
    "category": "Ad-Block",
	"handler": "dns",
    "servers": ["76.76.2.32", "76.76.10.32"],
    "doh": "https://dns.controld.com/p32"
  },

  "ControlD OISD Basic": {
    "category": "Ad-Block",
	"handler": "dns",
    "servers": ["76.76.2.33", "76.76.10.33"],
    "doh": "https://dns.controld.com/p33"
  },

  "Mullvad Family": {
    "category": "Family",
	"handler": "dns",
    "servers": ["194.242.2.6"],
    "doh": "https://dns.mullvad.net/Family"
  },

  "CleanBrowsing Family": {
    "category": "Family",
	"handler": "dns",
    "servers": ["185.228.168.168", "185.228.169.168"],
    "doh": "https://Family-filter-dns.cleanbrowsing.org/dns-query"
  },

  "ControlD Family": {
    "category": "Family",
	"handler": "dns",
    "servers": ["76.76.2.4", "76.76.10.4"],
    "doh": "https://dns.controld.com/p4"
  },

  "ControlD Malware Protection": {
    "category": "Family",
	"handler": "dns",
    "servers": ["76.76.2.1", "76.76.10.1"],
    "doh": "https://dns.controld.com/p1"
  },

  "AdGuard Family": {
    "category": "Family",
	"handler": "dns",
    "servers": ["94.140.14.15", "94.140.15.16"],
    "doh": "https://Family.adguard-dns.com/dns-query"
  },

  "Quad9 Malware Protection": {
    "category": "Family",
	"handler": "dns",
    "servers": ["9.9.9.11", "149.112.112.11"],
    "doh": "https://dns.quad9.net/dns-query"
  }
}
'@

  $NetworkTweaksJson = @'
{
  "repair_tools": {
    "title": "Network Repair Tools",
	"handler": "network-repair",
    "description": "Safe tools to fix common networking issues. These make temporary changes or reset components.",
    "items": {
      "flush_dns": {
        "label": "Flush DNS Cache",
        "handler": "network-repair",
        "type": "command",
        "script": "ipconfig /flushdns",
        "requires_admin": true
      },
      "reset_winsock": {
        "label": "Reset Winsock",
        "handler": "network-repair",
        "type": "command",
        "script": "netsh winsock reset",
        "requires_admin": true,
        "requires_reboot": true
      },
      "reset_tcpip": {
        "label": "Reset TCP/IP Stack",
        "handler": "network-repair",
        "type": "command",
        "script": "netsh int ip reset",
        "requires_admin": true,
        "requires_reboot": true
      }
    }
  },

  "gaming_latency": {
    "title": "Gaming / Low-Latency Scheduling",
	"handler": "network-gaming",
    "description": "Improves responsiveness for games and real-time workloads. Does not increase raw bandwidth.",
    "items": {
      "disable_network_throttling": {
        "label": "Disable Network Throttling",
        "handler": "network-gaming",
        "type": "registry",
        "path": "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile",
        "name": "NetworkThrottlingIndex",
        "value_type": "DWORD",
        "value": "0xffffffff",
        "requires_admin": true,
        "recommended": true
      },
      "maximize_system_responsiveness": {
        "label": "Maximize System Responsiveness",
        "handler": "network-gaming",
        "type": "registry",
        "path": "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile",
        "name": "SystemResponsiveness",
        "value_type": "DWORD",
        "value": "0",
        "requires_admin": true,
        "recommended": true
      },
      "optimize_games_task_scheduling": {
        "label": "Optimize Game Task Scheduling",
        "handler": "network-gaming",
        "type": "registry_group",
        "path": "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games",
        "entries": {
          "GPU Priority": {
            "value_type": "DWORD",
            "value": "8"
          },
          "Priority": {
            "value_type": "DWORD",
            "value": "6"
          },
          "Scheduling Category": {
            "value_type": "STRING",
            "value": "High"
          },
          "SFIO Priority": {
            "value_type": "STRING",
            "value": "High"
          }
        },
        "requires_admin": true,
        "recommended": true
      }
    }
  },

  "tcp_stack_advanced": {
    "title": "Advanced TCP/IP Stack Tweaks",
	"handler": "advanced-TCP",
    "description": "Advanced networking tweaks. These may help in specific scenarios but can reduce performance on modern networks.",
    "advanced": true,
    "items": {
      "disable_tcp_autotuning": {
        "label": "Disable TCP Auto-Tuning",
        "handler": "advanced-TCP",
        "type": "command",
        "script": "netsh int tcp set global autotuninglevel=disabled",
        "requires_admin": true,
        "warning": "May reduce download speeds on modern networks."
      },
      "enable_rss": {
        "label": "Enable Receive-Side Scaling (RSS)",
        "handler": "advanced-TCP",
        "type": "command",
        "script": "netsh int tcp set global rss=enabled",
        "requires_admin": true
      },
      "disable_tcp_chimney": {
        "label": "Disable TCP Chimney Offload",
        "handler": "advanced-TCP",
        "type": "command",
        "script": "netsh int tcp set global chimney=disabled",
        "requires_admin": true
      },
      "disable_ecn": {
        "label": "Disable Explicit Congestion Notification (ECN)",
        "handler": "advanced-TCP",
        "type": "command",
        "script": "netsh int tcp set global ecncapability=disabled",
        "requires_admin": true,
        "warning": "Compatibility tweak for problematic routers."
      }
    }
  }
}
'@

  $PrivacyTweaksJson = @'
{
  "WPFTweaksPowershell7Tele": {
    "Content": "Disable Powershell 7 Telemetry",
    "Description": "Disables Powershell 7 Telemetry Data.",
    "category": "Privacy",
    "handler": "tweak",
    "InvokeScript": [
      "[Environment]::SetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT', '1', 'Machine')"
    ]
  },
  "WPFTweaksConsumerFeatures": {
    "Content": "Disable Consumer Features",
    "Description": "Prevents Windows from automatically installing unwanted apps, games, and links.",
    "category": "Privacy",
    "handler": "tweak",
    "registry": [
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent",
        "Name": "DisableWindowsConsumerFeatures",
        "Value": "1",
        "Type": "DWord"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent",
        "Name": "DisableConsumerAccountStateContent",
        "Value": "1",
        "Type": "DWord"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent",
        "Name": "DisableCloudOptimizedContent",
        "Value": "1",
        "Type": "DWord"
      }
    ]
  },
  "WPFTweaksTelemetry": {
    "Content": "Disable Telemetry",
    "Description": "Disables Windows Telemetry and Data Collection.",
    "category": "Privacy",
    "handler": "tweak",
    "registry": [
      {
        "Path": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\DataCollection",
        "Name": "AllowTelemetry",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection",
        "Name": "AllowTelemetry",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager",
        "Name": "ContentDeliveryAllowed",
        "Value": "0",
        "Type": "DWord"
      }
    ],
    "ScheduledTask": [
        { "Name": "Microsoft\\Windows\\Customer Experience Improvement Program\\Consolidator", "State": "Disabled" },
        { "Name": "Microsoft\\Windows\\Customer Experience Improvement Program\\UsbCeip", "State": "Disabled" },
        { "Name": "Microsoft\\Windows\\Customer Experience Improvement Program\\KernelCeipTask", "State": "Disabled" },
        { "Name": "Microsoft\\Windows\\Application Experience\\Microsoft Compatibility Appraiser", "State": "Disabled" },
        { "Name": "Microsoft\\Windows\\Application Experience\\ProgramDataUpdater", "State": "Disabled" }
    ],
    "service": [
        { "Name": "DiagTrack", "StartupType": "Disabled" },
        { "Name": "dmwappushservice", "StartupType": "Disabled" }
    ]
  },
  "WPFTweaksActivity": {
    "Content": "Disable Activity History",
    "Description": "Prevents Windows from collecting activity history.",
    "category": "Privacy",
    "handler": "tweak",
    "registry": [
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System",
        "Name": "EnableActivityFeed",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System",
        "Name": "PublishUserActivities",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System",
        "Name": "UploadUserActivities",
        "Value": "0",
        "Type": "DWord"
      },
	  {
      "Path": "HKCU:\\Control Panel\\International\\User Profile",
      "Name": "HttpAcceptLanguageOptOut",
      "Value": "1",
      "Type": "DWord"
    }
    ]
  },
  "WPFTweaksLocation": {
    "Content": "Disable Location Tracking",
    "Description": "Disables system-wide location services.",
    "category": "Privacy",
    "handler": "tweak",
    "registry": [
      {
        "Path": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\location",
        "Name": "Value",
        "Value": "Deny",
        "Type": "String"
      }
    ],
    "service": [
        { "Name": "lfsvc", "StartupType": "Disabled" }
    ]
  },
"WPFTweaksDisableCopilot": {
  "Content": "Disable Copilot (Windows + Edge)",
  "Description": "Disables Microsoft Copilot across Windows and Microsoft Edge, including Copilot 365, Edge Copilot UI, and browsing context sharing.",
  "category": "Privacy",
  "handler": "tweak",
  "registry": [
    {
      "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsCopilot",
      "Name": "TurnOffWindowsCopilot",
      "Value": "1",
      "Type": "DWord"
    },
    {
      "Path": "HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsCopilot",
      "Name": "TurnOffWindowsCopilot",
      "Value": "1",
      "Type": "DWord"
    },
    {
      "Path": "HKCU:\\Software\\Microsoft\\Windows\\Shell\\Copilot\\BingChat",
      "Name": "IsUserEligible",
      "Value": "0",
      "Type": "DWord"
    },
    {
      "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Notifications\\Settings",
      "Name": "AutoOpenCopilotLargeScreens",
      "Value": "0",
      "Type": "DWord"
    },
    {
      "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
      "Name": "ShowCopilotButton",
      "Value": "0",
      "Type": "DWord"
    },
    {
      "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
      "Name": "HubsSidebarEnabled",
      "Value": "0",
      "Type": "DWord"
    },
    {
      "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
      "Name": "StandaloneHubsSidebarEnabled",
      "Value": "0",
      "Type": "DWord"
    },
    {
      "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
      "Name": "NewTabPageBingChatEnabled",
      "Value": "0",
      "Type": "DWord"
    },
    {
      "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
      "Name": "EdgeDiscoverEnabled",
      "Value": "0",
      "Type": "DWord"
    },
    {
      "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
      "Name": "DiscoverPageContextEnabled",
      "Value": "0",
      "Type": "DWord"
    },
    {
      "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
      "Name": "CopilotPageContext",
      "Value": "0",
      "Type": "DWord"
    },
    {
      "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
      "Name": "CopilotCDPPageContext",
      "Value": "0",
      "Type": "DWord"
    },
	{
      "Path": "HKCU:\\Software\\Microsoft\\Notepad",
      "Name": "EnableCopilot",
      "Value": "0",
      "Type": "DWord"
    },
    {
     "Path": "HKCU:\\Software\\Microsoft\\Office\\16.0\\Common\\Privacy",
     "Name": "DisableConnectedExperiences",
     "Value": "1",
     "Type": "DWord"
    },
    {
     "Path": "HKCU:\\Software\\Microsoft\\Office\\16.0\\Common\\Privacy",
     "Name": "DisableOptionalConnectedExperiences",
     "Value": "1",
     "Type": "DWord"
    }
  ]
},
  "WPFTweaksDVR": {
    "Content": "Disable GameDVR",
    "Description": "Disables GameDVR (Xbox Game Bar recording).",
    "category": "Privacy",
    "handler": "tweak",
    "registry": [
      {
        "Path": "HKCU:\\System\\GameConfigStore",
        "Name": "GameDVR_Enabled",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR",
        "Name": "AllowGameDVR",
        "Value": "0",
        "Type": "DWord"
      }
    ]
  },
"WPFTweaksSearchPrivacy": {
  "Content": "Harden Windows Search",
  "Description": "Prevents Windows Search from sending queries, device data, and usage metadata to Microsoft while preserving fast local search functionality.",
  "category": "Privacy",
  "handler": "tweak",
  "registry": [
    {
      "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Search",
      "Name": "BingSearchEnabled",
      "Value": "0",
      "Type": "DWord"
    },
    {
      "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Search",
      "Name": "AllowSearchToUseLocation",
      "Value": "0",
      "Type": "DWord"
    },
    {
      "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Search",
      "Name": "SearchboxTaskbarMode",
      "Value": "0",
      "Type": "DWord"
    },
    {
      "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search",
      "Name": "AllowCloudSearch",
      "Value": "0",
      "Type": "DWord"
    },
    {
      "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search",
      "Name": "DisableWebSearch",
      "Value": "1",
      "Type": "DWord"
    },
    {
      "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search",
      "Name": "ConnectedSearchUseWeb",
      "Value": "0",
      "Type": "DWord"
    },
    {
      "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search",
      "Name": "ConnectedSearchUseWebOverMeteredConnections",
      "Value": "0",
      "Type": "DWord"
    },
	{
      "Path": "HKLM:\\Software\\Policies\\Microsoft\\Windows\\Explorer",
      "Name": "DisableSearchHistory",
      "Value": "1",
      "Type": "DWord"
    },
    {
      "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\SearchSettings",
      "Name": "IsDeviceSearchHistoryEnabled",
      "Value": "0",
      "Type": "DWord"
    }
  ]
},
  "WPFToggleStartMenuRecommendations": {
    "Content": "Disable Start Menu Recommendations",
    "Description": "Removes 'Recommended' section from Start Menu.",
    "category": "Privacy",
    "handler": "tweak",
    "registry": [
       {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer",
        "Name": "HideRecommendedSection",
        "Value": "1",
        "Type": "DWord"
      },
	  {
      "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
      "Name": "Start_TrackProgs",
      "Value": "0",
      "Type": "DWord"
    }
    ]
  },
"WPFTweaksWidgetsPrivacy": {
  "Content": "Disable Widgets & Web Feeds",
  "Description": "Disables Windows Widgets, including background services and web-based news feeds, to prevent unnecessary network requests and data collection.",
  "category": "Privacy",
  "handler": "tweak",
  "registry": [
    {
      "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Dsh",
      "Name": "AllowNewsAndInterests",
      "Value": "0",
      "Type": "DWord"
    },
    {
      "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Feeds",
      "Name": "EnableFeeds",
      "Value": "0",
      "Type": "DWord"
    }
  ]
},
"WPFTweaksEdgePrivacy": {
  "Content": "Harden Edge Privacy",
  "Description": "Reduces Microsoft Edge telemetry, ads, tracking, cloud services, and UX noise while keeping Edge fully functional and update-safe. Edge Copilot is excluded.",
  "category": "Privacy",
  "handler": "tweak",
  "registry": [
    {
      "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
      "Name": "DiagnosticData",
      "Value": "0",
      "Type": "DWord"
    },
    {
      "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
      "Name": "MetricsReportingEnabled",
      "Value": "0",
      "Type": "DWord"
    },
    {
      "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
      "Name": "SendSiteInfoToImproveServices",
      "Value": "0",
      "Type": "DWord"
    },
    {
      "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
      "Name": "UserFeedbackAllowed",
      "Value": "0",
      "Type": "DWord"
    },
    {
      "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
      "Name": "ShowRecommendationsEnabled",
      "Value": "0",
      "Type": "DWord"
    },
    {
      "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
      "Name": "BingAdsSuppression",
      "Value": "0",
      "Type": "DWord"
    },
    {
      "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
      "Name": "PromotionalTabsEnabled",
      "Value": "0",
      "Type": "DWord"
    },
    {
      "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
      "Name": "MicrosoftEdgeInsiderPromotionEnabled",
      "Value": "0",
      "Type": "DWord"
    },
    {
      "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
      "Name": "SpotlightExperiencesAndRecommendationsEnabled",
      "Value": "0",
      "Type": "DWord"
    },
    {
      "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
      "Name": "ShowMicrosoftRewards",
      "Value": "0",
      "Type": "DWord"
    },
    {
      "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
      "Name": "TrackingPrevention",
      "Value": "3",
      "Type": "DWord"
    },
    {
      "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
      "Name": "BlockThirdPartyCookies",
      "Value": "1",
      "Type": "DWord"
    },
    {
      "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
      "Name": "ConfigureDoNotTrack",
      "Value": "1",
      "Type": "DWord"
    },
    {
      "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
      "Name": "StartupBoostEnabled",
      "Value": "0",
      "Type": "DWord"
    },
    {
      "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
      "Name": "SearchSuggestEnabled",
      "Value": "0",
      "Type": "DWord"
    },
    {
      "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
      "Name": "ResolveNavigationErrorsUseWebService",
      "Value": "0",
      "Type": "DWord"
    },
    {
      "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
      "Name": "RelatedMatchesCloudServiceEnabled",
      "Value": "0",
      "Type": "DWord"
    },
    {
      "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
      "Name": "EdgeShoppingAssistantEnabled",
      "Value": "0",
      "Type": "DWord"
    },
    {
      "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
      "Name": "EdgeCollectionsEnabled",
      "Value": "0",
      "Type": "DWord"
    },
    {
      "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
      "Name": "EdgeFollowEnabled",
      "Value": "0",
      "Type": "DWord"
    },
    {
      "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
      "Name": "ExperimentationAndConfigurationServiceControl",
      "Value": "0",
      "Type": "DWord"
    }
  ]
},
  "WPFTweaksStoreAds": {
    "Content": "Disable Advertising ID",
    "Description": "Prevents apps from using your advertising ID for experiences across apps.",
    "category": "Privacy",
    "handler": "tweak",
    "registry": [
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo",
        "Name": "Enabled",
        "Value": "0",
        "Type": "DWord"
      }
    ]
  },
  "WPFTweaksTailored": {
    "Content": "Disable Tailored Experiences",
    "Description": "Prevents Windows from using diagnostic data to provide tailored experiences.",
    "category": "Privacy",
    "handler": "tweak",
    "registry": [
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Privacy",
        "Name": "TailoredExperiencesWithDiagnosticDataEnabled",
        "Value": "0",
        "Type": "DWord"
      }
    ]
  },
  "WPFTweaksInputPersonalization": {
    "Content": "Disable Typing Insights",
    "Description": "Disables typing and handwriting data collection and insights.",
    "category": "Privacy",
    "handler": "tweak",
    "registry": [
      {
        "Path": "HKCU:\\Software\\Microsoft\\InputPersonalization",
        "Name": "RestrictImplicitTextCollection",
        "Value": "1",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Software\\Microsoft\\InputPersonalization",
        "Name": "RestrictImplicitInkCollection",
        "Value": "1",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Software\\Microsoft\\InputPersonalization\\TrainedDataStore",
        "Name": "HarvestContacts",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\InputPersonalization",
        "Name": "AllowInputInsights",
        "Value": "0",
        "Type": "DWord"
      }
    ]
  },
  "WPFTweaksFeedback": {
    "Content": "Disable Feedback Prompts",
    "Description": "Disables the 'Windows should ask for my feedback' prompts.",
    "category": "Privacy",
    "handler": "tweak",
    "registry": [
      {
        "Path": "HKCU:\\Software\\Microsoft\\Siuf\\Rules",
        "Name": "NumberOfSIUFInPeriod",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Software\\Microsoft\\Siuf\\Rules",
        "Name": "PeriodInNanoSeconds",
        "Value": "0",
        "Type": "QWord"
      }
    ]
  },
  "WPFTweaksRecall": {
    "Content": "Disable Recall (AI Timeline)",
    "Description": "Disables the Windows Recall (AI Timeline) feature which screenshots your activity.",
    "category": "Privacy",
    "handler": "tweak",
    "registry": [
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsAI",
        "Name": "DisableAIDataAnalysis",
        "Value": "1",
        "Type": "DWord"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsAI",
        "Name": "DisableRecall",
        "Value": "1",
        "Type": "DWord"
      }
    ]
  }
}
'@


  # Parse JSONs
  $AppsData = $AppsJson | ConvertFrom-Json
  $TweaksData = $TweaksJson | ConvertFrom-Json
  $DebloatData = $DebloatJson | ConvertFrom-Json
  $DnsData = $DnsJson | ConvertFrom-Json
  $NetData = $NetworkTweaksJson | ConvertFrom-Json
  $PrivacyData = $PrivacyTweaksJson | ConvertFrom-Json

  # ==============================================================================
  # SECTION 6: TWEAK CORE (Central tweak runner with dry-run support)
  # ==============================================================================

  function Invoke-Tweak {
    param(
      [Parameter(Mandatory)][string]$TweakId,
      [Parameter(Mandatory)]$TweakData,
      [switch]$IsUndo,
      [switch]$WhatIf  # Dry-run mode
    )
    
    $result = [PSCustomObject]@{
      TweakId         = $TweakId
      Success         = $true
      RegistryChanges = 0
      ServicesChanged = 0
      WouldChange     = @()
      Duration        = [TimeSpan]::Zero
      ErrorMessage    = ""
    }
    
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    
    try {
      # Registry changes
      if ($TweakData.registry) {
        foreach ($reg in $TweakData.registry) {
          $valueToApply = if ($IsUndo -and $reg.OriginalValue) { $reg.OriginalValue } else { $reg.Value }
                
          # Handle <RemoveEntry> for undo
          if ($IsUndo -and $valueToApply -eq "<RemoveEntry>") {
            if ($WhatIf) {
              $result.WouldChange += "Remove: $($reg.Path)\$($reg.Name)"
            }
            else {
              $fullPath = $reg.Path -replace "HKLM:", "Registry::HKEY_LOCAL_MACHINE" -replace "HKCU:", "Registry::HKEY_CURRENT_USER"
              Remove-ItemProperty -Path $fullPath -Name $reg.Name -ErrorAction SilentlyContinue
            }
            $result.RegistryChanges++
            continue
          }
                
          if ($WhatIf) {
            $result.WouldChange += "Registry: $($reg.Path)\$($reg.Name) -> $valueToApply"
          }
          else {
            Set-RegistryValue -Path $reg.Path -Name $reg.Name -Value $valueToApply -Type $reg.Type
          }
          $result.RegistryChanges++
        }
      }
        
      # Service changes
      if ($TweakData.service) {
        foreach ($srv in $TweakData.service) {
          if ($WhatIf) {
            $result.WouldChange += "Service: $($srv.Name) -> $($srv.StartupType)"
          }
          else {
            Set-ServiceState -Name $srv.Name -StartupType $srv.StartupType
          }
          $result.ServicesChanged++
        }
      }
        
      # Scheduled tasks
      if ($TweakData.ScheduledTask -and -not $WhatIf) {
        foreach ($task in $TweakData.ScheduledTask) {
          try {
            if ($task.State -eq "Disabled") {
              Disable-ScheduledTask -TaskName $task.Name -ErrorAction SilentlyContinue | Out-Null
            }
            else {
              Enable-ScheduledTask -TaskName $task.Name -ErrorAction SilentlyContinue | Out-Null
            }
            Write-Log "Scheduled Task: $($task.Name) -> $($task.State)" "SUCCESS"
          }
          catch {
            Write-Log "Scheduled Task failed: $($task.Name)" "SKIPPED"
          }
        }
      }
        
      # Script execution (skip in dry-run)
      $scripts = if ($IsUndo) { $TweakData.UndoScript } else { $TweakData.InvokeScript }
      if ($scripts -and -not $WhatIf) {
        foreach ($line in $scripts) {
          $sb = [scriptblock]::Create($line)
          & $sb
        }
      }
      elseif ($scripts -and $WhatIf) {
        $result.WouldChange += "Script: $(($scripts | Select-Object -First 1).Substring(0, [Math]::Min(50, $scripts[0].Length)))..."
      }
        
      $Global:OptimizerState.AppliedTweaks += $TweakId
    }
    catch {
      $result.Success = $false
      $result.ErrorMessage = $_.ToString()
      $Global:OptimizerState.Errors += @{ Id = $TweakId; Error = $_.ToString() }
      Write-Log "Tweak failed: $TweakId - $_" "ERROR"
    }
    
    $result.Duration = $sw.Elapsed
    return $result
  }

  # ==============================================================================
  # SECTION 7: INSTALLERS (Winget)
  # ==============================================================================

  function Install-App {
    param([Parameter(Mandatory)][string]$WingetId)
    
    try {
      $null = winget install --id $WingetId --silent --accept-source-agreements --accept-package-agreements 2>&1
      if ($LASTEXITCODE -eq 0) {
        Write-Log "Installed: $WingetId" "SUCCESS"
        return $true
      }
      else {
        Write-Log "Install failed: $WingetId - Exit code $LASTEXITCODE" "ERROR"
        return $false
      }
    }
    catch {
      Write-Log "Install error: $WingetId - $_" "ERROR"
      return $false
    }
  }

  # ==============================================================================
  # SECTION 8: UI (XAML Definition)
  # ==============================================================================
  $XamlContent = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="MakeWindowsGreatAgain" Height="720" Width="1200"
        WindowStartupLocation="CenterScreen"
        Background="#161618" Foreground="#f4f4f5"
        FontFamily="Segoe UI Variable, Segoe UI, sans-serif"
        UseLayoutRounding="True"
        SnapsToDevicePixels="True">

    <Window.Resources>
        <!-- ============================================ -->
        <!-- ENHANCED COLOR PALETTE - Layered Dark Theme -->
        <!-- ============================================ -->
        
        <!-- Surface layers for visual depth -->
        <SolidColorBrush x:Key="Surface0" Color="#0f0f10"/>
        <SolidColorBrush x:Key="Surface1" Color="#161618"/>
        <SolidColorBrush x:Key="Surface2" Color="#1e1e21"/>
        <SolidColorBrush x:Key="Surface3" Color="#27272b"/>
        <SolidColorBrush x:Key="Surface4" Color="#323238"/>
        
        <!-- Legacy compatibility -->
        <SolidColorBrush x:Key="WindowBackground" Color="#161618"/>
        <SolidColorBrush x:Key="PanelBackground" Color="#1e1e21"/>
        
        <!-- Text colors -->
        <SolidColorBrush x:Key="PrimaryText" Color="#f4f4f5"/>
        <SolidColorBrush x:Key="SecondaryText" Color="#a1a1aa"/>
        <SolidColorBrush x:Key="TertiaryText" Color="#71717a"/>
        
        <!-- Accent colors -->
        <SolidColorBrush x:Key="AccentColor" Color="#14b8a6"/>
        <SolidColorBrush x:Key="AccentHover" Color="#2dd4bf"/>
        <SolidColorBrush x:Key="AccentMuted" Color="#0d9488"/>
        
        <!-- Status colors -->
        <SolidColorBrush x:Key="SuccessColor" Color="#22c55e"/>
        <SolidColorBrush x:Key="WarningColor" Color="#f59e0b"/>
        <SolidColorBrush x:Key="ErrorColor" Color="#ef4444"/>
        
        <!-- Border -->
        <SolidColorBrush x:Key="BorderColor" Color="#3f3f46"/>
        <SolidColorBrush x:Key="BorderSubtle" Color="#27272a"/>

        <!-- ============================================ -->
        <!-- TYPOGRAPHY STYLES                           -->
        <!-- ============================================ -->
        
        <Style x:Key="HeadingLarge" TargetType="TextBlock">
            <Setter Property="FontSize" Value="24"/>
            <Setter Property="FontWeight" Value="Bold"/>
            <Setter Property="Foreground" Value="{StaticResource PrimaryText}"/>
        </Style>
        
        <Style x:Key="HeadingMedium" TargetType="TextBlock">
            <Setter Property="FontSize" Value="18"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Foreground" Value="{StaticResource PrimaryText}"/>
        </Style>
        
        <Style x:Key="HeadingSmall" TargetType="TextBlock">
            <Setter Property="FontSize" Value="14"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Foreground" Value="{StaticResource AccentColor}"/>
        </Style>

        <!-- ============================================ -->
        <!-- PROGRESS BAR STYLE                          -->
        <!-- ============================================ -->
        
        <Style x:Key="StatusProgressBar" TargetType="ProgressBar">
            <Setter Property="Height" Value="3"/>
            <Setter Property="Background" Value="{StaticResource Surface3}"/>
            <Setter Property="Foreground" Value="{StaticResource AccentColor}"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="ProgressBar">
                        <Grid>
                            <Border Background="{TemplateBinding Background}" CornerRadius="2"/>
                            <Border x:Name="PART_Track"/>
                            <Border x:Name="PART_Indicator" HorizontalAlignment="Left" CornerRadius="2">
                                <Border.Background>
                                    <LinearGradientBrush StartPoint="0,0" EndPoint="1,0">
                                        <GradientStop Color="#14b8a6" Offset="0"/>
                                        <GradientStop Color="#2dd4bf" Offset="1"/>
                                    </LinearGradientBrush>
                                </Border.Background>
                            </Border>
                        </Grid>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- ============================================ -->
        <!-- BUTTON STYLES                               -->
        <!-- ============================================ -->

        <Style TargetType="Button">
            <Setter Property="Background" Value="{StaticResource Surface3}"/>
            <Setter Property="Foreground" Value="{StaticResource PrimaryText}"/>
            <Setter Property="BorderBrush" Value="{StaticResource BorderColor}"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding" Value="14,8"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="border" Background="{TemplateBinding Background}" 
                                BorderBrush="{TemplateBinding BorderBrush}" 
                                BorderThickness="{TemplateBinding BorderThickness}" 
                                CornerRadius="6"
                                Padding="{TemplateBinding Padding}">
                            <Border.Effect>
                                <DropShadowEffect BlurRadius="8" ShadowDepth="1" Opacity="0.15" Color="#000000"/>
                            </Border.Effect>
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter Property="Background" Value="{StaticResource Surface4}"/>
                                <Setter Property="BorderBrush" Value="{StaticResource AccentMuted}"/>
                            </Trigger>
                            <Trigger Property="IsPressed" Value="True">
                                <Setter Property="Background" Value="{StaticResource AccentColor}"/>
                                <Setter Property="Foreground" Value="#0f0f10"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style x:Key="PrimaryButton" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}">
            <Setter Property="Background" Value="{StaticResource AccentMuted}"/>
            <Setter Property="Foreground" Value="#ffffff"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="BorderBrush" Value="{StaticResource AccentMuted}"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="border" Background="{TemplateBinding Background}" 
                                BorderBrush="{TemplateBinding BorderBrush}" 
                                BorderThickness="1" 
                                CornerRadius="6"
                                Padding="{TemplateBinding Padding}">
                            <Border.Effect>
                                <DropShadowEffect BlurRadius="12" ShadowDepth="2" Opacity="0.3" Color="#14b8a6"/>
                            </Border.Effect>
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter Property="Background" Value="{StaticResource AccentHover}"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- ============================================ -->
        <!-- TAB ITEM STYLE                              -->
        <!-- ============================================ -->

        <Style TargetType="TabItem">
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="TabItem">
                        <Border Name="Border" BorderThickness="0,0,0,3" BorderBrush="Transparent" Padding="18,12" Background="Transparent" Cursor="Hand">
                            <ContentPresenter ContentSource="Header" TextElement.FontSize="13" TextElement.FontWeight="SemiBold"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsSelected" Value="True">
                                <Setter TargetName="Border" Property="BorderBrush" Value="{StaticResource AccentColor}"/>
                                <Setter TargetName="Border" Property="Background" Value="#1514b8a6"/>
                                <Setter Property="Foreground" Value="{StaticResource AccentColor}"/>
                            </Trigger>
                            <Trigger Property="IsSelected" Value="False">
                                <Setter Property="Foreground" Value="{StaticResource SecondaryText}"/>
                            </Trigger>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter Property="Foreground" Value="{StaticResource PrimaryText}"/>
                                <Setter TargetName="Border" Property="Background" Value="#1014b8a6"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- ============================================ -->
        <!-- CHECKBOX STYLE                              -->
        <!-- ============================================ -->

        <Style TargetType="CheckBox">
            <Setter Property="Foreground" Value="{StaticResource PrimaryText}"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="Margin" Value="0,5"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="CheckBox">
                        <StackPanel Orientation="Horizontal">
                            <Border x:Name="border" Width="18" Height="18" CornerRadius="4" Background="{StaticResource Surface3}" BorderBrush="{StaticResource BorderColor}" BorderThickness="1">
                                <Path x:Name="checkMark" Data="M 3 8 L 7 12 L 15 4" Stroke="{StaticResource AccentColor}" StrokeThickness="2" Visibility="Collapsed" HorizontalAlignment="Center" VerticalAlignment="Center"/>
                            </Border>
                            <ContentPresenter Margin="10,0,0,0" VerticalAlignment="Center"/>
                        </StackPanel>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsChecked" Value="True">
                                <Setter TargetName="checkMark" Property="Visibility" Value="Visible"/>
                                <Setter TargetName="border" Property="Background" Value="{StaticResource AccentMuted}"/>
                                <Setter TargetName="border" Property="BorderBrush" Value="{StaticResource AccentColor}"/>
                            </Trigger>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="border" Property="BorderBrush" Value="{StaticResource AccentColor}"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- Toggle Switch Style -->
        <Style x:Key="ToggleSwitch" TargetType="CheckBox">
            <Setter Property="Foreground" Value="{StaticResource PrimaryText}"/>
            <Setter Property="FontSize" Value="14"/>
            <Setter Property="Margin" Value="0,6"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="CheckBox">
                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="Auto"/>
                                <ColumnDefinition Width="*"/>
                            </Grid.ColumnDefinitions>
                            <!-- Toggle Track -->
                            <Border x:Name="track" Grid.Column="0" Width="44" Height="24" CornerRadius="12" Background="#3f3f46" BorderThickness="0">
                                <!-- Toggle Thumb -->
                                <Border x:Name="thumb" Width="18" Height="18" CornerRadius="9" Background="#a1a1aa" HorizontalAlignment="Left" Margin="3,0,0,0"/>
                            </Border>
                            <!-- Label -->
                            <ContentPresenter Grid.Column="1" Margin="12,0,0,0" VerticalAlignment="Center"/>
                        </Grid>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsChecked" Value="True">
                                <Setter TargetName="track" Property="Background" Value="{StaticResource AccentColor}"/>
                                <Setter TargetName="thumb" Property="Background" Value="#ffffff"/>
                                <Setter TargetName="thumb" Property="HorizontalAlignment" Value="Right"/>
                                <Setter TargetName="thumb" Property="Margin" Value="0,0,3,0"/>
                            </Trigger>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="thumb" Property="Background" Value="#ffffff"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- ============================================ -->
        <!-- COMBOBOX STYLE                              -->
        <!-- ============================================ -->

        <Style TargetType="ComboBox">
            <Setter Property="Foreground" Value="{StaticResource PrimaryText}"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="Padding" Value="8"/>
            <Setter Property="Margin" Value="0,4"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="ComboBox">
                        <Grid>
                            <ToggleButton Name="ToggleButton" Grid.Column="2" Focusable="false" IsChecked="{Binding Path=IsDropDownOpen,Mode=TwoWay,RelativeSource={RelativeSource TemplatedParent}}" ClickMode="Press">
                                <ToggleButton.Template>
                                    <ControlTemplate>
                                        <Border x:Name="Border" Grid.ColumnSpan="2" CornerRadius="6" Background="{StaticResource Surface3}" BorderBrush="{StaticResource BorderColor}" BorderThickness="1">
                                            <Border.Effect>
                                                <DropShadowEffect BlurRadius="6" ShadowDepth="1" Opacity="0.1" Color="#000000"/>
                                            </Border.Effect>
                                        </Border>
                                    </ControlTemplate>
                                </ToggleButton.Template>
                            </ToggleButton>
                            <ContentPresenter Name="ContentSite" IsHitTestVisible="False" Content="{TemplateBinding SelectionBoxItem}" ContentTemplate="{TemplateBinding SelectionBoxItemTemplate}" ContentTemplateSelector="{TemplateBinding ItemTemplateSelector}" Margin="12,3,28,3" VerticalAlignment="Center" HorizontalAlignment="Left" />
                            <Path x:Name="Arrow" Grid.Column="1" Fill="{StaticResource AccentColor}" HorizontalAlignment="Right" VerticalAlignment="Center" Data="M 0 0 L 4 4 L 8 0 Z" Margin="0,0,12,0" IsHitTestVisible="False"/>
                            <Popup Name="Popup" Placement="Bottom" IsOpen="{TemplateBinding IsDropDownOpen}" AllowsTransparency="True" Focusable="False" PopupAnimation="Slide">
                                <Grid Name="DropDown" SnapsToDevicePixels="True" MinWidth="{TemplateBinding ActualWidth}" MaxHeight="{TemplateBinding MaxDropDownHeight}">
                                    <Border x:Name="DropDownBorder" Background="{StaticResource Surface2}" BorderThickness="1" BorderBrush="{StaticResource BorderColor}" CornerRadius="6">
                                        <Border.Effect>
                                            <DropShadowEffect BlurRadius="15" ShadowDepth="3" Opacity="0.3" Color="#000000"/>
                                        </Border.Effect>
                                    </Border>
                                    <ScrollViewer Margin="4,8,4,8" SnapsToDevicePixels="True">
                                        <StackPanel IsItemsHost="True" KeyboardNavigation.DirectionalNavigation="Contained" />
                                    </ScrollViewer>
                                </Grid>
                            </Popup>
                        </Grid>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- ============================================ -->
        <!-- SCROLLBAR STYLE                             -->
        <!-- ============================================ -->

        <Style TargetType="ScrollBar">
            <Setter Property="Background" Value="Transparent"/>
            <Setter Property="Foreground" Value="{StaticResource BorderColor}"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="ScrollBar">
                        <Grid x:Name="GridRoot" Width="8" Background="{TemplateBinding Background}">
                            <Track x:Name="PART_Track" IsDirectionReversed="true" Focusable="false">
                                <Track.Thumb>
                                    <Thumb>
                                        <Thumb.Template>
                                            <ControlTemplate TargetType="Thumb">
                                                <Border Background="{StaticResource Surface4}" CornerRadius="4"/>
                                            </ControlTemplate>
                                        </Thumb.Template>
                                    </Thumb>
                                </Track.Thumb>
                            </Track>
                        </Grid>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- ============================================ -->
        <!-- EXPANDER STYLE                              -->
        <!-- ============================================ -->

        <Style TargetType="Expander">
            <Setter Property="Foreground" Value="{StaticResource PrimaryText}"/>
            <Setter Property="Background" Value="Transparent"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Expander">
                        <Border Background="{StaticResource Surface2}" CornerRadius="8" Margin="0,0,0,8" Padding="4">
                            <Border.Effect>
                                <DropShadowEffect BlurRadius="8" ShadowDepth="1" Opacity="0.15" Color="#000000"/>
                            </Border.Effect>
                            <Grid>
                                <Grid.RowDefinitions>
                                    <RowDefinition Height="Auto"/>
                                    <RowDefinition Height="*"/>
                                </Grid.RowDefinitions>

                                <ToggleButton IsChecked="{Binding IsExpanded, Mode=TwoWay, RelativeSource={RelativeSource TemplatedParent}}" 
                                              OverridesDefaultStyle="True" 
                                              Padding="12,10"
                                              Cursor="Hand"
                                              Background="Transparent">
                                    <ToggleButton.Template>
                                        <ControlTemplate TargetType="ToggleButton">
                                            <Border x:Name="toggleBorder" Background="{TemplateBinding Background}" Padding="{TemplateBinding Padding}" CornerRadius="6">
                                                <Grid>
                                                    <Grid.ColumnDefinitions>
                                                        <ColumnDefinition Width="Auto"/>
                                                        <ColumnDefinition Width="*"/>
                                                    </Grid.ColumnDefinitions>
                                                    <Border Width="24" Height="24" CornerRadius="6" Background="{StaticResource Surface3}" BorderBrush="{StaticResource BorderSubtle}" BorderThickness="1">
                                                        <Path x:Name="arrow" Data="M 4,6 L 8,10 L 12,6" Stroke="{StaticResource AccentColor}" StrokeThickness="2" HorizontalAlignment="Center" VerticalAlignment="Center" RenderTransformOrigin="0.5,0.5">
                                                            <Path.RenderTransform>
                                                                <RotateTransform Angle="-90"/>
                                                            </Path.RenderTransform>
                                                        </Path>
                                                    </Border>
                                                    <ContentPresenter Grid.Column="1" Margin="12,0,0,0" Content="{Binding Header, RelativeSource={RelativeSource AncestorType=Expander}}" VerticalAlignment="Center" TextElement.FontWeight="SemiBold" TextElement.FontSize="14"/>
                                                </Grid>
                                            </Border>
                                            <ControlTemplate.Triggers>
                                                <Trigger Property="IsChecked" Value="True">
                                                    <Setter TargetName="arrow" Property="RenderTransform">
                                                        <Setter.Value>
                                                            <RotateTransform Angle="0"/>
                                                        </Setter.Value>
                                                    </Setter>
                                                </Trigger>
                                                <Trigger Property="IsMouseOver" Value="True">
                                                    <Setter TargetName="toggleBorder" Property="Background" Value="Transparent"/>
                                                </Trigger>
                                            </ControlTemplate.Triggers>
                                        </ControlTemplate>
                                    </ToggleButton.Template>
                                </ToggleButton>
                                <ContentPresenter Grid.Row="1" x:Name="ExpandSite" Visibility="Collapsed" Margin="12,0,12,12" HorizontalAlignment="{TemplateBinding HorizontalContentAlignment}" VerticalAlignment="{TemplateBinding VerticalContentAlignment}"/>
                            </Grid>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsExpanded" Value="True">
                                <Setter TargetName="ExpandSite" Property="Visibility" Value="Visible"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

    </Window.Resources>

    <Grid>
        <Grid.RowDefinitions>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <!-- Main Content -->
        <TabControl Grid.Row="0" Background="Transparent" BorderThickness="0" Padding="0">
            
            <!-- DASHBOARD -->
            <TabItem>
                <TabItem.Header>
                    <StackPanel Orientation="Horizontal">
                        <TextBlock Text="&#xE80F;" FontFamily="Segoe MDL2 Assets" FontSize="14" VerticalAlignment="Center" Margin="0,0,8,0"/>
                        <TextBlock Text="Dashboard" VerticalAlignment="Center"/>
                    </StackPanel>
                </TabItem.Header>
                <ScrollViewer VerticalScrollBarVisibility="Auto">
                <Grid Margin="20" VerticalAlignment="Top">
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="Auto"/>
                    </Grid.RowDefinitions>
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="*"/>
                    </Grid.ColumnDefinitions>

                    <!-- Hero Banner -->
                    <Border Grid.Row="0" Grid.ColumnSpan="3" CornerRadius="14" Margin="0,0,0,24" Height="120" HorizontalAlignment="Stretch">
                        <Border.Effect>
                            <DropShadowEffect BlurRadius="30" ShadowDepth="6" Opacity="0.5" Color="#0d9488"/>
                        </Border.Effect>
                        <Border.Background>
                            <LinearGradientBrush StartPoint="0,0" EndPoint="1,1">
                                <GradientStop Color="#0f766e" Offset="0"/>
                                <GradientStop Color="#1e40af" Offset="0.5"/>
                                <GradientStop Color="#7c3aed" Offset="1"/>
                            </LinearGradientBrush>
                        </Border.Background>
                        <Grid ClipToBounds="True">
                            
                            <!-- Windows Logo watermark -->
                            <Path Data="F1 M0,0 L9,0 L9,9 L0,9 Z M10,0 L19,0 L19,9 L10,9 Z M0,10 L9,10 L9,19 L0,19 Z M10,10 L19,10 L19,19 L10,19 Z" 
                                  Fill="White" Opacity="0.12" Stretch="Uniform" 
                                  HorizontalAlignment="Right" VerticalAlignment="Bottom" 
                                  Margin="0,0,-15,-15" Height="110" Width="110"/>

                            <Grid Margin="30,0,30,0">
                                <StackPanel VerticalAlignment="Center" HorizontalAlignment="Left">
                                    <TextBlock Text="MakeWindowsGreatAgain" FontSize="28" Foreground="#ffffff" FontWeight="Bold" FontFamily="Segoe UI Variable Display, Segoe UI">
                                        <TextBlock.Effect>
                                            <DropShadowEffect BlurRadius="8" ShadowDepth="2" Opacity="0.4"/>
                                        </TextBlock.Effect>
                                    </TextBlock>
                                    <TextBlock Text="Fixing Windows, since Microsoft won't." 
                                               FontSize="14" Foreground="#f0fdfa" Margin="2,6,0,0" Opacity="0.85"/>
                                </StackPanel>
                                
                                <!-- Version Badge -->
                                <Border HorizontalAlignment="Right" VerticalAlignment="Top" Margin="0,10,0,0"
                                        Background="Transparent" BorderBrush="#50ffffff" BorderThickness="1" CornerRadius="12" Padding="12,5">
                                    <TextBlock Text="v1.1" Foreground="#80ffffff" FontSize="12" FontWeight="SemiBold"/>
                                </Border>
                            </Grid>
                        </Grid>
                    </Border>
                    
                    <!-- System Information Title -->
                    <StackPanel Grid.Row="1" Grid.ColumnSpan="5" Orientation="Horizontal" Margin="0,0,0,12">
                        <TextBlock Text="&#xE7F4;" FontFamily="Segoe MDL2 Assets" FontSize="14" 
                                   Foreground="{StaticResource AccentColor}" VerticalAlignment="Center" Margin="0,0,10,0"/>
                        <TextBlock Text="SYSTEM INFORMATION" FontSize="12" FontWeight="SemiBold" 
                                   Foreground="{StaticResource SecondaryText}" VerticalAlignment="Center"/>
                    </StackPanel>
                    
                    <!-- CPU -->
                    <Border Grid.Row="2" Grid.Column="0" Background="{StaticResource Surface2}" CornerRadius="12" Padding="16" Margin="0,0,10,0">
                        <Border.Effect>
                            <DropShadowEffect BlurRadius="10" ShadowDepth="2" Opacity="0.15" Color="#000000"/>
                        </Border.Effect>
                        <StackPanel VerticalAlignment="Top">
                            <Border Width="32" Height="32" CornerRadius="8" Background="{StaticResource Surface3}" HorizontalAlignment="Left" Margin="0,0,0,12">
                                <TextBlock Text="&#xE950;" FontFamily="Segoe MDL2 Assets" FontSize="14" 
                                           Foreground="{StaticResource AccentColor}" HorizontalAlignment="Center" VerticalAlignment="Center"/>
                            </Border>
                            <TextBlock Text="CPU" Foreground="{StaticResource AccentColor}" FontWeight="SemiBold" FontSize="12" Margin="4,0,0,6"/>
                            <TextBlock x:Name="CpuName" Text="Detecting..." TextWrapping="Wrap" Foreground="{StaticResource PrimaryText}" FontSize="13" Margin="4,0,0,0"/>
                        </StackPanel>
                    </Border>
                    
                    <!-- GPU -->
                    <Border Grid.Row="2" Grid.Column="1" Background="{StaticResource Surface2}" CornerRadius="12" Padding="16" Margin="0,0,10,0">
                        <Border.Effect>
                            <DropShadowEffect BlurRadius="10" ShadowDepth="2" Opacity="0.15" Color="#000000"/>
                        </Border.Effect>
                        <StackPanel VerticalAlignment="Top">
                            <Border Width="32" Height="32" CornerRadius="8" Background="{StaticResource Surface3}" HorizontalAlignment="Left" Margin="0,0,0,12">
                                <TextBlock Text="&#xE7F4;" FontFamily="Segoe MDL2 Assets" FontSize="14" 
                                           Foreground="{StaticResource AccentColor}" HorizontalAlignment="Center" VerticalAlignment="Center"/>
                            </Border>
                            <TextBlock Text="GPU" Foreground="{StaticResource AccentColor}" FontWeight="SemiBold" FontSize="12" Margin="4,0,0,6"/>
                            <TextBlock x:Name="GpuName" Text="Detecting..." TextWrapping="Wrap" Foreground="{StaticResource PrimaryText}" FontSize="13" Margin="4,0,0,0"/>
                        </StackPanel>
                    </Border>

                    <!-- RAM -->
                    <Border Grid.Row="2" Grid.Column="2" Background="{StaticResource Surface2}" CornerRadius="12" Padding="16" Margin="0,0,10,0">
                        <Border.Effect>
                            <DropShadowEffect BlurRadius="10" ShadowDepth="2" Opacity="0.15" Color="#000000"/>
                        </Border.Effect>
                        <StackPanel VerticalAlignment="Top">
                            <Border Width="32" Height="32" CornerRadius="8" Background="{StaticResource Surface3}" HorizontalAlignment="Left" Margin="0,0,0,12">
                                <TextBlock Text="&#xE964;" FontFamily="Segoe MDL2 Assets" FontSize="14" 
                                           Foreground="{StaticResource AccentColor}" HorizontalAlignment="Center" VerticalAlignment="Center"/>
                            </Border>
                            <TextBlock Text="RAM" Foreground="{StaticResource AccentColor}" FontWeight="SemiBold" FontSize="12" Margin="4,0,0,6"/>
                            <TextBlock x:Name="RamInfo" Text="Detecting..." TextWrapping="Wrap" Foreground="{StaticResource PrimaryText}" FontSize="13" Margin="4,0,0,0"/>
                        </StackPanel>
                    </Border>
                    
                    <!-- Disk -->
                    <Border Grid.Row="2" Grid.Column="3" Background="{StaticResource Surface2}" CornerRadius="12" Padding="16" Margin="0,0,10,0">
                        <Border.Effect>
                            <DropShadowEffect BlurRadius="10" ShadowDepth="2" Opacity="0.15" Color="#000000"/>
                        </Border.Effect>
                        <StackPanel VerticalAlignment="Top">
                            <Border Width="32" Height="32" CornerRadius="8" Background="{StaticResource Surface3}" HorizontalAlignment="Left" Margin="0,0,0,12">
                                <TextBlock Text="&#xEDA2;" FontFamily="Segoe MDL2 Assets" FontSize="14" 
                                           Foreground="{StaticResource AccentColor}" HorizontalAlignment="Center" VerticalAlignment="Center"/>
                            </Border>
                            <TextBlock Text="Disk" Foreground="{StaticResource AccentColor}" FontWeight="SemiBold" FontSize="12" Margin="4,0,0,6"/>
                            <TextBlock x:Name="DiskInfo" Text="Detecting..." TextWrapping="Wrap" Foreground="{StaticResource PrimaryText}" FontSize="13" Margin="4,0,0,0"/>
                        </StackPanel>
                    </Border>
                    
                    <!-- System -->
                    <Border Grid.Row="2" Grid.Column="4" Background="{StaticResource Surface2}" CornerRadius="12" Padding="16">
                        <Border.Effect>
                            <DropShadowEffect BlurRadius="10" ShadowDepth="2" Opacity="0.15" Color="#000000"/>
                        </Border.Effect>
                        <StackPanel VerticalAlignment="Top">
                            <Border Width="32" Height="32" CornerRadius="8" Background="{StaticResource Surface3}" HorizontalAlignment="Left" Margin="0,0,0,12">
                                <TextBlock Text="&#xE7F7;" FontFamily="Segoe MDL2 Assets" FontSize="14" 
                                           Foreground="{StaticResource AccentColor}" HorizontalAlignment="Center" VerticalAlignment="Center"/>
                            </Border>
                            <TextBlock Text="System" Foreground="{StaticResource AccentColor}" FontWeight="SemiBold" FontSize="12" Margin="4,0,0,6"/>
                            <TextBlock x:Name="SysInfo" Text="Detecting..." TextWrapping="Wrap" Foreground="{StaticResource PrimaryText}" FontSize="13" Margin="4,0,0,0"/>
                        </StackPanel>
                    </Border>
                    
                    <!-- Separator -->
                    <Border Grid.Row="3" Grid.ColumnSpan="5" Height="1" 
                            Background="{StaticResource BorderColor}" 
                            Margin="0,20,0,20"/>
                    
                    <!-- Quick Access Title -->
                    <StackPanel Grid.Row="4" Grid.ColumnSpan="5" Orientation="Horizontal" Margin="0,0,0,12">
                        <TextBlock Text="&#xE728;" FontFamily="Segoe MDL2 Assets" FontSize="14" 
                                   Foreground="{StaticResource AccentColor}" VerticalAlignment="Center" Margin="0,0,10,0"/>
                        <TextBlock Text="QUICK ACCESS" FontSize="12" FontWeight="SemiBold" 
                                   Foreground="{StaticResource SecondaryText}" VerticalAlignment="Center"/>
                    </StackPanel>
                    
                    <!-- Section Descriptions Grid -->
                    <Grid Grid.Row="5" Grid.ColumnSpan="5" x:Name="DashboardDescriptions">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="*"/>
                        </Grid.ColumnDefinitions>
                        <!-- Description cards will be added here dynamically -->
                    </Grid>
                </Grid>
                </ScrollViewer>
            </TabItem>


            <!-- INSTALL APPS -->
            <TabItem>
                <TabItem.Header>
                    <StackPanel Orientation="Horizontal">
                        <TextBlock Text="&#xE8F1;" FontFamily="Segoe MDL2 Assets" FontSize="14" VerticalAlignment="Center" Margin="0,0,8,0"/>
                        <TextBlock Text="Install Apps" VerticalAlignment="Center"/>
                    </StackPanel>
                </TabItem.Header>
                <Grid Margin="20">
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                        <RowDefinition Height="Auto"/>
                    </Grid.RowDefinitions>

                    <TextBox x:Name="TxtInstallSearch" Margin="0,0,0,10" Padding="8" Background="{StaticResource PanelBackground}" Foreground="White" BorderBrush="{StaticResource BorderColor}">
                        <TextBox.Style>
                            <Style TargetType="TextBox">
                                <Setter Property="Template">
                                    <Setter.Value>
                                        <ControlTemplate TargetType="TextBox">
                                            <Border Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="1" CornerRadius="5" Padding="{TemplateBinding Padding}">
                                                <Grid>
                                                    <TextBlock x:Name="Placeholder" Text="Search apps..." Foreground="#666" VerticalAlignment="Center" Visibility="Collapsed"/>
                                                    <ScrollViewer x:Name="PART_ContentHost" VerticalAlignment="Center"/>
                                                </Grid>
                                            </Border>
                                            <ControlTemplate.Triggers>
                                                <MultiTrigger>
                                                    <MultiTrigger.Conditions>
                                                        <Condition Property="Text" Value=""/>
                                                        <Condition Property="IsFocused" Value="False"/>
                                                    </MultiTrigger.Conditions>
                                                    <Setter TargetName="Placeholder" Property="Visibility" Value="Visible"/>
                                                </MultiTrigger>
                                            </ControlTemplate.Triggers>
                                        </ControlTemplate>
                                    </Setter.Value>
                                </Setter>
                            </Style>
                        </TextBox.Style>
                    </TextBox>

                    <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto">
                        <StackPanel x:Name="AppsPanel" Margin="0,0,10,0">
                            <!-- Populated Dynamically with Expanders -->
                        </StackPanel>
                    </ScrollViewer>

                    <StackPanel Grid.Row="2" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,15,0,0">
                        <Button x:Name="BtnInstall" Content="Install Selected" Style="{StaticResource PrimaryButton}" Padding="25,10"/>
                    </StackPanel>
                </Grid>
            </TabItem>

            <!-- TWEAKS -->
            <TabItem>
                <TabItem.Header>
                    <StackPanel Orientation="Horizontal">
                        <TextBlock Text="&#xE713;" FontFamily="Segoe MDL2 Assets" FontSize="14" VerticalAlignment="Center" Margin="0,0,8,0"/>
                        <TextBlock Text="Tweaks" VerticalAlignment="Center"/>
                    </StackPanel>
                </TabItem.Header>
                <Grid Margin="20">
                    <Grid.RowDefinitions>
                        <RowDefinition Height="*"/>
                        <RowDefinition Height="Auto"/>
                    </Grid.RowDefinitions>
                    
                    <ScrollViewer VerticalScrollBarVisibility="Auto">
                    <Grid>
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="*"/>
                        </Grid.ColumnDefinitions>
                        <StackPanel x:Name="TweaksLeftPanel" Grid.Column="0" Margin="0,0,10,0"/>
                        <StackPanel x:Name="TweaksRightPanel" Grid.Column="1" Margin="10,0,0,0"/>
                    </Grid>
                    </ScrollViewer>

                    <StackPanel Grid.Row="1" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,15,0,0">
                        <CheckBox x:Name="ChkDryRunTweaks" Content="Preview only (don't apply)" VerticalAlignment="Center" Margin="0,0,20,0" Foreground="{StaticResource SecondaryText}" FontStyle="Italic"/>
                        <CheckBox x:Name="ChkCreateRestore" Content="Create Restore Point" IsChecked="True" VerticalAlignment="Center" Margin="0,0,20,0"/>
                        <Button x:Name="BtnApplyTweaks" Content="Apply Tweaks" Style="{StaticResource PrimaryButton}" Padding="25,10"/>
                    </StackPanel>
                </Grid>
            </TabItem>

            <!-- PRIVACY & TELEMETRY -->
            <TabItem>
                <TabItem.Header>
                    <StackPanel Orientation="Horizontal">
                        <TextBlock Text="&#xE72E;" FontFamily="Segoe MDL2 Assets" FontSize="14" VerticalAlignment="Center" Margin="0,0,8,0"/>
                        <TextBlock Text="Privacy" VerticalAlignment="Center"/>
                    </StackPanel>
                </TabItem.Header>
                <Grid Margin="20">
                    <Grid.RowDefinitions>
                        <RowDefinition Height="*"/>
                        <RowDefinition Height="Auto"/>
                    </Grid.RowDefinitions>

                    <ScrollViewer VerticalScrollBarVisibility="Auto">
                        <StackPanel x:Name="PrivacyPanel" Margin="0,0,10,0"/>
                    </ScrollViewer>

                    <StackPanel Grid.Row="1" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,15,0,0">
                        <CheckBox x:Name="ChkDryRunPrivacy" Content="Preview only (don't apply)" VerticalAlignment="Center" Margin="0,0,20,0" Foreground="{StaticResource SecondaryText}" FontStyle="Italic"/>
                        <Button x:Name="BtnApplyPrivacy" Content="Apply Privacy Settings" Style="{StaticResource PrimaryButton}" Padding="25,10"/>
                    </StackPanel>
                </Grid>
            </TabItem>

            <!-- DEBLOAT -->
            <TabItem>
                <TabItem.Header>
                    <StackPanel Orientation="Horizontal">
                        <TextBlock Text="&#xE74D;" FontFamily="Segoe MDL2 Assets" FontSize="14" VerticalAlignment="Center" Margin="0,0,8,0"/>
                        <TextBlock Text="Debloat" VerticalAlignment="Center"/>
                    </StackPanel>
                </TabItem.Header>
                <Grid Margin="20">
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                        <RowDefinition Height="Auto"/>
                    </Grid.RowDefinitions>

                    <TextBlock Grid.Row="0" Text="Installed Applications" FontSize="18" FontWeight="Bold" Foreground="{StaticResource AccentColor}" Margin="0,0,0,15"/>

                    <ListBox x:Name="DebloatList" Grid.Row="1" Background="Transparent" BorderThickness="0" ScrollViewer.HorizontalScrollBarVisibility="Disabled">
                        <ListBox.ItemContainerStyle>
                            <Style TargetType="ListBoxItem">
                                <Setter Property="Template">
                                    <Setter.Value>
                                        <ControlTemplate TargetType="ListBoxItem">
                                            <Border Background="Transparent" Margin="0">
                                                <ContentPresenter/>
                                            </Border>
                                        </ControlTemplate>
                                    </Setter.Value>
                                </Setter>
                            </Style>
                        </ListBox.ItemContainerStyle>
                         <ListBox.ItemTemplate>
                            <DataTemplate>
                                <CheckBox Content="{Binding DisplayName}" IsChecked="{Binding IsSelected}" Foreground="White" Tag="{Binding PackageName}"/>
                            </DataTemplate>
                        </ListBox.ItemTemplate>
                    </ListBox>

                    <Grid Grid.Row="2" Margin="0,15,0,0">
                        <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
                            <Button x:Name="BtnDebloat" Content="Remove Selected" Style="{StaticResource PrimaryButton}" Padding="25,10"/>
                        </StackPanel>
                    </Grid>
                </Grid>
            </TabItem>
            
            <!-- NETWORK -->
             <TabItem>
                <TabItem.Header>
                    <StackPanel Orientation="Horizontal">
                        <TextBlock Text="&#xE774;" FontFamily="Segoe MDL2 Assets" FontSize="14" VerticalAlignment="Center" Margin="0,0,8,0"/>
                        <TextBlock Text="Network" VerticalAlignment="Center"/>
                    </StackPanel>
                </TabItem.Header>
                <Grid Margin="20">
                    <ScrollViewer>
                        <StackPanel>
                             <!-- DNS -->
                            <Border Background="{StaticResource PanelBackground}" Padding="20" CornerRadius="10" Margin="0,0,0,20">
                                <StackPanel>
                                    <TextBlock Text="DNS Manager" FontSize="16" FontWeight="Bold" Foreground="{StaticResource AccentColor}" Margin="0,0,0,10"/>
                                    <ComboBox x:Name="CmbAdapters" Margin="0,0,0,15" Padding="5"/>
                                    <TextBlock x:Name="TxtCurrentDns" Text="Select an adapter to view current DNS" Foreground="#999" Margin="0,0,0,10" FontSize="12" TextWrapping="Wrap"/>
                                    
                                    <WrapPanel x:Name="DnsProvidersPanel" ItemWidth="200">
                                        <!-- Dynamic Radio Buttons -->
                                    </WrapPanel>
                                    
                                    <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,15,0,0">
                                        <Button x:Name="BtnRevertDns" Content="Revert DNS" Margin="0,0,10,0"/>
                                        <Button x:Name="BtnSetDns" Content="Set DNS" Style="{StaticResource PrimaryButton}"/>
                                    </StackPanel>
                                </StackPanel>
                            </Border>

                            <!-- Repair Tools -->
                            <Border Background="{StaticResource PanelBackground}" Padding="20" CornerRadius="10" Margin="0,0,0,20">
                                <StackPanel>
                                    <TextBlock Text="Network Repair Tools" FontSize="16" FontWeight="Bold" Foreground="{StaticResource AccentColor}" Margin="0,0,0,10"/>
                                    <TextBlock Text="Safe tools to fix common networking issues." Foreground="{StaticResource SecondaryText}" FontSize="12" Margin="0,0,0,15" TextWrapping="Wrap"/>
                                    
                                    <StackPanel x:Name="NetworkRepairPanel">
                                        <!-- Dynamic Checkboxes -->
                                    </StackPanel>

                                    <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,15,0,0">
                                        <Button x:Name="BtnRunRepair" Content="Run Selected" Style="{StaticResource PrimaryButton}"/>
                                    </StackPanel>
                                </StackPanel>
                            </Border>

                            <!-- Advanced Tweaks -->
                            <StackPanel x:Name="NetworkAdvancedPanel">
                                <!-- Dynamic Expanders/Groups -->
                            </StackPanel>
                        </StackPanel>
                    </ScrollViewer>
                </Grid>
             </TabItem>

        </TabControl>
        <!-- Enhanced Status Bar -->
        <Border Grid.Row="1" Background="{StaticResource Surface2}" Padding="16,10" BorderBrush="{StaticResource BorderSubtle}" BorderThickness="0,1,0,0">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                
                <!-- Status Indicator + Text -->
                <StackPanel Grid.Column="0" Orientation="Horizontal" VerticalAlignment="Center">
                    <Ellipse x:Name="StatusIndicator" Width="8" Height="8" Fill="{StaticResource SuccessColor}" Margin="0,0,10,0"/>
                    <TextBlock x:Name="StatusText" Text="Ready" Foreground="{StaticResource SecondaryText}" FontSize="12" VerticalAlignment="Center"/>
                </StackPanel>
                
                <!-- Progress Bar (hidden by default) -->
                <ProgressBar x:Name="ProgressBar" Grid.Column="1" Height="3" Margin="24,0" 
                             Style="{StaticResource StatusProgressBar}"
                             Visibility="Collapsed" Value="0" Maximum="100"/>
                
                <!-- View Log Button -->
                <Button x:Name="BtnViewLog" Grid.Column="2" Margin="0,0,12,0" Padding="8,4" 
                        Background="Transparent" BorderThickness="0" Cursor="Hand" ToolTip="Open log file">
                    <StackPanel Orientation="Horizontal">
                        <TextBlock Text="&#xE7C3;" FontFamily="Segoe MDL2 Assets" FontSize="12" 
                                   Foreground="{StaticResource SecondaryText}" VerticalAlignment="Center" Margin="0,0,5,0"/>
                        <TextBlock Text="View Log" Foreground="{StaticResource SecondaryText}" FontSize="11" VerticalAlignment="Center"/>
                    </StackPanel>
                </Button>
                
                <!-- Admin Badge -->
                <Border Grid.Column="3" Background="{StaticResource AccentMuted}" CornerRadius="6" Padding="10,4">
                    <StackPanel Orientation="Horizontal">
                        <TextBlock Text="&#xE7EF;" FontFamily="Segoe MDL2 Assets" FontSize="11" 
                                   Foreground="White" VerticalAlignment="Center" Margin="0,0,6,0"/>
                        <TextBlock Text="Admin" Foreground="White" FontSize="11" FontWeight="SemiBold" VerticalAlignment="Center"/>
                    </StackPanel>
                </Border>
            </Grid>
        </Border>
    </Grid>
</Window>
'@

  [xml]$Xaml = $XamlContent
  $Reader = (New-Object System.Xml.XmlNodeReader $Xaml)
  $Window = [Windows.Markup.XamlReader]::Load($Reader)


  # Map UI Elements to Variables
  $BtnInstall = $Window.FindName("BtnInstall")
  $TxtInstallSearch = $Window.FindName("TxtInstallSearch")
  $AppsPanel = $Window.FindName("AppsPanel")
  $TweaksLeftPanel = $Window.FindName("TweaksLeftPanel")
  $TweaksRightPanel = $Window.FindName("TweaksRightPanel")
    
  # Dashboard Variables
  $CpuName = $Window.FindName("CpuName")
  $GpuName = $Window.FindName("GpuName")
  $RamInfo = $Window.FindName("RamInfo")
  $DiskInfo = $Window.FindName("DiskInfo")
  $SysInfo = $Window.FindName("SysInfo")

  $StatusText = $Window.FindName("StatusText")
  $BtnViewLog = $Window.FindName("BtnViewLog")
  
  # View Log button click handler
  $BtnViewLog.Add_Click({
      if (Test-Path $script:LogFile) {
        Start-Process notepad.exe -ArgumentList $script:LogFile
      }
      else {
        Show-Toast -Message "No log file exists yet." -Type "Info"
      }
    })

  # ------------------------------------------------------------------------------
  # 4. DASHBOARD LOGIC (STATIC)
  # ------------------------------------------------------------------------------
  function Update-Dashboard {
    try {
      $StatusText.Text = "Loading System Info..."
            
      # CPU
      $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
      $CpuName.Text = $cpu.Name
            
      # GPU
      $gpu = Get-CimInstance Win32_VideoController | Select-Object -First 1
      $GpuName.Text = $gpu.Name
            
      # RAM
      $cs = Get-CimInstance Win32_ComputerSystem
      $ramGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 0)
      $RamInfo.Text = "$ramGB GB"
            
      # Disk (Primary)
      $disk = Get-CimInstance Win32_DiskDrive | Select-Object -First 1
      $diskSize = [math]::Round($disk.Size / 1GB, 0)
      $DiskInfo.Text = "$diskSize GB $($disk.Model)"
            
      # System
      $os = Get-CimInstance Win32_OperatingSystem
      $SysInfo.Text = $os.Caption
            
      $StatusText.Text = "Ready"
    }
    catch {
      $StatusText.Text = "Error loading info"
    }
  }

  function Populate-DashboardDescriptions {
    # Find the dashboard descriptions grid
    $dashDescriptions = $Window.FindName("DashboardDescriptions")
    if (-not $dashDescriptions) { return }
    
    # Find the TabControl - it's in the main Grid
    $mainGrid = $Window.Content
    $tabControl = $null
    foreach ($child in $mainGrid.Children) {
      if ($child -is [System.Windows.Controls.TabControl]) {
        $tabControl = $child
        break
      }
    }
    if (-not $tabControl) { return }
    
    $sections = @(
      @{Name = "Install Apps"; Desc = "Uses Winget to download and install popular applications"; TabIndex = 1; Column = 0 },
      @{Name = "Tweaks"; Desc = "Apply system optimizations and performance tweaks"; TabIndex = 2; Column = 1 },
      @{Name = "Privacy"; Desc = "Configure privacy settings and disable telemetry"; TabIndex = 3; Column = 2 },
      @{Name = "Debloat"; Desc = "Remove pre-installed bloatware and unnecessary apps"; TabIndex = 4; Column = 3 },
      @{Name = "Network"; Desc = "Configure DNS, repair network issues, and optimize connectivity"; TabIndex = 5; Column = 4 }
    )
    
    foreach ($section in $sections) {
      $card = New-Object System.Windows.Controls.Border
      $card.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(37, 37, 38))
      $card.CornerRadius = "10"
      $card.Padding = "20"
      $card.Cursor = [System.Windows.Input.Cursors]::Hand
      
      # Set margin to match system info cards (0,0,10,0 for all except last)
      if ($section.Column -eq 4) {
        $card.Margin = "0"
      }
      else {
        $card.Margin = "0,0,10,0"
      }
      
      # Set column position
      [System.Windows.Controls.Grid]::SetColumn($card, $section.Column)
      
      $card.Tag = $section.TabIndex
      
      # Add click handler for navigation
      # Use PreviewMouseLeftButtonUp which is more reliable for 'clicks' on composite controls
      $card.Add_PreviewMouseLeftButtonUp({
          param($s, $e)
          $idx = $s.Tag
          $s.Dispatcher.Invoke([Action] {
              $tabControl.SelectedIndex = $idx
            })
        }.GetNewClosure())
      
      # Add hover effect
      $card.Add_MouseEnter({
          param($s, $e)
          $s.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(63, 63, 70))
        })
      $card.Add_MouseLeave({
          param($s, $e)
          $s.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(37, 37, 38))
        })
      
      $stack = New-Object System.Windows.Controls.StackPanel
      
      # Title (matching system info style exactly - using AccentColor)
      $title = New-Object System.Windows.Controls.TextBlock
      $title.Text = $section.Name
      $title.FontWeight = "Bold"
      $title.Foreground = $Window.Resources["AccentColor"]
      $title.Margin = "0,0,0,10"
      
      # Description (matching system info text style exactly)
      $desc = New-Object System.Windows.Controls.TextBlock
      $desc.Text = $section.Desc
      $desc.FontSize = 13
      $desc.Foreground = [System.Windows.Media.Brushes]::White
      $desc.TextWrapping = "Wrap"
      
      $stack.Children.Add($title) | Out-Null
      $stack.Children.Add($desc) | Out-Null
      $card.Child = $stack
      
      $dashDescriptions.Children.Add($card) | Out-Null
    }
  }

  # ------------------------------------------------------------------------------
  # 5. INITIALIZATION FUNCTIONS
  # ------------------------------------------------------------------------------

  function Install-Winget {
    try {
      $StatusText.Text = "Downloading Winget..."
      Write-Log "Downloading Winget..."
      $url = "https://aka.ms/getwinget"
      $output = "$env:TEMP\winget.msixbundle"
      Invoke-WebRequest -Uri $url -OutFile $output
        
      $StatusText.Text = "Installing Winget..."
      Write-Log "Installing Winget..."
      Add-AppxPackage -Path $output
      $StatusText.Text = "Winget installed."
      Write-Log "Winget installed." "SUCCESS"
      return $true
    }
    catch {
      Write-Log "Failed to install Winget: $_" "ERROR"
      Show-Toast -Message "Failed to install Winget: $_" -Type "Error"
      return $false
    }
  }

  function Invoke-ExplorerUpdate {
    param($action)
    Write-Log "Scheduling Explorer restart..."
    $script:RestartExplorer = $true
  }

  function Restart-ExplorerIfNeeded {
    if ($script:RestartExplorer) {
      Write-Log "Restarting Explorer..."
      Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
      Start-Sleep -Seconds 1
      $script:RestartExplorer = $false
    }
  }

  # Global flag to prevent concurrent operations
  $script:ProcessRunning = $false

  # ===== WINGET INSTALLATION FUNCTIONS =====
  
  function Install-WinUtilWinget {
    <#
    .SYNOPSIS
        Installs Winget if not already installed.

    .DESCRIPTION
        Installs winget if needed using the Microsoft.WinGet.Client PowerShell module
    #>
    
    # Check if winget is already available
    if (Get-Command winget -ErrorAction SilentlyContinue) {
      Write-Log "Winget is already installed." "SUCCESS"
      return $true
    }

    Write-Log "Winget is not installed. Installing..." "WARNING"
    
    try {
      # Set PSGallery as trusted
      Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop

      # Install NuGet provider
      Write-Log "Installing NuGet provider..."
      Install-PackageProvider -Name NuGet -Force -ErrorAction Stop | Out-Null

      # Install Microsoft.WinGet.Client module
      Write-Log "Installing Microsoft.WinGet.Client module..."
      Install-Module Microsoft.WinGet.Client -Force -ErrorAction Stop
        
      # Import the module
      Import-Module Microsoft.WinGet.Client -ErrorAction Stop
        
      # Repair/Install WinGet
      Write-Log "Repairing WinGet Package Manager..."
      Repair-WinGetPackageManager -ErrorAction Stop
        
      Write-Log "Winget installed successfully!" "SUCCESS"
      return $true
    }
    catch {
      Write-Log "Failed to install Winget: $_" "ERROR"
      Show-Toast -Message "Failed to install Winget. Please install it manually from the Microsoft Store." -Type "Error"
      return $false
    }
  }

  function Install-WinUtilProgramWinget {
    <#
    .SYNOPSIS
        Runs the designated action on the provided programs using Winget

    .PARAMETER Programs
        A list of programs to process

    .PARAMETER Action
        The action to perform on the programs, can be either 'Install' or 'Uninstall'
    #>

    param(
      [Parameter(Mandatory, Position = 0)]$Programs,

      [Parameter(Mandatory, Position = 1)]
      [ValidateSet("Install", "Uninstall")]
      [String]$Action
    )

    Function Invoke-Winget {
      param ([string]$wingetId)

      $commonArguments = "--id $wingetId --silent"
      $arguments = if ($Action -eq "Install") {
        "install $commonArguments --accept-source-agreements --accept-package-agreements"
      }
      else {
        "uninstall $commonArguments"
      }

      $processParams = @{
        FilePath     = "winget"
        ArgumentList = $arguments
        Wait         = $true
        PassThru     = $true
        NoNewWindow  = $true
      }

      return (Start-Process @processParams).ExitCode
    }

    Function Invoke-Install {
      param ([string]$Program)
        
      $status = Invoke-Winget -wingetId $Program
      if ($status -eq 0) {
        Write-Log "$($Program) installed successfully." "SUCCESS"
        return $true
      }
      elseif ($status -eq -1978335189) {
        Write-Log "$($Program) - No applicable update found (already installed)" "WARNING"
        return $true
      }

      Write-Log "Failed to install $($Program). Exit code: $status" "ERROR"
      return $false
    }

    Function Invoke-Uninstall {
      param ([psobject]$Program)

      try {
        $status = Invoke-Winget -wingetId $Program
        if ($status -eq 0) {
          Write-Log "$($Program) uninstalled successfully." "SUCCESS"
          return $true
        }
        else {
          Write-Log "Failed to uninstall $($Program). Exit code: $status" "ERROR"
          return $false
        }
      }
      catch {
        Write-Log "Failed to uninstall $($Program) due to an error: $_" "ERROR"
        return $false
      }
    }

    $count = $Programs.Count
    $failedPackages = @()

    Write-Log "==========================================="
    Write-Log "Configuring winget packages ($count total)"
    Write-Log "==========================================="

    for ($i = 0; $i -lt $count; $i++) {
      $Program = $Programs[$i]
      $result = $false
        
      Write-Log "[$($i+1)/$count] ${Action}ing: $Program"

      $result = switch ($Action) {
        "Install" { Invoke-Install -Program $Program }
        "Uninstall" { Invoke-Uninstall -Program $Program }
        default { throw "[Install-WinUtilProgramWinget] Invalid action: $Action" }
      }

      if (-not $result) {
        $failedPackages += $Program
      }
    }

    Write-Log "==========================================="
    Write-Log "Installation Complete"
    Write-Log "==========================================="
    
    if ($failedPackages.Count -gt 0) {
      Write-Log "Failed packages: $($failedPackages -join ', ')" "ERROR"
    }

    return $failedPackages
  }

  # ===== END WINGET FUNCTIONS =====

  # ===== TOAST NOTIFICATION FUNCTIONS =====

  $script:ToastTimer = $null
  $script:ToastContainer = $null

  function Initialize-ToastContainer {
    # Create toast container programmatically
    $script:ToastContainer = New-Object System.Windows.Controls.Border
    $script:ToastContainer.VerticalAlignment = "Top"
    $script:ToastContainer.HorizontalAlignment = "Center"
    $script:ToastContainer.Margin = "0,10,0,0"
    $script:ToastContainer.Padding = "15,10"
    $script:ToastContainer.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(45, 45, 48))
    $script:ToastContainer.BorderBrush = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(0, 122, 204))
    $script:ToastContainer.BorderThickness = "1"
    $script:ToastContainer.CornerRadius = "5"
    $script:ToastContainer.Visibility = "Collapsed"
    
    # Add drop shadow
    $shadow = New-Object System.Windows.Media.Effects.DropShadowEffect
    $shadow.Color = [System.Windows.Media.Colors]::Black
    $shadow.BlurRadius = 10
    $shadow.ShadowDepth = 3
    $shadow.Opacity = 0.5
    $script:ToastContainer.Effect = $shadow
    
    # Create stack panel for content
    $stackPanel = New-Object System.Windows.Controls.StackPanel
    $stackPanel.Orientation = "Horizontal"
    
    # Icon
    $script:ToastIcon = New-Object System.Windows.Controls.TextBlock
    $script:ToastIcon.FontSize = 20
    $script:ToastIcon.FontWeight = "Bold"
    $script:ToastIcon.Margin = "0,0,10,0"
    $script:ToastIcon.VerticalAlignment = "Center"
    
    # Message
    $script:ToastMessage = New-Object System.Windows.Controls.TextBlock
    $script:ToastMessage.FontSize = 14
    $script:ToastMessage.Foreground = [System.Windows.Media.Brushes]::White
    $script:ToastMessage.TextWrapping = "Wrap"
    $script:ToastMessage.MaxWidth = 400
    $script:ToastMessage.VerticalAlignment = "Center"
    
    # Close button
    $script:ToastCloseButton = New-Object System.Windows.Controls.Button
    $script:ToastCloseButton.Content = "X"
    $script:ToastCloseButton.FontSize = 16
    $script:ToastCloseButton.FontWeight = "Bold"
    $script:ToastCloseButton.Margin = "15,0,0,0"
    $script:ToastCloseButton.Padding = "5,0"
    $script:ToastCloseButton.Background = [System.Windows.Media.Brushes]::Transparent
    $script:ToastCloseButton.Foreground = [System.Windows.Media.Brushes]::White
    $script:ToastCloseButton.BorderThickness = "0"
    $script:ToastCloseButton.Cursor = [System.Windows.Input.Cursors]::Hand
    $script:ToastCloseButton.VerticalAlignment = "Center"
    
    # Add click handler for close button
    $script:ToastCloseButton.Add_Click({
        Hide-Toast
        if ($script:ToastTimer) {
          $script:ToastTimer.Stop()
          $script:ToastTimer = $null
        }
      })
    
    # Add elements to stack panel
    $stackPanel.Children.Add($script:ToastIcon) | Out-Null
    $stackPanel.Children.Add($script:ToastMessage) | Out-Null
    $stackPanel.Children.Add($script:ToastCloseButton) | Out-Null
    
    $script:ToastContainer.Child = $stackPanel
    
    # Add to window's main grid (assuming it has a Grid as content)
    try {
      $mainGrid = $Window.Content
      if ($mainGrid -is [System.Windows.Controls.Grid]) {
        # Set high ZIndex to appear above everything
        [System.Windows.Controls.Grid]::SetZIndex($script:ToastContainer, 9999)
        $mainGrid.Children.Add($script:ToastContainer) | Out-Null
      }
    }
    catch {
      Write-Log "Could not add toast container to window: $_" "ERROR"
    }
  }

  function Get-InstalledApps {
    $StatusText.Text = "Scanning installed applications..."
    
    # Run in a separate dispatcher operation to allow UI to update first
    $Window.Dispatcher.InvokeAsync([Action] {
        try {
          $Visible = @()
          # Wrap in array to ensure property access works even if 0 or 1 item
          $Installed = @(Get-AppxPackage -ErrorAction SilentlyContinue)
            
          foreach ($item in $script:DebloatItems) {
            # Check if installed list contains this package
            if ($Installed.Name -contains $item.PackageName -or $Installed.PackageFullName -like "*$($item.PackageName)*") {
              $Visible += $item
            }
          }
            
          $DebloatList.ItemsSource = $Visible
          $StatusText.Text = "Scan complete. Found $( $Visible.Count ) apps."
            
          # Reset status to Ready after 3 seconds
          $timer = New-Object System.Windows.Threading.DispatcherTimer
          $timer.Interval = [TimeSpan]::FromSeconds(3)
          $timer.Add_Tick({
              param($s, $e)
              $StatusText.Text = "Ready"
              $s.Stop()
            })
          $timer.Start()
        }
        catch {
          $StatusText.Text = "Error scanning apps."
          Show-Toast -Message "Scan error: $_" -Type "Error"
        }
      }, [System.Windows.Threading.DispatcherPriority]::Background) | Out-Null
  }

  function Show-Toast {
    param(
      [Parameter(Mandatory)]
      [string]$Message,
          
      [Parameter(Mandatory)]
      [ValidateSet("Success", "Info", "Warning", "Error")]
      [string]$Type,
          
      [int]$Duration = 4000  # milliseconds
    )
      
    if (-not $script:ToastContainer) {
      Write-Log "Toast container not initialized" "ERROR"
      return
    }
      
    # Stop any existing timer
    if ($script:ToastTimer) {
      $script:ToastTimer.Stop()
      $script:ToastTimer = $null
    }
      
    # Set message
    $script:ToastMessage.Text = $Message
      
    # Set icon and colors based on type
    switch ($Type) {
      "Success" {
        $script:ToastIcon.Text = "[OK]"
        $script:ToastIcon.Foreground = [System.Windows.Media.Brushes]::LightGreen
        $script:ToastContainer.BorderBrush = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(40, 167, 69))
      }
      "Info" {
        $script:ToastIcon.Text = "[i]"
        $script:ToastIcon.Foreground = [System.Windows.Media.Brushes]::LightBlue
        $script:ToastContainer.BorderBrush = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(23, 162, 184))
      }
      "Warning" {
        $script:ToastIcon.Text = "[!]"
        $script:ToastIcon.Foreground = [System.Windows.Media.Brushes]::Orange
        $script:ToastContainer.BorderBrush = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(255, 193, 7))
      }
      "Error" {
        $script:ToastIcon.Text = "[X]"
        $script:ToastIcon.Foreground = [System.Windows.Media.Brushes]::Red
        $script:ToastContainer.BorderBrush = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(220, 53, 69))
      }
    }
      
    # Show toast
    $script:ToastContainer.Visibility = "Visible"
      
    # Auto-hide after duration
    $script:ToastTimer = New-Object System.Windows.Threading.DispatcherTimer
    $script:ToastTimer.Interval = [TimeSpan]::FromMilliseconds($Duration)
    $script:ToastTimer.Add_Tick({
        Hide-Toast
        $script:ToastTimer.Stop()
        $script:ToastTimer = $null
      })
    $script:ToastTimer.Start()
  }

  function Hide-Toast {
    if ($script:ToastContainer) {
      $script:ToastContainer.Visibility = "Collapsed"
    }
  }

  # ===== END TOAST FUNCTIONS =====

  function Add-TweakGroup {
    param($Title, $Items, $Color, $TargetPanel)
    
    $lbl = New-Object System.Windows.Controls.TextBlock
    $lbl.Text = $Title
    $lbl.FontSize = 16
    $lbl.FontWeight = "Bold"
    $lbl.Foreground = $Color
    $lbl.Margin = "0,10,0,5"
    
    $TargetPanel.Children.Add($lbl) | Out-Null
    
    foreach ($item in $Items) {
      $TargetPanel.Children.Add($item) | Out-Null
    }
  }

  # ------------------------------------------------------------------------------
  # 6. UI POPULATION
  # ------------------------------------------------------------------------------

  # --- Populate Apps ---
  $Categories = @{}
  foreach ($key in $AppsData.PSObject.Properties.Name) {
    if ($key -ne "PSObject") {
      $item = $AppsData.$key
      $cat = $item.category
      if (-not $Categories.ContainsKey($cat)) { $Categories[$cat] = @() }
      $Categories[$cat] += $item
    }
  }
    
  foreach ($catName in ($Categories.Keys | Sort-Object)) {
    $expander = New-Object System.Windows.Controls.Expander
    $expander.Header = $catName
    $expander.IsExpanded = $true
    $expander.Foreground = [System.Windows.Media.Brushes]::White
    $expander.Margin = "0,0,0,10"
        
    $wrapPanel = New-Object System.Windows.Controls.Primitives.UniformGrid
    $wrapPanel.Columns = 4
    $wrapPanel.VerticalAlignment = "Top"
        
    foreach ($app in ($Categories[$catName] | Sort-Object Content)) {
      $border = New-Object System.Windows.Controls.Border
      $border.Background = $Window.Resources["PanelBackground"]
      $border.CornerRadius = "6"
      $border.Padding = "10"
      $border.Margin = "4"
             
      $cb = New-Object System.Windows.Controls.CheckBox
      $cb.Content = $app.Content
      $cb.ToolTip = $app.Description
      $cb.Tag = $app.winget
      $cb.Foreground = [System.Windows.Media.Brushes]::White
             
      $border.Child = $cb
      $wrapPanel.Children.Add($border) | Out-Null
    }
    $expander.Content = $wrapPanel
    $AppsPanel.Children.Add($expander) | Out-Null
  }

  # --- Populate Tweaks ---
  # Variables mapped above
  $Essential = @(); $Advanced = @(); $Customize = @()
  $script:ToggleInitialStates = @{}  # Track initial toggle states

  foreach ($key in $TweaksData.PSObject.Properties.Name) {
    if ($key -eq "PSObject") { continue }
    $t = $TweaksData.$key
   
    # Check if this is a Toggle type using handler property
    $isToggle = $t.PSObject.Properties.Name -contains 'handler' -and $t.handler -eq "toggle"
    if ($isToggle) {
      $toggle = New-Object System.Windows.Controls.CheckBox
      $toggle.Content = $t.Content
      $toggle.ToolTip = $t.Description
      $toggle.Tag = $key
      $toggle.Style = $Window.Resources["ToggleSwitch"]
      
      # Read current registry state to set initial toggle position
      if ($t.registry -and $t.registry.Count -gt 0) {
        $reg = $t.registry[0]
        $regPath = $reg.Path.Replace("HKLM:", "Registry::HKEY_LOCAL_MACHINE").Replace("HKCU:", "Registry::HKEY_CURRENT_USER")
        try {
          $currentValue = Get-ItemProperty -Path $regPath -Name $reg.Name -ErrorAction SilentlyContinue
          if ($currentValue) {
            $toggle.IsChecked = ($currentValue.$($reg.Name).ToString() -eq $reg.Value.ToString())
          }
        }
        catch {
          # If we can't read the registry, default to unchecked
          $toggle.IsChecked = $false
        }
      }
      
      # Store initial state for change tracking
      $script:ToggleInitialStates[$key] = $toggle.IsChecked
      
      if ($t.category -like "*Essential*") { $Essential += $toggle }
      elseif ($t.category -like "*Advanced*") { $Advanced += $toggle }
      else { $Customize += $toggle }
    }
    else {
      # Regular checkbox for non-toggle items
      $cb = New-Object System.Windows.Controls.CheckBox
      $cb.Content = $t.Content
      $cb.ToolTip = $t.Description
      $cb.Tag = $key
      # Style (Foreground, FontSize, Margin) handled by XAML style

      if ($t.category -like "*Essential*") { $Essential += $cb }
      elseif ($t.category -like "*Advanced*") { $Advanced += $cb }
      else { $Customize += $cb }
    }
  }
  
  # Use AccentColor resource for group headers to ensure consistency
  # Store Essential items for Select All functionality
  $script:EssentialItems = $Essential
  
  Add-TweakGroup "Essential Tweaks" $Essential $Window.Resources["AccentColor"] $TweaksLeftPanel
  
  # Add Select All checkbox for Essential Tweaks (insert after header, before items)
  $selectAllEssential = New-Object System.Windows.Controls.CheckBox
  $selectAllEssential.Content = "Select All Essential"
  $selectAllEssential.FontWeight = "SemiBold"
  $selectAllEssential.FontStyle = "Italic"
  $selectAllEssential.Foreground = $Window.Resources["SecondaryText"]
  $selectAllEssential.Margin = "15,0,0,8"
  $selectAllEssential.Add_Click({
      $isChecked = $this.IsChecked
      foreach ($item in $script:EssentialItems) {
        # Only toggle non-toggle checkboxes (regular tweaks)
        $key = $item.Tag
        $tweak = $TweaksData.$key
        $isToggle = $tweak.PSObject.Properties.Name -contains 'handler' -and $tweak.handler -eq 'toggle'
        if (-not $isToggle) {
          $item.IsChecked = $isChecked
        }
      }
    })
  # Insert after header (index 0 is header, so insert at index 1)
  $TweaksLeftPanel.Children.Insert(1, $selectAllEssential)
  
  Add-TweakGroup "Advanced Tweaks" $Advanced $Window.Resources["AccentColor"] $TweaksLeftPanel
  Add-TweakGroup "Customization" $Customize $Window.Resources["AccentColor"] $TweaksRightPanel

  # --- Populate Privacy ---
  $PrivacyPanel = $Window.FindName("PrivacyPanel")
  
  # Add Heading
  $lbl = New-Object System.Windows.Controls.TextBlock
  $lbl.Text = "Privacy and Telemetry"
  $lbl.FontSize = 18
  $lbl.FontWeight = "Bold"
  $lbl.Foreground = $Window.Resources["AccentColor"]
  $lbl.Margin = "0,10,0,15"
  $PrivacyPanel.Children.Add($lbl) | Out-Null
  
  # Add Select All checkbox for Privacy
  $script:PrivacyItems = @()
  $selectAllPrivacy = New-Object System.Windows.Controls.CheckBox
  $selectAllPrivacy.Content = "Select All Privacy"
  $selectAllPrivacy.FontWeight = "SemiBold"
  $selectAllPrivacy.FontStyle = "Italic"
  $selectAllPrivacy.Foreground = $Window.Resources["SecondaryText"]
  $selectAllPrivacy.Margin = "15,0,0,8"
  $selectAllPrivacy.Add_Click({
      $isChecked = $this.IsChecked
      foreach ($item in $script:PrivacyItems) {
        $item.IsChecked = $isChecked
      }
    })
  $PrivacyPanel.Children.Add($selectAllPrivacy) | Out-Null
  
  foreach ($key in $PrivacyData.PSObject.Properties.Name) {
    if ($key -eq "PSObject") { continue }
    $t = $PrivacyData.$key
    
    $cb = New-Object System.Windows.Controls.CheckBox
    $cb.Content = $t.Content
    $cb.ToolTip = $t.Description
    $cb.Tag = $key
    $cb.IsChecked = $false 
    # Style handled by XAML
    
    $script:PrivacyItems += $cb
    $PrivacyPanel.Children.Add($cb) | Out-Null
  }

  # --- Populate Debloat ---
  $DebloatList = $Window.FindName("DebloatList")
  
  function Refresh-DebloatList {
    $list = New-Object System.Collections.Generic.List[PSObject]
    foreach ($key in $DebloatData.PSObject.Properties.Name) {
      if ($key -eq "PSObject") { continue }
      $d = $DebloatData.$key
      $obj = New-Object PSObject
      $obj | Add-Member -MemberType NoteProperty -Name "PackageName" -Value $key
      $obj | Add-Member -MemberType NoteProperty -Name "DisplayName" -Value $d.Name
      $obj | Add-Member -MemberType NoteProperty -Name "Type" -Value $d.Type
      $obj | Add-Member -MemberType NoteProperty -Name "IsSelected" -Value $false
      $list.Add($obj)
    }
    $script:DebloatItems = $list.ToArray()
    
    # Filter and display only installed apps
    Get-InstalledApps
  }

  # Initial population
  Refresh-DebloatList

  # --- Populate DNS ---
  $DnsPanel = $Window.FindName("DnsProvidersPanel")
  $CmbAdapters = $Window.FindName("CmbAdapters")
  
  # Smart adapter selection: only Up adapters, prioritize Ethernet > WiFi
  $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
  foreach ($adapter in $adapters) {
    $CmbAdapters.Items.Add($adapter.Name) | Out-Null
  }
  
  if ($CmbAdapters.Items.Count -gt 0) {
    # Try to select Ethernet first
    $selectedIndex = -1
    for ($i = 0; $i -lt $CmbAdapters.Items.Count; $i++) {
      if ($CmbAdapters.Items[$i] -like "*Ethernet*") {
        $selectedIndex = $i
        break
      }
    }
    # Fallback to Wi-Fi
    if ($selectedIndex -eq -1) {
      for ($i = 0; $i -lt $CmbAdapters.Items.Count; $i++) {
        if ($CmbAdapters.Items[$i] -like "*Wi-Fi*" -or $CmbAdapters.Items[$i] -like "*WiFi*") {
          $selectedIndex = $i
          break
        }
      }
    }
    # Fallback to first available
    if ($selectedIndex -eq -1) { $selectedIndex = 0 }
    $CmbAdapters.SelectedIndex = $selectedIndex
  }

  foreach ($key in $DnsData.PSObject.Properties.Name) {
    if ($key -eq "PSObject") { continue }
    $p = $DnsData.$key
    $rb = New-Object System.Windows.Controls.RadioButton
    $rb.Content = $key
    $rb.Tag = $p
    $rb.GroupName = "DNS"
    $rb.Margin = "0,0,10,10"
    $rb.Foreground = [System.Windows.Media.Brushes]::White
    $rb.ToolTip = "Servers: $($p.servers -join ', ')"
    $DnsPanel.Children.Add($rb) | Out-Null
  }

  # --- Populate Network Tweaks ---
  $NetworkRepairPanel = $Window.FindName("NetworkRepairPanel")
  $NetworkAdvancedPanel = $Window.FindName("NetworkAdvancedPanel")
    
  if ($NetData.repair_tools -and $NetData.repair_tools.items) {
    foreach ($key in $NetData.repair_tools.items.PSObject.Properties.Name) {
      $item = $NetData.repair_tools.items.$key
      $cb = New-Object System.Windows.Controls.CheckBox
      $cb.Content = $item.label
      $cb.Tag = $item
      $cb.Foreground = [System.Windows.Media.Brushes]::White
      $cb.Margin = "0,2,0,2"
      $NetworkRepairPanel.Children.Add($cb) | Out-Null
    }
  }

  foreach ($groupKey in ("gaming_latency", "tcp_stack_advanced")) {
    $group = $NetData.$groupKey
    if (-not $group) { continue }
    
    # Create Border Container (Card Style)
    $border = New-Object System.Windows.Controls.Border
    $border.Background = $Window.Resources["PanelBackground"]
    $border.CornerRadius = "10"
    $border.Padding = "20"
    $border.Margin = "0,0,0,20"

    $stack = New-Object System.Windows.Controls.StackPanel
    
    # Header
    $header = New-Object System.Windows.Controls.TextBlock
    $header.Text = $group.title
    $header.FontSize = 16
    $header.FontWeight = "Bold"
    $header.Foreground = $Window.Resources["AccentColor"]
    $header.Margin = "0,0,0,10"
    $stack.Children.Add($header) | Out-Null

    # Description
    if ($group.description) {
      $desc = New-Object System.Windows.Controls.TextBlock
      $desc.Text = $group.description
      $desc.Foreground = $Window.Resources["SecondaryText"]
      $desc.FontSize = 12
      $desc.TextWrapping = "Wrap"
      $desc.Margin = "0,0,0,15"
      $stack.Children.Add($desc) | Out-Null
    }

    # Items
    if ($group.items) {
      foreach ($key in $group.items.PSObject.Properties.Name) {
        $item = $group.items.$key
        $cb = New-Object System.Windows.Controls.CheckBox
        $cb.Content = $item.label
        $cb.Tag = $item
        $cb.Foreground = [System.Windows.Media.Brushes]::White
        $cb.Margin = "0,2,0,2"
        $stack.Children.Add($cb) | Out-Null
      }
    }
        
    $btn = New-Object System.Windows.Controls.Button
    if ($groupKey -eq "gaming_latency") {
      $btn.Content = "Apply Gaming Tweaks"
    }
    else {
      $btn.Content = "Apply TCP/IP Tweaks"
    }
    $btn.Margin = "0,15,0,0"
    $btn.HorizontalAlignment = "Right"
    $btn.Style = $Window.Resources["PrimaryButton"] 
        
    $btn.Add_Click({
        param($s, $e)
        $parentStack = $s.Parent
        $SelectedItems = @()
        foreach ($child in $parentStack.Children) {
          if ($child -is [System.Windows.Controls.CheckBox] -and $child.IsChecked) {
            $SelectedItems += $child.Tag
          }
        }
            
        if (-not $SelectedItems) { 
          Show-Toast -Message "No tweaks selected." -Type "Info"
          return 
        }
            
        foreach ($t in $SelectedItems) {
          $StatusText.Text = "Applying $($t.label)..."
          
          # Use Dispatcher
          $result = Invoke-Handler -Entry $t -WhatIf:$false
            
          if ($result.Success) {
            Write-Log "Applied: $($t.label)" "SUCCESS"
          }
          else {
            Write-Log "Failed: $($t.label)" "ERROR"
          }
        }
        $StatusText.Text = "Tweaks applied"
        Show-Toast -Message "Network tweaks applied successfully!" -Type "Success"
      })
      
    $stack.Children.Add($btn) | Out-Null
    $border.Child = $stack
    $NetworkAdvancedPanel.Children.Add($border) | Out-Null
  }

  # ------------------------------------------------------------------------------
  # 7. EVENT HANDLERS
  # ------------------------------------------------------------------------------
    
  # INSTALL APPS
  $BtnInstall.Add_Click({
      $StatusText.Text = "Preparing to install apps..."
      $Checked = @()
      
      # Collect all checked apps
      foreach ($expander in $AppsPanel.Children) {
        if ($expander -is [System.Windows.Controls.Expander]) {
          $wp = $expander.Content
          foreach ($border in $wp.Children) {
            $cb = $border.Child
            if ($cb.IsChecked) { $Checked += $cb.Tag } # Just pass IDs
          }
        }
      }
    
      if (-not $Checked) {
        Show-Toast -Message "No apps selected." -Type "Info"
        $StatusText.Text = "Ready"
        return
      }

      $StatusText.Text = "Installing $($Checked.Count) app(s)..."
      [System.Windows.Forms.Application]::DoEvents()

      $result = Invoke-AppInstallHandler -App $Checked
      
      if ($result.Success) {
        $StatusText.Text = "All apps installed successfully!"
        Show-Toast -Message "All applications installed successfully!" -Type "Success" -Duration 5000
      }
      else {
        $StatusText.Text = "Installation failed/partial"
        Show-Toast -Message "$($result.Error)" -Type "Warning" -Duration 6000
      }
    })

  # TWEAKS
  $BtnApplyTweaks = $Window.FindName("BtnApplyTweaks")
  $ChkCreateRestore = $Window.FindName("ChkCreateRestore")
  $ChkDryRunTweaks = $Window.FindName("ChkDryRunTweaks")
  $BtnApplyTweaks.Add_Click({
      $isDryRun = $ChkDryRunTweaks.IsChecked
      
      # Check if already running
      if ($script:ProcessRunning) {
        Show-Toast -Message "A tweak operation is already in progress. Please wait for it to complete." -Type "Warning"
        return
      }

      $Selected = @()
      $Toggles = @()
      foreach ($child in $TweaksLeftPanel.Children + $TweaksRightPanel.Children) {
        if ($child -is [System.Windows.Controls.CheckBox]) {
          # Check if it's a toggle by checking handler
          $key = $child.Tag
          $tweak = $TweaksData.$key
          $isToggle = $tweak.PSObject.Properties.Name -contains 'handler' -and $tweak.handler -eq 'toggle'
          if ($isToggle) {
            # Only include toggles that have changed from their initial state
            $initialState = $script:ToggleInitialStates[$key]
            if ($child.IsChecked -ne $initialState) {
              $Toggles += $child
            }
          }
          elseif ($child.IsChecked) {
            # Regular checkboxes only if checked
            $Selected += $child
          }
        }
      }
      
      if (-not $Selected -and -not $Toggles) { 
        Show-Toast -Message "No tweaks selected." -Type "Info"
        return 
      }

      # Set process running flag
      $script:ProcessRunning = $true

      try {
        # Dry-run mode: show preview and exit
        if ($isDryRun) {
          Write-Log "=== TWEAKS DRY RUN PREVIEW ===" "INFO"
          $previewRegChanges = 0
          $previewSvcChanges = 0
          foreach ($cb in $Selected) {
            $key = $cb.Tag
            if (-not $key) { continue }
            $tweak = $TweaksData.$key
            if (-not $tweak) { continue }
            if ($tweak.PSObject.Properties.Name -contains 'registry' -and $tweak.registry) { 
              $previewRegChanges += $tweak.registry.Count 
            }
            if ($tweak.PSObject.Properties.Name -contains 'service' -and $tweak.service) { 
              $previewSvcChanges += $tweak.service.Count 
            }
            Write-Log "Would apply: $($tweak.Content)" "INFO"
          }
          foreach ($toggle in $Toggles) {
            $key = $toggle.Tag
            if (-not $key) { continue }
            $tweak = $TweaksData.$key
            if (-not $tweak) { continue }
            $state = if ($toggle.IsChecked) { "ON" } else { "OFF" }
            Write-Log "Would toggle: $($tweak.Content) -> $state" "INFO"
          }
          $StatusText.Text = "Preview complete - no changes applied"
          Show-Toast -Message "Preview: $previewRegChanges registry, $previewSvcChanges service changes from $($Selected.Count + $Toggles.Count) tweak(s)" -Type "Info" -Duration 5000
          $script:ProcessRunning = $false
          return
        }
        
        # Initialize counters for summary
        $tweaksApplied = 0
        $registryChanges = 0
        $servicesConfigured = 0
        $servicesSkipped = 0
        $togglesApplied = 0
        $errorsOccurred = 0

        Write-Log "--- Starting Tweaks Application ---"
        
        if ($ChkCreateRestore.IsChecked) {
          $StatusText.Text = "Creating Restore Point..."
          [System.Windows.Forms.Application]::DoEvents()
          Write-Log "Creating system restore point..."
          try {
            # Bypass the 24-hour cooldown (Windows blocks frequent restore points)
            $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore"
            $oldFreq = (Get-ItemProperty -Path $regPath -Name "SystemRestorePointCreationFrequency" -ErrorAction SilentlyContinue).SystemRestorePointCreationFrequency
            Set-ItemProperty -Path $regPath -Name "SystemRestorePointCreationFrequency" -Value 0 -Type DWord -Force

            Checkpoint-Computer -Description "Optimizer Restore Point" -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
            Write-Log "Restore point created successfully" "SUCCESS"

            # Restore original frequency (1440 minutes = 24 hours default)
            if ($null -ne $oldFreq) {
              Set-ItemProperty -Path $regPath -Name "SystemRestorePointCreationFrequency" -Value $oldFreq -Type DWord -Force
            }
            else {
              Set-ItemProperty -Path $regPath -Name "SystemRestorePointCreationFrequency" -Value 1440 -Type DWord -Force
            }
          }
          catch {
            Write-Log "Failed to create restore point: $_" "WARNING"
          }
        }

        # Process regular checkboxes first
        $totalItems = $Selected.Count + $Toggles.Count
        $currentIndex = 0

        for ($i = 0; $i -lt $Selected.Count; $i++) {
          $currentIndex++
          $cb = $Selected[$i]
          $key = $cb.Tag
          $tweak = $TweaksData.$key
          
          $StatusText.Text = "[$currentIndex/$totalItems] Applying: $($tweak.Content)"
          [System.Windows.Forms.Application]::DoEvents()
          Write-Log "Applying tweak: $($tweak.Content)"
      
          # === REGISTRY CHANGES ===
          if ($tweak.registry) {
            foreach ($reg in $tweak.registry) {
              # Create HKU drive if needed for HKEY_USERS access
              if ($reg.Path -imatch "hku" -and !(Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
                try {
                  New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS -ErrorAction Stop | Out-Null
                }
                catch {
                  Write-Log "Failed to create HKU drive: $_" "ERROR"
                  $errorsOccurred++
                  continue
                }
              }
              
              $path = $reg.Path.Replace("HKLM:", "Registry::HKEY_LOCAL_MACHINE").Replace("HKCU:", "Registry::HKEY_CURRENT_USER")
              
              if (-not (Test-Path $path)) { 
                try {
                  New-Item -Path $path -Force -ErrorAction Stop | Out-Null 
                }
                catch {
                  $errorsOccurred++
                  continue
                }
              }
              
              $type = if ($reg.Type -eq "DWord") { "DWord" } else { "String" }
              try {
                Set-ItemProperty -Path $path -Name $reg.Name -Value $reg.Value -Type $type -Force -ErrorAction Stop
                Write-Log "Registry: $path\$($reg.Name) = $($reg.Value)" "SUCCESS"
                $registryChanges++
              }
              catch {
                Write-Log "Registry failed: $path\$($reg.Name) - $_" "ERROR"
                $errorsOccurred++
              }
            }
          }
          
          # === SCRIPT EXECUTION ===
          if ($tweak.InvokeScript) { 
            foreach ($line in $tweak.InvokeScript) { 
              try {
                $scriptBlock = [scriptblock]::Create($line)
                & $scriptBlock
                Write-Log "Script executed: $($line.Substring(0, [Math]::Min(50, $line.Length)))..." "SUCCESS"
              } 
              catch {
                Write-Log "Script failed: $_" "ERROR"
                $errorsOccurred++
              }
            } 
          }
          
          # === SERVICE CHANGES ===
          if ($tweak.service) {
            foreach ($srv in $tweak.service) {
              $changeService = $true
              
              # Check if service exists and preserve user modifications
              try {
                $service = Get-Service -Name $srv.Name -ErrorAction Stop
                
                # If service has OriginalType defined, check if user modified it
                if ($srv.OriginalType) {
                  if ($service.StartType.ToString() -ne $srv.OriginalType) {
                    # User already customized this service, skip it
                    Write-Log "Service '$($srv.Name)' skipped - user customized" "SKIPPED"
                    $servicesSkipped++
                    $changeService = $false
                  }
                }
              }
              catch {
                # Check if it's a "service not found" error
                if ($_.Exception.Message -like "*Cannot find any service*" -or $_.Exception.Message -like "*does not exist*") {
                  # Service not found, skip silently
                  Write-Log "Service '$($srv.Name)' not found on this system" "SKIPPED"
                  $changeService = $false
                }
                else {
                  Write-Log "Error checking service '$($srv.Name)': $_" "ERROR"
                  $errorsOccurred++
                  $changeService = $false
                }
              }
              
              if ($changeService) {
                try {
                  if ($srv.StartupType -eq "AutomaticDelayedStart") {
                    sc.exe config $srv.Name start= delayed-auto | Out-Null
                  }
                  else {
                    Set-Service -Name $srv.Name -StartupType $srv.StartupType -ErrorAction Stop
                  }
                  
                  if ($srv.StartupType -eq "Disabled") { 
                    Stop-Service -Name $srv.Name -ErrorAction SilentlyContinue
                  }
                  Write-Log "Service '$($srv.Name)' set to $($srv.StartupType)" "SUCCESS"
                  $servicesConfigured++
                }
                catch {
                  Write-Log "Service '$($srv.Name)' failed: $_" "ERROR"
                  $errorsOccurred++
                }
              }
            }
          }
          
          $tweaksApplied++
        }

        # Process toggles - apply Value if ON, OriginalValue if OFF
        foreach ($toggle in $Toggles) {
          $currentIndex++
          $key = $toggle.Tag
          $tweak = $TweaksData.$key
          $isOn = $toggle.IsChecked
          
          $StatusText.Text = "[$currentIndex/$totalItems] Applying: $($tweak.Content)"
          [System.Windows.Forms.Application]::DoEvents()
          $toggleState = if ($isOn) { "ON" } else { "OFF" }
          Write-Log "Toggle: $($tweak.Content) -> $toggleState"
          
          if ($tweak.registry) {
            foreach ($reg in $tweak.registry) {
              $path = $reg.Path.Replace("HKLM:", "Registry::HKEY_LOCAL_MACHINE").Replace("HKCU:", "Registry::HKEY_CURRENT_USER")
              
              if (-not (Test-Path $path)) { 
                try {
                  New-Item -Path $path -Force -ErrorAction Stop | Out-Null 
                }
                catch {
                  Write-Log "Toggle path creation failed: $path - $_" "ERROR"
                  $errorsOccurred++
                  continue
                }
              }
              
              $type = if ($reg.Type -eq "DWord") { "DWord" } else { "String" }
              
              # Choose value based on toggle state
              $valueToApply = if ($isOn) { $reg.Value } else { $reg.OriginalValue }
              
              # Skip if OriginalValue is <RemoveEntry> and toggle is OFF
              if (-not $isOn -and $valueToApply -eq "<RemoveEntry>") {
                try {
                  Remove-ItemProperty -Path $path -Name $reg.Name -ErrorAction SilentlyContinue
                  $registryChanges++
                }
                catch {
                  # Silent fail for removal
                }
                continue
              }
              
              try {
                Set-ItemProperty -Path $path -Name $reg.Name -Value $valueToApply -Type $type -Force -ErrorAction Stop
                Write-Log "Toggle registry: $path\$($reg.Name) = $valueToApply" "SUCCESS"
                $registryChanges++
              }
              catch {
                Write-Log "Toggle registry failed: $path\$($reg.Name) - $_" "ERROR"
                $errorsOccurred++
              }
            }
          }
          
          # Execute InvokeScript (ON) or UndoScript (OFF)
          $scriptToRun = if ($isOn) { $tweak.InvokeScript } else { $tweak.UndoScript }
          if ($scriptToRun) {
            foreach ($line in $scriptToRun) {
              try {
                $scriptBlock = [scriptblock]::Create($line)
                & $scriptBlock
                Write-Log "Toggle script executed successfully" "SUCCESS"
              }
              catch {
                Write-Log "Toggle script failed: $_" "ERROR"
                $errorsOccurred++
              }
            }
          }
          
          # Update initial state to current state so toggle won't be re-processed
          $script:ToggleInitialStates[$key] = $toggle.IsChecked
          $togglesApplied++
        }

        Restart-ExplorerIfNeeded
        
        # Build summary message
        $summaryParts = @()
        if ($tweaksApplied -gt 0) { $summaryParts += "Applied $tweaksApplied tweak(s)" }
        if ($togglesApplied -gt 0) { $summaryParts += "$togglesApplied toggle(s) updated" }
        if ($registryChanges -gt 0) { $summaryParts += "$registryChanges registry changes" }
        if ($servicesConfigured -gt 0) { $summaryParts += "$servicesConfigured services configured" }
        if ($servicesSkipped -gt 0) { $summaryParts += "$servicesSkipped skipped (user-customized)" }
        if ($errorsOccurred -gt 0) { $summaryParts += "$errorsOccurred errors" }
        
        $summaryMessage = $summaryParts -join ", "
        
        $StatusText.Text = "Tweaks applied successfully"
        Write-Log "--- Tweaks Summary: $summaryMessage ---"
        
        if ($errorsOccurred -gt 0) {
          Show-Toast -Message "$summaryMessage. View log for details." -Type "Warning" -Duration 6000
        }
        else {
          Show-Toast -Message $summaryMessage -Type "Success" -Duration 5000
        }
      }
      catch {
        Write-Log "Critical error applying tweaks: $_" "ERROR"
        $StatusText.Text = "Error applying tweaks"
        Show-Toast -Message "An error occurred. View log for details." -Type "Error" -Duration 6000
      }
      finally {
        # Always clear the process running flag
        $script:ProcessRunning = $false
      }
    })


  $TxtInstallSearch.Add_TextChanged({
      $filter = $TxtInstallSearch.Text
      
      foreach ($expander in $AppsPanel.Children) {
        $hasVisibleChildren = $false
        $wrapPanel = $expander.Content
          
        foreach ($border in $wrapPanel.Children) {
          # Border contains CheckBox as Child
          $cb = $border.Child
          if ($cb.Content -like "*$filter*") {
            $border.Visibility = "Visible"
            $hasVisibleChildren = $true
          }
          else {
            $border.Visibility = "Collapsed"
          }
        }

        if ($hasVisibleChildren) {
          $expander.Visibility = "Visible"
          # Optional: Start expanded if searching? 
          if (-not [string]::IsNullOrWhiteSpace($filter)) {
            $expander.IsExpanded = $true
          }
        }
        else {
          $expander.Visibility = "Collapsed"
        }
      }
    })

  # DEBLOAT
  $BtnDebloat = $Window.FindName("BtnDebloat")
  $BtnDebloat.Add_Click({
      $Selected = $DebloatList.ItemsSource | Where-Object { $_.IsSelected -eq $true }
      if (-not $Selected) {
        Show-Toast -Message "No apps selected for removal." -Type "Info"
        return
      }
      Write-Log "--- Starting Debloat ---"
      foreach ($item in $Selected) {
        $StatusText.Text = "Removing $($item.DisplayName)..."
        [System.Windows.Forms.Application]::DoEvents() # Keep UI responsive
			
        Invoke-DebloatHandler -PackageName $item.PackageName -Type $item.Type -DisplayName $item.DisplayName
      }
      Write-Log "Debloat complete - Processed $($Selected.Count) app(s)"
      $StatusText.Text = "Debloat complete"
      Show-Toast -Message "Debloat completed." -Type "Success"
		  
      # Refresh list to clear selections and update state
      Refresh-DebloatList
    })



  # DNS
  $DnsPanel = $Window.FindName("DnsProvidersPanel")
  $BtnSetDns = $Window.FindName("BtnSetDns")
  $BtnRevertDns = $Window.FindName("BtnRevertDns")
  $TxtCurrentDns = $Window.FindName("TxtCurrentDns")
  
  # Add SelectionChanged handler for Adapters to show current DNS
  $CmbAdapters.Add_SelectionChanged({
      $adapter = $CmbAdapters.SelectedItem
      if ($adapter) {
        try {
          $current = (Get-DnsClientServerAddress -InterfaceAlias $adapter -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses
          if ($current) {
            $TxtCurrentDns.Text = "Current DNS: $($current -join ', ')"
            $TxtCurrentDns.Foreground = "#FFF"
          }
          else {
            $TxtCurrentDns.Text = "Current DNS: Automatic (DHCP)"
            $TxtCurrentDns.Foreground = "#999"
          }
        }
        catch {
          $TxtCurrentDns.Text = "Current DNS: Unknown"
        }
      }
    })
  $BtnSetDns.Add_Click({
      $Adapter = $CmbAdapters.SelectedItem
      if (-not $Adapter) { 
        Show-Toast -Message "No network adapter selected." -Type "Info"
        return 
      }
      $SelectedRb = $null
      foreach ($child in $DnsPanel.Children) {
        if ($child -is [System.Windows.Controls.RadioButton] -and $child.IsChecked) { $SelectedRb = $child; break }
      }
      if (-not $SelectedRb) { 
        Show-Toast -Message "No DNS provider selected." -Type "Info"
        return 
      }
      $p = $SelectedRb.Tag
      $StatusText.Text = "Setting DNS for $Adapter..."
      Write-Log "Setting DNS: $($SelectedRb.Content) for adapter '$Adapter'"
      
      # Use Invoke-Handler for DNS
      $result = Invoke-Handler -Entry $p -AdapterName $Adapter -WhatIf:$false
      
      if ($result.Success) {
        $StatusText.Text = "DNS configured"
        Show-Toast -Message "DNS set to $($SelectedRb.Content) for $Adapter" -Type "Success"
        Show-Toast -Message "DNS set to $($SelectedRb.Content) for $Adapter" -Type "Success"
        # Manually update display logic matches SelectionChanged event
        try {
          $current = (Get-DnsClientServerAddress -InterfaceAlias $Adapter -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses
          if ($current) {
            $TxtCurrentDns.Text = "Current DNS: $($current -join ', ')"
            $TxtCurrentDns.Foreground = "#FFF"
          }
        }
        catch {}
      }
      else {
        Write-Log "Failed to set DNS: $($result.Error)" "ERROR"
        Show-Toast -Message "Failed to set DNS. View log for details." -Type "Error"
      }
    })
  $BtnRevertDns.Add_Click({
      $Adapter = $CmbAdapters.SelectedItem
      if (-not $Adapter) { 
        Show-Toast -Message "No network adapter selected." -Type "Info"
        return 
      }
      $StatusText.Text = "Reverting DNS..."
      Write-Log "Reverting DNS for adapter '$Adapter'"
      try {
        Set-DnsClientServerAddress -InterfaceAlias $Adapter -ResetServerAddresses
        Write-Log "DNS reverted to automatic" "SUCCESS"
        $StatusText.Text = "DNS reverted"
        Show-Toast -Message "DNS reverted to automatic for $Adapter" -Type "Success"
      }
      catch {
        Write-Log "Failed to revert DNS: $_" "ERROR"
        Show-Toast -Message "Failed to revert DNS. View log for details." -Type "Error"
      }
    })

  # NETWORK REPAIR
  $BtnRunRepair = $Window.FindName("BtnRunRepair")
  $BtnRunRepair.Add_Click({
      $Selected = @()
      foreach ($child in $NetworkRepairPanel.Children) { if ($child.IsChecked) { $Selected += $child.Tag } }
      if (-not $Selected) { 
        Show-Toast -Message "No repair tools selected." -Type "Info"
        return 
      }
      Write-Log "--- Starting Network Repair ---"
      foreach ($item in $Selected) {
        $StatusText.Text = "Running: $($item.label)..."
        
        # Use Invoke-Handler for network items
        $result = Invoke-Handler -Entry $item -WhatIf:$false
        
        if ($result.Success) {
          Write-Log "Processed: $($item.label)" "SUCCESS"
        }
        else {
          Write-Log "Failed: $($item.label)" "ERROR"
        }
      }
      Write-Log "Network repair complete"
      $StatusText.Text = "Repair complete"
      Show-Toast -Message "Network repair tools executed successfully." -Type "Success"
    })

  # PRIVACY
  $BtnApplyPrivacy = $Window.FindName("BtnApplyPrivacy")
  $ChkDryRunPrivacy = $Window.FindName("ChkDryRunPrivacy")
  $BtnApplyPrivacy.Add_Click({
      $isDryRun = $ChkDryRunPrivacy.IsChecked
      $Selected = @()
      foreach ($child in $PrivacyPanel.Children) {
        if ($child -is [System.Windows.Controls.CheckBox] -and $child.IsChecked -and $child.Tag) {
          $Selected += $child
        }
      }
      if (-not $Selected) { 
        Show-Toast -Message "No privacy settings selected." -Type "Info"
        return 
      }
      
      Write-Log "--- Starting Privacy Settings $(if ($isDryRun) { '(DRY RUN)' } else { '' }) ---"
      $allResults = @()
      $totalRegChanges = 0
      $totalSvcChanges = 0
      
      foreach ($cb in $Selected) {
        $key = $cb.Tag
        $tweak = $PrivacyData.$key
        Update-Status "$(if ($isDryRun) { '[Preview] ' } else { '' })$($tweak.Content)"
        
        # Use handler dispatcher
        $result = Invoke-Handler -Entry $tweak -Key $key -WhatIf:$isDryRun
        $allResults += $result
        $totalRegChanges += $result.RegistryChanges
        $totalSvcChanges += $result.ServicesChanged
      }
      
      if ($isDryRun) {
        # Show preview summary
        $previewMsg = "Preview: $totalRegChanges registry, $totalSvcChanges service changes would be made"
        Show-Toast -Message $previewMsg -Type "Info" -Duration 5000
        Write-Log "=== DRY RUN PREVIEW ===" "INFO"
        foreach ($r in $allResults) {
          foreach ($change in $r.WouldChange) {
            Write-Log $change "INFO"
          }
        }
        $StatusText.Text = "Preview complete - no changes applied"
      }
      else {
        Restart-Explorer
        $StatusText.Text = "Privacy settings applied"
        Show-Toast -Message "Privacy settings applied: $totalRegChanges registry, $totalSvcChanges services" -Type "Success" -Duration 5000
      }
      Write-Log "Privacy settings complete - $($Selected.Count) setting(s)"
    })

  # --- INITIAL DASHBOARD LOAD ---
  Update-Dashboard
  Populate-DashboardDescriptions
  
  # Load installed apps for debloat in background
  $Window.Dispatcher.InvokeAsync({
      Get-InstalledApps
    }) | Out-Null

  # ------------------------------------------------------------------------------
  # SHOW WINDOW
  # ------------------------------------------------------------------------------
  # Initialize toast notification system
  Initialize-ToastContainer
  
  # Enable dark mode titlebar (Windows 10/11)
  try {
    Add-Type @"
using System;
using System.Runtime.InteropServices;
public class DwmApi {
    [DllImport("dwmapi.dll")]
    public static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int attrValue, int attrSize);
}
"@
    
    # Show window first to get handle
    $Window.Show()
    
    # Get window handle
    $hwnd = (New-Object System.Windows.Interop.WindowInteropHelper($Window)).Handle
    
    # DWMWA_USE_IMMERSIVE_DARK_MODE = 20
    $darkMode = 1
    [DwmApi]::DwmSetWindowAttribute($hwnd, 20, [ref]$darkMode, 4) | Out-Null
    
    # Hide and show again to apply
    $Window.Hide()
  }
  catch {
    Write-Log "Could not enable dark titlebar: $_" "WARNING"
  }
  
  $Window.ShowDialog() | Out-Null

}
catch {
  Write-Log "FATAL ERROR: $_" "ERROR"
  Write-Log "Stack trace: $($_.ScriptStackTrace)" "ERROR"
}
