"""
defender: Windows Defender, the same things as Settings > Privacy & security > Windows Security.
Routed from app.py ("defender", "def", "av" or "wd").

    def                            is Windows Defender protecting this PC, and what needs attention
    def why                        what is wrong, and the command that fixes each thing
    def scan [quick|full|<path>]   start a scan in the background (--wait stays until it is done)
    def scan status | stop         is a scan running, and how the last one went | end the running one
    def scans [n]                  recent scans: when, which kind, how they ended
    def update                     get the newest virus signatures
    def threats [all|<id>]         what Defender found, and what it did about it
    def quarantine                 threats that are still active or in quarantine
    def clean                      remove every active threat Defender has found (administrator; asks first)
    def on|off <protection>        realtime, behavior, downloads, scripts, cloud, samples, pua, network, folders
    def <protection> [value]       show one, or set it: def cloud advanced, def samples never, def pua audit
    def folders [add|rm|allow|disallow ...]   controlled folder access: the folders it guards, the apps it trusts
    def exclusions [add path|ext|process <value> | rm <id>]   places Defender does not look
    def schedule [day <day>] [time <HH:MM>] [type quick|full]   the scheduled scan
    def cpu [<percent>]            how much of the CPU a scan may use
    def asr [<n> block|audit|warn|off|unset]   attack surface reduction rules
    def smartscreen | device | tamper          reputation protection, device security, tamper protection
    def events [days] [scans|threats|protection|updates|settings]   what Defender logged
    def offline                    Microsoft Defender Offline scan (restarts the PC; asks twice)
    def open [threats|settings|history|browser|device|isolation|network|offline]   open the Windows Security app

Reading needs no administrator rights (the exclusion list is the exception: Windows hides it from ordinary
users). Every change needs an administrator terminal, and the page checks that before it asks anything.
Readings and changes go through the Defender PowerShell module (Get-MpComputerStatus, Get-MpPreference,
Set-MpPreference, Add-MpPreference, Start-MpScan, Update-MpSignature, Get-MpThreat ...), the registry for
SmartScreen and device security, and the Defender event log for history.

Tamper Protection locks real-time, behaviour, download and cloud protection against changes from anything
but the Windows Security app. This page does not try to get around it, or around a policy set by an
organisation: it says which one is in the way.
"""

import base64
import os
import re
import subprocess
import sys
import time
from datetime import datetime

import _core
import _net
import _probe
import _win

# ======================================================================
# SETTING INFO — read by app.py to list and route this setting
# ======================================================================
NAME = "defender"
ALIASES = ["def", "av", "wd"]
SUMMARY = "Windows Defender: status, scans, protection, exclusions"
USAGE = ("def | def why | def scan [quick|full|<path>] | def update | def threats | def on|off <protection> | "
         "def exclusions | def folders | def schedule | def events | def open")
HELP = [
    ("def", "is Windows Defender protecting this PC, and what needs attention"),
    ("def why", "what is wrong, and the command that fixes each thing"),
    ("def scan", "start a quick scan in the background (def scan full, or def scan <folder>)"),
    ("def update", "get the newest virus signatures"),
    ("def threats", "what Defender found, and what it did about it"),
    ("def on|off <protection>", "real-time, behavior, cloud ... (administrator; turning off asks first)"),
    ("", "scans and threats"),
    ("def scan status", "is a scan running, and how the last one went (def scan stop ends it)"),
    ("def scans [n]", "recent scans: when, which kind, how they ended"),
    ("def quarantine", "threats that are still active or in quarantine"),
    ("def clean", "remove the active threats Defender found (administrator; asks first)"),
    ("def offline", "Defender Offline scan: restarts the PC (administrator; asks twice)"),
    ("", "protection settings"),
    ("def <protection>", "show one: realtime, behavior, downloads, scripts, cloud, samples, pua, network, folders"),
    ("def cloud off|basic|advanced", "cloud-delivered protection"),
    ("def samples ask|safe|never|all", "automatic sample submission"),
    ("def pua|network|folders [mode]", "off, on or audit: unwanted apps, network protection, folder guard"),
    ("def folders add|rm|allow", "the folders controlled folder access guards, and the apps it trusts"),
    ("def tamper", "tamper protection: what it does, and where to change it"),
    ("", "exclusions and schedule"),
    ("def exclusions", "places Defender does not look (add path|ext|process <value>, rm <id>)"),
    ("def schedule", "the scheduled scan, e.g. def schedule day sun time 02:00 type full"),
    ("def cpu <percent>", "how much of the CPU a scan may use"),
    ("", "hardening and history"),
    ("def asr", "attack surface reduction rules, e.g. def asr 3 audit"),
    ("def smartscreen", "SmartScreen and Smart App Control (read only)"),
    ("def device", "device security: memory integrity, Secure Boot, TPM (read only)"),
    ("def events [days]", "what Defender logged: scans, threats, protection turned off, updates"),
    ("def open [page]", "open the Windows Security app: threats, settings, history, browser, device, network"),
]
TIP = ("Reading needs no administrator rights; changes do, and turning protection off asks first. "
       "Tamper Protection can only be changed in the Windows Security app: def open settings.")
RUN_ALONE = True  # typing 'def' on its own shows the status, which changes nothing

# ======================================================================
# CONSTANTS
# ======================================================================
POLICY_KEY = r"SOFTWARE\Policies\Microsoft\Windows Defender"  # values here mean a policy owns the setting
MDM_ENROLLMENTS = r"SOFTWARE\Microsoft\Enrollments"  # one subkey per device-management enrollment
WINDOWS_AUTHORITIES = ("Local Authority", "Cloud Authority", "Deploy Authority")  # Windows' own, not an organisation
SAC_KEY = r"SYSTEM\CurrentControlSet\Control\CI\Policy"  # VerifiedAndReputablePolicyState: Smart App Control
HVCI_KEY = r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"  # Enabled
SECURE_BOOT_KEY = r"SYSTEM\CurrentControlSet\Control\SecureBoot\State"  # UEFISecureBootEnabled (hardware.py reads it too)
EXPLORER_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"  # SmartScreenEnabled: apps and files
SMARTSCREEN_POLICY_KEY = r"SOFTWARE\Policies\Microsoft\Windows\System"  # EnableSmartScreen, ShellSmartScreenLevel
EDGE_POLICY_KEY = r"SOFTWARE\Policies\Microsoft\Edge"  # SmartScreenEnabled
APPHOST_KEY = r"Software\Microsoft\Windows\CurrentVersion\AppHost"  # EnableWebContentEvaluation: Store apps
SERVICES = [  # (service name, what it is)
    ("WinDefend", "Microsoft Defender Antivirus Service"),
    ("WdNisSvc", "Network Inspection Service"),
    ("SecurityHealthService", "Windows Security Service"),
    ("wscsvc", "Security Center"),
]
EVENT_LOG = "Microsoft-Windows-Windows Defender/Operational"
NEVER_AGE = 4294967295  # Get-MpComputerStatus reports this age for a scan that never ran
STALE_DAYS, OLD_DAYS = 3, 7  # signatures older than STALE_DAYS are a warning, older than OLD_DAYS a problem
SCAN_OLD_DAYS = 7  # no scan for this long is a warning
PASSIVE_WORDS = ("passive", "edr block")  # AMRunningMode values: another antivirus is in charge
SCAN_FILE = "defender-scan.json"  # the scan this page started: pid, kind, when (in the data folder)
SCAN_LOG = "defender-scan.log"  # what that scan's PowerShell wrote to stderr, to catch an immediate failure
LAUNCH_WAIT = 4  # seconds to watch a new scan for an immediate failure
WAIT_POLL = 5  # seconds between looks when --wait is given
WAIT_LIMIT = 6 * 3600  # --wait gives up after this many seconds
SCAN_EVENTS = (1000, 1001, 1002, 1005)  # started, finished, stopped, failed
LIST_WORDS = ("ls", "list")
REMOVE_WORDS = ("rm", "remove", "delete", "del")
ON_WORDS, OFF_WORDS = _net.ON_WORDS, _net.OFF_WORDS
DAY_NAMES = ["every day", "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "never"]
DAY_WORDS = {"every": 0, "everyday": 0, "daily": 0, "all": 0, "sun": 1, "sunday": 1, "mon": 2, "monday": 2,
             "tue": 3, "tuesday": 3, "wed": 4, "wednesday": 4, "thu": 5, "thursday": 5, "fri": 6, "friday": 6,
             "sat": 7, "saturday": 7, "never": 8, "off": 8, "none": 8}
SCAN_TYPES = {"quick": 1, "full": 2}
SCAN_TYPE_NAMES = {1: "quick scan", 2: "full scan"}

# Plain words for the numbers Windows uses in threat records (MSFT_MpThreat, MSFT_MpThreatDetection)
SEVERITY = {0: "unknown", 1: "low", 2: "moderate", 4: "high", 5: "severe"}
THREAT_STATUS = {0: "unknown", 1: "detected", 2: "cleaned", 3: "quarantined", 4: "removed", 5: "allowed",
                 6: "blocked", 102: "quarantine failed", 103: "removal failed", 104: "allow failed",
                 105: "abandoned", 107: "block failed"}
HANDLED = {"cleaned", "quarantined", "removed", "blocked"}  # the threat is dealt with
CLEAN_ACTIONS = {1: "clean", 2: "quarantine", 3: "remove", 6: "allow", 8: "user defined", 9: "no action", 10: "block"}

# What each Defender event id means, in plain words, and whether it is good news (ok), neutral (info) or not
EVENT_TEXT = {
    1000: ("scan started", "info"), 1001: ("scan finished", "ok"), 1002: ("scan stopped before it finished", "warn"),
    1003: ("scan paused", "info"), 1004: ("scan resumed", "info"), 1005: ("scan failed", "bad"),
    1006: ("threat found", "bad"), 1007: ("action taken against a threat", "ok"),
    1008: ("action against a threat failed", "bad"), 1015: ("suspicious behaviour detected", "bad"),
    1116: ("threat found", "bad"), 1117: ("action taken against a threat", "ok"),
    1118: ("action against a threat failed", "bad"), 1119: ("action against a threat failed badly", "bad"),
    2000: ("signatures updated", "ok"), 2001: ("signature update failed", "bad"), 2002: ("engine updated", "ok"),
    2003: ("engine update failed", "bad"), 2004: ("went back to the last known good signatures", "warn"),
    3002: ("real-time protection stopped working", "bad"), 5000: ("real-time protection turned on", "ok"),
    5001: ("real-time protection turned off", "bad"), 5004: ("real-time protection settings changed", "warn"),
    5007: ("protection settings changed", "warn"), 5008: ("the scan engine stopped unexpectedly", "bad"),
    5009: ("spyware protection turned on", "ok"), 5010: ("spyware protection turned off", "bad"),
    5011: ("antivirus turned on", "ok"), 5012: ("antivirus turned off", "bad"),
    5013: ("Tamper Protection blocked a change to the settings", "warn"),
}
EVENT_GROUPS = {
    "scans": (1000, 1001, 1002, 1003, 1004, 1005),
    "threats": (1006, 1007, 1008, 1015, 1116, 1117, 1118, 1119),
    "updates": (2000, 2001, 2002, 2003, 2004),
    "protection": (3002, 5000, 5001, 5008, 5009, 5010, 5011, 5012),
    "settings": (5004, 5007, 5013),
}
EVENT_DEFAULT_DAYS, EVENT_LIMIT = 7, 60

# Attack surface reduction rules, with Microsoft's names (Learn: "Attack surface reduction rules reference")
ASR_RULES = [
    ("56a863a9-875e-4185-98a7-b882c64b5ce5", "Block abuse of exploited vulnerable signed drivers"),
    ("7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c", "Block Adobe Reader from creating child processes"),
    ("d4f940ab-401b-4efc-aadc-ad5f3c50688a", "Block all Office applications from creating child processes"),
    ("9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", "Block credential stealing from the Windows local security authority (lsass.exe)"),
    ("be9ba2d9-53ea-4cdc-84e5-9b1eeee46550", "Block executable content from email client and webmail"),
    ("01443614-cd74-433a-b99e-2ecdc07bfc25", "Block executable files unless they meet a prevalence, age or trusted-list rule"),
    ("5beb7efe-fd9a-4556-801d-275e5ffc04cc", "Block execution of potentially obfuscated scripts"),
    ("d3e037e1-3eb8-44c8-a917-57927947596d", "Block JavaScript or VBScript from launching downloaded executable content"),
    ("3b576869-a4ec-4529-8536-b80a7769e899", "Block Office applications from creating executable content"),
    ("75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84", "Block Office applications from injecting code into other processes"),
    ("26190899-1602-49e8-8b27-eb1d0a1ce869", "Block Office communication application from creating child processes"),
    ("e6db77e5-3df2-4cf1-b95a-636979351e5b", "Block persistence through WMI event subscription"),
    ("d1e49aac-8f56-4280-b9ba-993a6d77406c", "Block process creations originating from PSExec and WMI commands"),
    ("33ddedf1-c6e0-47cb-833e-de6133960387", "Block rebooting machine in Safe Mode (preview)"),
    ("b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4", "Block untrusted and unsigned processes that run from USB"),
    ("c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb", "Block use of copied or impersonated system tools (preview)"),
    ("a8f5898e-1dc8-49a9-9878-85004b8a61e6", "Block Webshell creation for Servers (meant for servers)"),
    ("92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b", "Block Win32 API calls from Office macros"),
    ("c1db55ab-c21a-4637-bb3f-a12568109d35", "Use advanced protection against ransomware"),
]
ASR_MODES = {0: "off", 1: "block", 2: "audit", 5: "not set", 6: "warn"}
ASR_WORDS = {"block": "Enabled", "on": "Enabled", "audit": "AuditMode", "warn": "Warn", "off": "Disabled"}

# Where the Windows Security app opens, by page. windowsdefender:// is the app's own address scheme; if it does not
# open, ms-settings:windowsdefender (Settings > Privacy & security > Windows Security) is used instead.
OPEN_TARGETS = {
    "app": ("windowsdefender://", "the Windows Security app"),
    "threats": ("windowsdefender://threat", "Virus & threat protection"),
    "virus": ("windowsdefender://threat", "Virus & threat protection"),
    "settings": ("windowsdefender://threatsettings", "Virus & threat protection settings (Tamper Protection is here)"),
    "history": ("windowsdefender://fullhistory", "Protection history"),
    "browser": ("windowsdefender://appbrowser", "App & browser control"),
    "smartscreen": ("windowsdefender://appbrowser", "App & browser control"),
    "device": ("windowsdefender://devicesecurity", "Device security"),
    "isolation": ("windowsdefender://coreisolation", "Core isolation"),
    "network": ("windowsdefender://network", "Firewall & network protection"),
    "offline": ("windowsdefender://wdoscan/", "Microsoft Defender Offline scan"),
}
SETTINGS_FALLBACK = "ms-settings:windowsdefender"

# An exclusion for any of these is a hole in the protection: asked twice
RISKY_EXTENSIONS = {".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".msi", ".lnk", ".jar"}
BROAD_PATH = re.compile(r"^([A-Za-z]:\\?|\\\\|%[A-Za-z]+%\\?|[A-Za-z]:\\(Windows|Users|Program Files( \(x86\))?|ProgramData)\\?)$",
                        re.IGNORECASE)


class DefenderError(Exception):
    """An error with an exit code: 1 for system errors, 2 for bad usage."""

    def __init__(self, message, code=1):
        super().__init__(message)
        self.code = code


# ======================================================================
# READING — the Defender cmdlets, one PowerShell call for the parts a command needs.
# Each part runs in its own try, so one refusal does not stop the rest.
# ======================================================================
_PRELUDE = r"""
$data = [ordered]@{}
$errors = [ordered]@{}
function Part([string]$name, [scriptblock]$block) {
    try { $data[$name] = @(& $block) } catch { $errors[$name] = $_.Exception.Message }
}
"""
_TAIL = "\n[pscustomobject]@{ data = $data; errors = $errors }\n"
PARTS = {
    "status": r"""Part 'status' { Get-MpComputerStatus | Select-Object AMServiceEnabled, AntivirusEnabled,
        AntispywareEnabled, AMRunningMode, RealTimeProtectionEnabled, BehaviorMonitorEnabled, IoavProtectionEnabled,
        OnAccessProtectionEnabled, NISEnabled, IsTamperProtected, TamperProtectionSource, AMEngineVersion,
        AMProductVersion, AntivirusSignatureVersion, AntivirusSignatureLastUpdated, AntivirusSignatureAge,
        QuickScanEndTime, QuickScanAge, FullScanEndTime, FullScanAge, DefenderSignaturesOutOfDate, RebootRequired,
        SmartAppControlState }""",
    "prefs": r"""Part 'prefs' { Get-MpPreference | Select-Object DisableRealtimeMonitoring, DisableBehaviorMonitoring,
        DisableIOAVProtection, DisableScriptScanning, DisableBlockAtFirstSeen, MAPSReporting, SubmitSamplesConsent,
        PUAProtection, EnableNetworkProtection, EnableControlledFolderAccess, CloudBlockLevel, ScanScheduleDay,
        @{n='ScanScheduleTime'; e={ $t = $_.ScanScheduleTime; if ($t -is [TimeSpan]) { $t.ToString() } elseif ($t -is [DateTime]) { $t.ToString('HH:mm:ss') } else { [string]$t } }},
        ScanParameters, ScanAvgCPULoadFactor, RandomizeScheduleTaskTimes, SignatureUpdateInterval }""",
    "exclusions": r"""Part 'exclusions' { Get-MpPreference | Select-Object ExclusionPath, ExclusionExtension,
        ExclusionProcess }""",
    "folders": r"""Part 'folders' { Get-MpPreference | Select-Object ControlledFolderAccessProtectedFolders,
        ControlledFolderAccessAllowedApplications }""",
    "asr": r"""Part 'asr' { Get-MpPreference | Select-Object AttackSurfaceReductionRules_Ids,
        AttackSurfaceReductionRules_Actions }""",
    "products": r"""Part 'products' { Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct |
        Select-Object displayName, productState }""",
    "threats": r"""Part 'threats' { Get-MpThreat | Select-Object ThreatID, ThreatName, SeverityID, IsActive,
        DidThreatExecute, @{n='Resources'; e={ @($_.Resources) }} }""",
    "detections": r"""Part 'detections' { Get-MpThreatDetection | Select-Object DetectionID, ThreatID, ProcessName,
        InitialDetectionTime, LastThreatStatusChangeTime, ThreatStatusID, CleaningActionID, ActionSuccess,
        DomainUser, @{n='Resources'; e={ @($_.Resources) }} }""",
    "events": r"""Part 'events' {
        $ids = @($env:W11_IDS -split ',' | ForEach-Object { [int]$_ })
        $since = (Get-Date).AddDays(-[int]$env:W11_DAYS)
        try {
            Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = $ids; StartTime = $since } -MaxEvents ([int]$env:W11_LIMIT) |
                ForEach-Object { [pscustomobject]@{ Id = $_.Id; Time = $_.TimeCreated; Message = $_.Message } }
        } catch { if ($_.Exception.Message -notmatch 'No events were found') { throw } }
    }""",
    "tpm": r"""Part 'tpm' { Get-Tpm | Select-Object TpmPresent, TpmReady, ManufacturerVersion }""",
    "deviceguard": r"""Part 'deviceguard' { Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard |
        Select-Object VirtualizationBasedSecurityStatus, @{n='Running'; e={ @($_.SecurityServicesRunning) }},
        @{n='Configured'; e={ @($_.SecurityServicesConfigured) }} }""",
}


class Reading:
    """What the parts of one PowerShell call returned, and why any part failed."""

    def __init__(self, data, raw):
        self.data, self.raw = data, raw

    def rows(self, name):
        return self.data.get(name) or []

    def row(self, name):
        rows = self.rows(name)
        return rows[0] if rows else {}

    def failed(self, name):
        return name in self.raw

    def reason(self, name):
        return _probe.reason(self.raw[name]) if name in self.raw else None


def _read(names, env=None, timeout=90):
    """Run the named parts in one PowerShell call."""
    reply = _win.powershell_json(_PRELUDE + "\n".join(PARTS[name] for name in names) + _TAIL, timeout, env)
    body = reply[0] if reply else {}
    return Reading(body.get("data") or {}, body.get("errors") or {})


def _list(value):
    """A property that is a list, a single string or missing, as a list of strings."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    return [str(item) for item in value if item not in (None, "")]


def _hidden(items):
    """Windows replaces lists it hides from ordinary users with 'N/A: Must be an administrator ...'."""
    return any(item.lower().startswith("n/a") for item in items)


def _moment(text):
    """A datetime from the ISO text _win gives, or None for a missing or placeholder date (before the year 2000)."""
    if not text:
        return None
    try:
        when = datetime.fromisoformat(text)
    except (TypeError, ValueError):
        return None
    return when if when.year >= 2000 else None


def _days_since(when):
    return max(0, (datetime.now() - when).days) if when else None


def _when(text):
    """'2026-10-21 14:03 (2 hours ago)' for ISO text, 'never' when Windows has no date."""
    when = _moment(text)
    return f"{when:%Y-%m-%d %H:%M} ({_win.ago(when)})" if when else "never"


def _onoff(flag):
    return "on" if flag is True else "off" if flag is False else "unknown"


def _plural(count, word):
    return f"{count} {word}{'' if count == 1 else 's'}"


# ======================================================================
# THE SWITCHES — one table drives the status, 'def why', 'def on|off' and 'def <protection>'
# ======================================================================
class Switch:
    """One protection setting: the preference behind it, the words for its values, and what turning it off costs."""

    def __init__(self, key, title, pref, words, names, on, off, what, risk, effective=None, tamper=False,
                 ask_on=False, quiet=False, strength=None, policy=None, on_note=None):
        self.key, self.title, self.pref, self.words, self.names = key, title, pref, words, names
        self.on_word, self.off_word, self.what, self.risk = on, off, what, risk
        self.effective = effective  # Get-MpComputerStatus property that says whether it is really working
        self.tamper = tamper  # Tamper Protection locks it against changes from anything but the Security app
        self.ask_on = ask_on  # turning it on can break things, so ask
        self.quiet = quiet  # never ask: a privacy preference, not a protection
        self.strength = strength  # {word: rank} for settings with more than on and off
        self.policy = policy  # where an organisation's policy for it lives, under POLICY_KEY
        self.on_note = on_note

    def word_of(self, value):
        """The word for the value Windows holds ('on', 'advanced' ...), whether it came as a number, a flag or text."""
        if value is None:
            return "unknown"
        if isinstance(value, str):
            if value.lstrip("-").isdigit():
                value = int(value)
            else:
                lowered = value.lower()
                return lowered if lowered in self.words else lowered
        return self.names.get(value, str(value))

    def state(self, status, prefs):
        """What it is really doing now: the effective state when Windows reports one, else the preference."""
        if self.effective and status.get(self.effective) is not None:
            return _onoff(status[self.effective])
        return self.word_of(prefs.get(self.pref))

    def lowers(self, old, new):
        """Whether going from the word `old` to the word `new` weakens protection."""
        if self.quiet:
            return False
        if self.strength:
            return self.strength.get(new, 0) < self.strength.get(old, 0)
        return new == "off" and old != "off"

    def usage(self):
        words = [word for word in self.words if word not in ("on", "off") or not self.strength]
        return f"def {self.key} " + "|".join(words if self.strength or self.key == "samples" else ["on", "off"])


_BOOL_NAMES = {False: "on", True: "off"}  # the Disable* preferences: false means the protection is on
_BOOL_WORDS = {"on": False, "off": True}
_LEVELS3 = {"off": 0, "audit": 1, "on": 2}
SWITCHES = {spec.key: spec for spec in [
    Switch("realtime", "real-time protection", "DisableRealtimeMonitoring", _BOOL_WORDS, _BOOL_NAMES, "on", "off",
           "scans files as they are opened, downloaded or run",
           "Files are not scanned when they are opened, downloaded or run, so malware can run unnoticed until the next scan.",
           effective="RealTimeProtectionEnabled", tamper=True, policy="Real-Time Protection\\DisableRealtimeMonitoring"),
    Switch("behavior", "behaviour monitoring", "DisableBehaviorMonitoring", _BOOL_WORDS, _BOOL_NAMES, "on", "off",
           "watches what programs do, to catch malware that signatures do not know",
           "Windows stops watching what programs do, so malware that signatures do not know is harder to catch.",
           effective="BehaviorMonitorEnabled", tamper=True, policy="Real-Time Protection\\DisableBehaviorMonitoring"),
    Switch("downloads", "scanning of downloads and attachments", "DisableIOAVProtection", _BOOL_WORDS, _BOOL_NAMES,
           "on", "off", "scans files you download and email attachments when they arrive",
           "Downloaded files and email attachments are not checked when they arrive.",
           effective="IoavProtectionEnabled", tamper=True, policy="Real-Time Protection\\DisableIOAVProtection"),
    Switch("scripts", "script scanning", "DisableScriptScanning", _BOOL_WORDS, _BOOL_NAMES, "on", "off",
           "checks scripts (PowerShell, JavaScript, VBScript) before they run",
           "Scripts are not checked before they run.", policy="Real-Time Protection\\DisableScriptScanning"),
    Switch("cloud", "cloud-delivered protection", "MAPSReporting",
           {"off": 0, "basic": 1, "advanced": 2, "on": 2}, {0: "off", 1: "basic", 2: "advanced"}, "advanced", "off",
           "asks Microsoft's cloud about files Defender does not know, for a faster answer",
           "New threats that only Microsoft's cloud knows about are caught later.",
           tamper=True, strength={"off": 0, "basic": 1, "advanced": 2}, policy="Spynet\\SpynetReporting"),
    Switch("samples", "automatic sample submission", "SubmitSamplesConsent",
           {"ask": 0, "safe": 1, "never": 2, "all": 3, "on": 1, "off": 2}, {0: "ask", 1: "safe", 2: "never", 3: "all"},
           "safe", "never", "sends suspicious files to Microsoft for analysis: ask first, safe ones only, never, or all",
           "Microsoft gets fewer samples to learn from.", quiet=True, policy="Spynet\\SubmitSamplesConsent"),
    Switch("pua", "blocking of unwanted apps", "PUAProtection", {"off": 0, "on": 1, "audit": 2},
           {0: "off", 1: "on", 2: "audit"}, "on", "off",
           "blocks software that is unwanted but not strictly malware, such as adware and bundled installers",
           "Adware and bundled junk software is no longer blocked.", strength=_LEVELS3, policy="PUAProtection"),
    Switch("network", "network protection", "EnableNetworkProtection", {"off": 0, "on": 1, "audit": 2},
           {0: "off", 1: "on", 2: "audit"}, "on", "off", "stops apps reaching dangerous sites and servers",
           "Apps are no longer stopped from reaching dangerous sites and servers.", strength=_LEVELS3,
           policy="Windows Defender Exploit Guard\\Network Protection\\EnableNetworkProtection"),
    Switch("folders", "controlled folder access", "EnableControlledFolderAccess", {"off": 0, "on": 1, "audit": 2},
           {0: "off", 1: "on", 2: "audit", 3: "block disk changes only", 4: "audit disk changes only"}, "on", "off",
           "stops apps Windows does not trust from changing files in Documents, Pictures, Videos, Music and Desktop "
           "(ransomware protection)",
           "Ransomware protection for your Documents, Pictures and other folders stops.",
           ask_on=True, strength=_LEVELS3,
           policy="Windows Defender Exploit Guard\\Controlled Folder Access\\EnableControlledFolderAccess"),
]}
SWITCH_ORDER = list(SWITCHES)
