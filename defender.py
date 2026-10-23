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
# extra words people use, for 'settings search'
KEYWORDS = ["antivirus", "virus", "malware", "scan", "security", "windows security", "threat", "ransomware",
            "smartscreen", "exclusion", "quarantine"]
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
ASR_STRENGTH = {"not set": 0, "off": 0, "audit": 1, "warn": 2, "block": 3}
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


def _is_broad(path):
    """A path that covers a drive, a system folder, everything, or is only a wildcard or a bare root."""
    text = path.strip().strip('"').replace("/", "\\")
    if not text.strip("*?\\ "):
        return True
    parts = [part for part in re.split(r"\\+", text.rstrip("\\")) if part not in ("", "*", "?")]
    if text.startswith("\\\\"):
        return len(parts) <= 2
    root = 1 if re.match(r"^([A-Za-z]:|%[A-Za-z_]+%)", parts[0] if parts else "") else 0
    depth = len(parts) - root
    return depth <= 0 or (depth == 1 and parts[-1].lower() in (
        "windows", "users", "program files", "program files (x86)", "programdata"))


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


def _isnum(word):
    """Whether a word is plain ASCII digits (str.isdigit() also accepts '²', which int() cannot read)."""
    return re.fullmatch(r"[0-9]+", str(word)) is not None


def _say(options, text=""):
    """Progress and prose for a person; under --json it goes to stderr so stdout stays one JSON document."""
    print(text, file=sys.stderr if options["json"] else sys.stdout)


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
            if _isnum(value.lstrip("-")):
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


# ======================================================================
# THE PICTURE — what Windows says, turned into one dict that the status, 'def why' and --json all use
# ======================================================================
def _services():
    return {name: _net.service_state(name) for name, _ in SERVICES}


def _policy_values():
    """Every value under the Defender policy key, as {'Real-Time Protection\\DisableRealtimeMonitoring': 1, ...}."""
    found = {}

    def walk(path, label):
        for name, (value, _) in _win.reg_values(_win.HKLM, path).items():
            found[label + name] = value
        for sub in _win.reg_subkeys(_win.HKLM, path):
            walk(path + "\\" + sub, label + sub + "\\")

    walk(POLICY_KEY, "")
    return found


def _managed_by():
    """Plain reasons an organisation manages this PC (the same test location.py uses); empty if it does not."""
    reasons = []
    domain = os.environ.get("USERDNSDOMAIN")
    if domain:
        reasons.append(f"joined to the domain {domain}")
    for enrollment in _win.reg_subkeys(_win.HKLM, MDM_ENROLLMENTS):
        provider = _net.reg_read(f"{MDM_ENROLLMENTS}\\{enrollment}", "ProviderID")
        if provider and provider not in WINDOWS_AUTHORITIES:
            reasons.append(f"enrolled in device management ({provider})")
    return reasons


def _products(reading):
    """Other antivirus products registered with Windows Security Center. productState is read the way third-party
    tools read it (0x1000 = on, 0x10 = definitions out of date); Microsoft does not document it."""
    found = []
    for row in reading.rows("products"):
        name = str(row.get("displayName") or "")
        if not name or "defender" in name.lower():
            continue
        state = row.get("productState")
        known = isinstance(state, int)
        found.append({"name": name, "on": bool(state & 0x1000) if known else None,
                      "up_to_date": not state & 0x10 if known else None, "product_state": state})
    return found


def _scan_info(status, kind):
    end = status.get(f"{kind}ScanEndTime")
    when = _moment(end)
    if when is None:
        return {"last": None, "age_days": None}
    age = status.get(f"{kind}ScanAge")
    return {"last": end, "age_days": age if isinstance(age, int) and age != NEVER_AGE else _days_since(when)}


def _signatures(status):
    updated = status.get("AntivirusSignatureLastUpdated")
    age = status.get("AntivirusSignatureAge")
    if not isinstance(age, int) or age == NEVER_AGE:
        age = _days_since(_moment(updated))
    return {"version": status.get("AntivirusSignatureVersion"), "updated": updated if _moment(updated) else None,
            "age_days": age, "engine": status.get("AMEngineVersion"), "product": status.get("AMProductVersion"),
            "out_of_date": status.get("DefenderSignaturesOutOfDate")}


def _schedule(prefs):
    day = prefs.get("ScanScheduleDay")
    kind = prefs.get("ScanParameters")
    day = int(day) if isinstance(day, (int, str)) and _isnum(str(day)) else None
    return {"day": DAY_NAMES[day] if day is not None and day < len(DAY_NAMES) else None,
            "time": prefs.get("ScanScheduleTime") or None,
            "type": SCAN_TYPE_NAMES.get(int(kind)) if _isnum(str(kind)) else None,
            "randomized": prefs.get("RandomizeScheduleTaskTimes")}


def _picture():
    reading = _read(["status", "prefs", "products", "threats"])
    status, prefs = reading.row("status"), reading.row("prefs")
    threats = reading.rows("threats")
    products = _products(reading)
    mode = status.get("AMRunningMode") or None
    policy = _policy_values()
    protection = {key: spec.state(status, prefs) for key, spec in SWITCHES.items()}
    protection["tamper"] = _onoff(status.get("IsTamperProtected"))
    unavailable = {}
    for name, label in (("status", "status"), ("prefs", "protection settings"), ("threats", "threat list")):
        if reading.failed(name):
            unavailable[label] = reading.reason(name)
    return {
        "readable": bool(status), "status_error": reading.reason("status"),
        "mode": mode, "passive": bool(mode) and any(word in mode.lower() for word in PASSIVE_WORDS),
        "enabled": status.get("AntivirusEnabled"), "other_products": products,
        "other_active": [item["name"] for item in products if item["on"]],
        "protection": protection, "signatures": _signatures(status),
        "scans": {"quick": _scan_info(status, "Quick"), "full": _scan_info(status, "Full"), "schedule": _schedule(prefs)},
        "threats": {"active": sum(1 for item in threats if item.get("IsActive")), "known": len(threats)},
        "services": _services(), "policy": {"values": len(policy), "set": policy, "managed_by": _managed_by()},
        "reboot_required": status.get("RebootRequired"), "smart_app_control": status.get("SmartAppControlState"),
        "unavailable": unavailable, "findings": [], "verdict": None,
    }


def _finding(level, key, text, fix=None):
    return {"level": level, "key": key, "text": text, "fix": fix}


def _judge(p):
    """Fills p['findings'] and p['verdict']. 'bad' and 'warn' need attention; 'info' is worth knowing."""
    out = []
    protection, sig, scans, services = p["protection"], p["signatures"], p["scans"], p["services"]
    others = p["other_active"]
    in_charge = p["readable"] and p["enabled"] is not False and not p["passive"]
    if not p["readable"]:
        if services.get("WinDefend") == "RUNNING":
            out.append(_finding("warn", "unreadable", "Windows Defender is running, but its status could not be read"
                                f" ({p['status_error'] or 'no reason given'}).", "def help"))
        elif others:
            out.append(_finding("info", "other", f"{', '.join(others)} is the active antivirus, so Windows Defender "
                                "is not running. That is normal."))
        else:
            out.append(_finding("bad", "service", "Windows Defender's service is not running, and no other antivirus "
                                "is registered. This PC may be unprotected.", "svc WinDefend on"))
    elif p["enabled"] is False:
        if others:
            out.append(_finding("info", "other", f"Windows Defender is off because {', '.join(others)} is the active "
                                "antivirus. That is normal."))
        else:
            out.append(_finding("bad", "disabled", "Windows Defender's antivirus is turned off, and no other antivirus "
                                "is registered.", "def open threats"))
    elif p["passive"]:
        who = ", ".join(others) if others else "another product"
        out.append(_finding("info", "passive", f"Windows Defender is in {p['mode']}: {who} is the antivirus in charge, "
                            "so protection is managed there."))
    if in_charge:
        if protection["realtime"] == "off":
            out.append(_finding("bad", "realtime", "Real-time protection is off. Files are not scanned when they are "
                                "opened, downloaded or run.", "def on realtime"))
        for key, text in (("behavior", "Behaviour monitoring is off."), ("downloads", "Downloads and attachments are not "
                          "being scanned."), ("cloud", "Cloud-delivered protection is off.")):
            if protection[key] == "off":
                out.append(_finding("warn", key, text, f"def on {key}"))
        if protection["samples"] in ("never", "ask"):
            out.append(_finding("info", "samples", f"Automatic sample submission is '{protection['samples']}': "
                                "Microsoft gets fewer samples. A privacy choice, not a fault.", "def samples safe"))
        if protection["tamper"] == "off":
            out.append(_finding("warn", "tamper", "Tamper Protection is off, so other programs can change these "
                                "settings.", "def open settings"))
        age = sig["age_days"]
        if sig["out_of_date"] or (age is not None and age >= OLD_DAYS):
            out.append(_finding("bad", "signatures", "The virus signatures are " + (
                f"{_plural(age, 'day')} old." if age is not None else "out of date."), "def update"))
        elif age is not None and age >= STALE_DAYS:
            out.append(_finding("warn", "signatures", f"The virus signatures are {_plural(age, 'day')} old.", "def update"))
        ages = [item["age_days"] for item in (scans["quick"], scans["full"]) if item["last"]]
        if not ages:
            out.append(_finding("warn", "scan", "No scan has been run on this PC yet.", "def scan"))
        elif min(ages) >= SCAN_OLD_DAYS:
            out.append(_finding("warn", "scan", f"The last scan was {_plural(min(ages), 'day')} ago.", "def scan"))
        if p["threats"]["active"]:
            count = p["threats"]["active"]
            out.append(_finding("bad", "threats", f"{_plural(count, 'threat')} found by Defender "
                                f"{'is' if count == 1 else 'are'} still active.", "def threats"))
        for key, label in (("pua", "Blocking of unwanted apps"), ("network", "Network protection"),
                           ("folders", "Controlled folder access")):
            if protection[key] == "off":
                out.append(_finding("info", key, f"{label} is off. It is optional extra protection.", f"def on {key}"))
    if p["reboot_required"]:
        out.append(_finding("warn", "reboot", "Windows Defender needs a restart to finish an update.", None))
    if services.get("SecurityHealthService") not in (None, "RUNNING", "UNKNOWN") and p["readable"]:
        out.append(_finding("warn", "securityhealth", "The Windows Security service is not running, so the Windows "
                            "Security app cannot show the status.", "svc SecurityHealthService on"))
    if p["policy"]["values"]:
        out.append(_finding("info", "policy", f"{_plural(p['policy']['values'], 'Defender setting')} come from a policy "
                            "(Group Policy or device management), so changes here may be refused or put back."))
    p["findings"] = out
    attention = [item for item in out if item["level"] in ("bad", "warn")]
    if not p["readable"] and others or (p["readable"] and (p["enabled"] is False or p["passive"]) and others):
        p["verdict"] = "not active"
    else:
        p["verdict"] = "needs attention" if attention else "protected"
    return p


def _attention(p):
    return [item for item in p["findings"] if item["level"] in ("bad", "warn")]


LEVEL_COLORS = {"bad": _net.RED, "warn": _net.YELLOW, "info": _net.CYAN, "ok": _net.GREEN}


def _verdict_line(p):
    count = len(_attention(p))
    if p["verdict"] == "protected":
        return _net.GREEN + "Windows Defender: protected" + _net.RESET
    if p["verdict"] == "not active":
        who = ", ".join(p["other_active"]) or "another product"
        return _net.CYAN + f"Windows Defender is not the active antivirus: {who} is" + _net.RESET
    return _net.YELLOW + f"Windows Defender: needs attention ({_plural(count, 'thing')})" + _net.RESET


def _public(p):
    """The picture without the raw policy values, for --json."""
    out = {key: value for key, value in p.items() if key != "policy"}
    out["policy"] = {"values": p["policy"]["values"], "managed_by": p["policy"]["managed_by"]}
    return out


def _finding_lines(items):
    lines = []
    for item in items:
        color = LEVEL_COLORS[item["level"]]
        lines.append(color + f"  {item['text']}" + (f"   fix: {item['fix']}" if item["fix"] else "") + _net.RESET)
    return lines


# ======================================================================
# SHOWING — the status, and 'def why'
# ======================================================================
def _status_cmd(options):
    p = _judge(_picture())
    if options["json"]:
        _core.print_json(_public(p))
        return 0
    protection, sig, scans = p["protection"], p["signatures"], p["scans"]
    rows = []
    for key in SWITCH_ORDER:
        spec, state = SWITCHES[key], protection[key]
        hint = f"   (def {key} {spec.on_word})" if state == "off" and key in ("realtime", "behavior", "downloads", "cloud") else ""
        rows.append((spec.title, state + hint))
    rows.append(("tamper protection", protection["tamper"]))
    schedule = scans["schedule"]
    scheduled = ("not set" if not schedule["day"] else
                 "never" if schedule["day"] == "never" else
                 f"{schedule['day']} at {(schedule['time'] or '?')[:5]}, {schedule['type'] or 'scan'}")
    sections = [
        ("protection", rows),
        ("signatures", [("version", sig["version"]), ("last updated", _when(sig["updated"])),
                        ("engine", sig["engine"]), ("program", sig["product"])]),
        ("scans", [("last quick scan", _when(scans["quick"]["last"])), ("last full scan", _when(scans["full"]["last"])),
                   ("scheduled scan", scheduled)]),
        ("threats", [("still active", p["threats"]["active"]), ("found before", p["threats"]["known"]),
                     ("details", "def threats")]),
        ("this PC", [("mode", p["mode"] or "unknown"),
                     ("other antivirus", [f"{i['name']} ({'on' if i['on'] else 'off'})" for i in p["other_products"]] or "none"),
                     ("services", ", ".join(f"{name} {state.lower()}" for name, state in p["services"].items())),
                     ("set by policy", "yes" if p["policy"]["values"] else "no"),
                     ("managed by", p["policy"]["managed_by"] or "nobody"),
                     ("firewall", "fw shows it")]),
        ("next", [("def why", "what is wrong, with the fix for each"), ("def scan", "start a quick scan"),
                  ("def help", "everything this page can do")]),
    ]
    attention = _finding_lines(_attention(p))
    _net.render(_verdict_line(p) + ("\n" + "\n".join(attention) if attention else ""), sections)
    for label, reason in p["unavailable"].items():
        print(f"not available: {label} ({reason})")
    return 0


def _why_cmd(options):
    p = _judge(_picture())
    if options["json"]:
        _core.print_json({"verdict": p["verdict"], "findings": p["findings"], "unavailable": p["unavailable"]})
        return 0
    print(_verdict_line(p))
    need = _attention(p)
    other = [item for item in p["findings"] if item["level"] == "info"]
    if not need:
        print("\nNothing needs attention.")
    for number, item in enumerate(need, start=1):
        print(LEVEL_COLORS[item["level"]] + f"\n {number}. {item['text']}" + _net.RESET)
        if item["fix"]:
            print(f"    fix: {item['fix']}" + ("   (administrator)" if item["fix"].startswith(("def on", "svc")) else ""))
    if other:
        print(_net.CYAN + "\nGood to know" + _net.RESET)
        for line in _finding_lines(other):
            print(line)
    for label, reason in p["unavailable"].items():
        print(f"not available: {label} ({reason})")
    return 0


# ======================================================================
# EVENTS — the Defender operational log: scans, threats, protection turned off, updates
# ======================================================================
def _events(ids, days, limit=EVENT_LIMIT):
    """Defender events, newest first: [{'id', 'time', 'message'}]."""
    reading = _read(["events"], env={"W11_IDS": ",".join(str(i) for i in ids), "W11_DAYS": str(int(days)),
                                     "W11_LIMIT": str(int(limit))})
    if reading.failed("events"):
        raise DefenderError(f"could not read the Defender event log ({reading.reason('events')})")
    return [{"id": int(row.get("Id") or 0), "time": row.get("Time"), "message": row.get("Message") or ""}
            for row in reading.rows("events")]


def _detail(event):
    """The one useful fact in an event's message."""
    message = event["message"]
    if event["id"] == 5007:
        old = re.search(r"Old value:\s*(.+)", message)
        new = re.search(r"New value:\s*(.+)", message)
        if new:
            name = re.split(r"[\\=]", new.group(1).split(" = ")[0])[-1].strip() if " = " in new.group(1) else new.group(1)
            return f"{name}: {(old.group(1).split(' = ')[-1].strip() if old else '?')} -> {new.group(1).split(' = ')[-1].strip()}"
    found = re.search(r"(?:Name|Threat name):\s*(.+)", message)
    if found and event["id"] in (1006, 1007, 1008, 1015, 1116, 1117, 1118, 1119):
        return found.group(1).strip()
    found = re.search(r"Scan Parameters:\s*(.+)", message)
    if found and event["id"] in SCAN_EVENTS:
        return found.group(1).strip()
    found = re.search(r"(?:Current|New) (?:security intelligence|signature) version:\s*(\S+)", message)
    if found:
        return f"version {found.group(1)}"
    lines = [line.strip() for line in message.splitlines() if line.strip()]
    return lines[0][:80] if lines else ""


def _events_cmd(words, options):
    days, ids, label = EVENT_DEFAULT_DAYS, None, "everything"
    for word in words:
        if _isnum(word) and 1 <= int(word) <= 365:
            days = int(word)
        elif word.lower() in EVENT_GROUPS and ids is None:
            ids, label = EVENT_GROUPS[word.lower()], word.lower()
        else:
            raise DefenderError("usage: def events [days] [scans|threats|protection|updates|settings]", 2)
    if ids is None:
        ids = tuple(sorted(i for group in EVENT_GROUPS.values() for i in group))
    events = _events(ids, days)
    rows = []
    for event in events:
        text, level = EVENT_TEXT.get(event["id"], (f"event {event['id']}", "info"))
        rows.append({"time": event["time"], "id": event["id"], "what": text, "level": level, "detail": _detail(event)})
    if options["json"]:
        _core.print_json({"days": days, "filter": label, "events": rows})
        return 0
    if not rows:
        print(f"Defender logged no {label} events in the last {_plural(days, 'day')}.")
        return 0
    for row in rows:
        when = _moment(row["time"])
        print(LEVEL_COLORS[row["level"]] + f"{when:%Y-%m-%d %H:%M}  {row['what']:<48}{row['detail']}".rstrip() + _net.RESET)
    print(f"\n{_plural(len(rows), 'event')} in the last {_plural(days, 'day')} ({label}). "
          "'def events 30 protection' looks further back; 'def events threats' narrows it.")
    return 0


# ======================================================================
# SCANS — started in the background, so the person gets the prompt back
# ======================================================================
def _mpcmdrun():
    """MpCmdRun.exe: the newest copy in the platform folder, else the one in Program Files."""
    platform = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "Microsoft", "Windows Defender", "Platform")
    try:
        versions = sorted(os.listdir(platform), key=lambda v: [int(n) for n in re.findall(r"\d+", v)], reverse=True)
    except OSError:
        versions = []
    for version in versions:
        path = os.path.join(platform, version, "MpCmdRun.exe")
        if os.path.isfile(path):
            return path
    return os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "Windows Defender", "MpCmdRun.exe")


def _pid_alive(pid):
    try:
        import psutil
        return bool(pid) and psutil.pid_exists(pid)
    except ImportError:
        return None


def _process_stamp(pid):
    """(create time, name) of a process, to tell it from a later process that reuses the pid; None if unknown."""
    try:
        import psutil
        proc = psutil.Process(pid)
        return round(proc.create_time(), 1), proc.name().lower()
    except Exception:
        return None


def _saved_scan():
    """The scan this page started, if its process is still that process. A reused pid drops the file."""
    saved = _win.load_json(SCAN_FILE, {}) or {}
    pid = saved.get("pid")
    if not pid or not _pid_alive(pid):
        return None
    stamp = _process_stamp(pid)
    if saved.get("stamp") and stamp and [saved["stamp"][0], saved["stamp"][1]] != [stamp[0], stamp[1]]:
        try:
            (_win.data_dir() / SCAN_FILE).unlink()
        except OSError:
            pass
        return None
    return saved


def _scan_runs(days=30, limit=200):
    """Scans from the event log, newest first: started, how it ended, which kind. Pairs the events by scan id."""
    runs, order = {}, []
    for event in reversed(_events(SCAN_EVENTS, days, limit)):
        found = re.search(r"Scan ID:\s*(\{?[0-9A-Fa-f-]{8,}\}?)", event["message"])
        key = found.group(1).strip("{}").lower() if found else f"event-{event['id']}-{event['time']}"
        run = runs.setdefault(key, {"started": None, "ended": None, "result": None, "type": None})
        kind = re.search(r"Scan Parameters:\s*(.+)", event["message"])
        if kind:
            run["type"] = kind.group(1).strip().lower()
        if event["id"] == 1000:
            run["started"] = event["time"]
            order.append(key)
        else:
            run["ended"] = event["time"]
            run["result"] = {1001: "finished", 1002: "stopped before it finished", 1005: "failed"}.get(event["id"])
            if key not in order:
                order.append(key)
    out = []
    for key in reversed(order):
        run = runs[key]
        start, end = _moment(run["started"]), _moment(run["ended"])
        run["seconds"] = int((end - start).total_seconds()) if start and end else None
        run["result"] = run["result"] or ("running" if start and (datetime.now() - start).days < 1 else "unknown")
        out.append(run)
    return out


def _duration(seconds):
    if seconds is None:
        return "-"
    minutes, secs = divmod(seconds, 60)
    return f"{minutes} min {secs} s" if minutes else f"{secs} s"


def _scans_cmd(words, options):
    if len(words) > 1 or (words and not _isnum(words[0])):
        raise DefenderError("usage: def scans [n]", 2)
    count = int(words[0]) if words else 10
    runs = _scan_runs()[:count]
    if options["json"]:
        _core.print_json({"scans": runs})
        return 0
    if not runs:
        print("Defender logged no scans in the last 30 days.")
        return 0
    print(f"{'STARTED':<18}{'KIND':<14}{'RESULT':<28}TOOK")
    for run in runs:
        start = _moment(run["started"] or run["ended"])
        color = {"finished": _net.GREEN, "running": _net.CYAN}.get(run["result"], _net.YELLOW)
        print(color + f"{start:%Y-%m-%d %H:%M}".ljust(18) + f"{(run['type'] or 'scan')[:12]:<14}{run['result']:<28}"
              f"{_duration(run['seconds'])}" + _net.RESET)
    return 0


def _scan_running():
    """Whether a scan is going now: the one this page started (its saved process), else the newest log events."""
    saved = _saved_scan()
    if saved:
        return {"running": True, "started": saved.get("started"), "kind": saved.get("kind"), "by": "this page"}
    for run in _scan_runs(days=2, limit=40)[:1]:
        if run["result"] == "running":
            return {"running": True, "started": run["started"], "kind": run["type"], "by": "Windows"}
    return {"running": False, "started": None, "kind": None, "by": None}


def _scan_status(options):
    now = _scan_running()
    last = next((run for run in _scan_runs() if run["result"] != "running"), None)
    if options["json"]:
        _core.print_json({"running": now["running"], "started": now["started"], "kind": now["kind"],
                          "started_by": now["by"], "last": last})
        return 0
    if now["running"]:
        print(_net.CYAN + f"a {now['kind'] or 'scan'} is running (started {_win.ago(now['started'])}, by {now['by']}). "
              "'def scan stop' ends it." + _net.RESET)
    else:
        print("no scan is running.")
    if last:
        print(f"last scan: {last['type'] or 'scan'}, {last['result']} {_win.ago(last['ended'] or last['started'])}"
              f", took {_duration(last['seconds'])}.")
    return 0


def _launch_script(kind, custom):
    command = f"Start-MpScan -ScanType {kind}" + (" -ScanPath $env:W11_SCAN_PATH" if custom else "")
    return ("$ErrorActionPreference = 'Stop'; try { " + command +
            " } catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }")


def _start_scan(kind_word, path):
    """Start Start-MpScan in a hidden PowerShell that outlives this command. Returns (pid, finished_already)."""
    kind = "CustomScan" if path else ("FullScan" if kind_word == "full" else "QuickScan")
    encoded = base64.b64encode(_launch_script(kind, bool(path)).encode("utf-16-le")).decode("ascii")
    log = _win.data_dir() / SCAN_LOG
    env = {**os.environ, **({"W11_SCAN_PATH": path} if path else {})}
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    try:
        with open(log, "w", encoding="utf-8") as err:
            process = subprocess.Popen(["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=err, env=env,
                                       creationflags=flags)
    except OSError as e:
        raise DefenderError(f"could not start PowerShell: {e}")
    deadline = time.monotonic() + LAUNCH_WAIT
    while process.poll() is None and time.monotonic() < deadline:
        time.sleep(0.25)
    code = process.poll()
    if code not in (None, 0):
        try:
            text = log.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        raise DefenderError(_net.explain(text) if text.strip() else "Windows would not start the scan")
    return process.pid, code == 0


def _scan_cmd(words, options, wait):
    if words and words[0].lower() == "status" and len(words) == 1:
        return _scan_status(options)
    if words and words[0].lower() in ("stop", "cancel") and len(words) == 1:
        return _scan_stop(options)
    path = None
    kind = "quick"
    if words and words[0].lower() in SCAN_TYPES and len(words) == 1:
        kind = words[0].lower()
    elif words:
        path = " ".join(words)
        if not os.path.exists(path):
            raise DefenderError(f"'{path}' is not quick, full, status, stop, or a file or folder that exists", 2)
        kind = "custom"
    now = _scan_running()
    if now["running"]:
        msg = f"a {now['kind'] or 'scan'} is already running (started {_win.ago(now['started'])}). 'def scan status' shows it."
        if options["json"]:
            _core.print_json({"started": False, "reason": "already running", **now})
        else:
            print(msg)
        return 0
    expect = {"quick": "a quick scan usually takes a few minutes", "full": "a full scan can take an hour or more",
              "custom": f"scanning {path}"}[kind]
    if not options["json"]:
        print(f"starting a {kind} scan: {expect}. The PC stays usable.")
    pid, finished = _start_scan(kind, path)
    started = datetime.now().isoformat(timespec="seconds")
    _win.save_json(SCAN_FILE, {"pid": pid, "started": started, "kind": f"{kind} scan", "path": path,
                                  "stamp": _process_stamp(pid)})
    if wait and not finished:
        _wait_for_scan(pid, options)
    result = {"started": True, "kind": kind, "path": path, "pid": pid, "finished": finished or wait}
    if options["json"]:
        _core.print_json(result)
    elif finished:
        print("the scan finished already. 'def threats' shows anything it found.")
    elif not wait:
        print("the scan runs in the background. 'def scan status' shows how it is going, 'def scan stop' ends it.")
    return 0


def _wait_for_scan(pid, options):
    began = time.monotonic()
    try:
        while _pid_alive(pid) and time.monotonic() - began < WAIT_LIMIT:
            time.sleep(WAIT_POLL)
            if not options["json"] and int(time.monotonic() - began) % 30 < WAIT_POLL:
                print(f"still scanning ({int(time.monotonic() - began)} s)...")
    except KeyboardInterrupt:
        _say(options, "\nstopped waiting. The scan keeps running: 'def scan status' shows it.")
        return
    if not options["json"]:
        print("the scan has finished. 'def threats' shows anything it found.")


def _scan_stop(options):
    saved = _saved_scan()
    ok, text = _net.run_tool([_mpcmdrun(), "-Scan", "-Cancel"], timeout=60)
    if saved:
        try:
            import psutil
            psutil.Process(saved["pid"]).terminate()
        except Exception:
            pass
    if options["json"]:
        _core.print_json({"stopped": ok, "detail": text.splitlines()[0] if text else ""})
    elif ok:
        print("asked Windows Defender to stop the scan.")
    else:
        raise DefenderError(_net.explain(text) if text else "Windows would not stop the scan")
    return 0


def _update_cmd(options):
    before = _signatures(_read(["status"]).row("status"))
    if not options["json"]:
        print("asking Microsoft for the newest signatures (this can take a minute)...")
    _win.powershell("Update-MpSignature", timeout=300)
    after = _signatures(_read(["status"]).row("status"))
    changed = bool(after["version"] and after["version"] != before["version"])
    if options["json"]:
        _core.print_json({"before": before, "after": after, "updated": changed})
    elif changed:
        print(f"signatures updated: {before['version']} -> {after['version']} ({_when(after['updated'])}).")
    else:
        print(f"already up to date: version {after['version']} ({_when(after['updated'])}).")
    return 0


# ======================================================================
# THREATS — what Defender found, and what it did about it
# ======================================================================
def _resource(text):
    """Defender writes resources as 'file:_C:\\path'; the part before ':_' says what kind of thing it is."""
    return re.sub(r"^[A-Za-z]+:_", "", text or "")


def _threat_rows(reading):
    """Detections joined to their threat, newest first and numbered from 1 (the list and the ids both come from here)."""
    threats = {row.get("ThreatID"): row for row in reading.rows("threats")}
    rows = []
    for det in reading.rows("detections"):
        threat = threats.get(det.get("ThreatID"), {})
        status = THREAT_STATUS.get(det.get("ThreatStatusID"), f"status {det.get('ThreatStatusID')}")
        rows.append({
            "name": threat.get("ThreatName") or f"threat {det.get('ThreatID')}",
            "severity": SEVERITY.get(threat.get("SeverityID"), "unknown"), "status": status,
            "active": bool(threat.get("IsActive")), "action": CLEAN_ACTIONS.get(det.get("CleaningActionID")),
            "action_succeeded": det.get("ActionSuccess"), "detected": det.get("InitialDetectionTime"),
            "changed": det.get("LastThreatStatusChangeTime"), "user": det.get("DomainUser"),
            "process": det.get("ProcessName"), "resources": [_resource(r) for r in _list(det.get("Resources"))],
        })
    rows.sort(key=lambda row: row["changed"] or row["detected"] or "", reverse=True)
    for number, row in enumerate(rows, start=1):
        row["id"] = number
    return rows


def _threat_color(row):
    if row["active"] or row["status"] not in HANDLED:
        return _net.RED
    return _net.GREEN


def _threats_cmd(words, options):
    reading = _read(["threats", "detections"])
    if reading.failed("detections"):
        raise DefenderError(f"could not read the threat history ({reading.reason('detections')})")
    rows = _threat_rows(reading)
    if len(words) > 1:
        raise DefenderError("usage: def threats [all|<id>]", 2)
    if words and _isnum(words[0]):
        row = next((r for r in rows if r["id"] == int(words[0])), None)
        if row is None:
            raise DefenderError(f"no threat with id {words[0]}. Run 'def threats' to see them.", 2)
        if options["json"]:
            _core.print_json(row)
            return 0
        _net.render(row["name"], [
            ("threat", [("severity", row["severity"]), ("status", row["status"]), ("still active", row["active"]),
                        ("action", row["action"]), ("action worked", row["action_succeeded"])]),
            ("where", [("files", row["resources"] or "-"), ("program", row["process"]), ("user", row["user"])]),
            ("when", [("found", _when(row["detected"])), ("last change", _when(row["changed"]))]),
        ])
        return 0
    if words and words[0].lower() != "all":
        raise DefenderError("usage: def threats [all|<id>]", 2)
    shown = rows if words else rows[:30]
    if options["json"]:
        _core.print_json({"total": len(rows), "threats": shown})
        return 0
    if not rows:
        print(_net.GREEN + "Defender has not found any threats on this PC." + _net.RESET)
        return 0
    print(f"{'ID':<5}{'THREAT':<42}{'SEVERITY':<10}{'STATUS':<18}FOUND")
    for row in shown:
        print(_threat_color(row) + f"{row['id']:<5}{row['name'][:40]:<42}{row['severity']:<10}{row['status']:<18}"
              f"{_win.ago(row['detected'])}" + _net.RESET)
    print(f"\n{len(rows)} detection(s). 'def threats <id>' shows the files and what Defender did.")
    return 0


def _quarantine_cmd(words, options):
    if words and words[0].lower() == "restore":
        _say(options, "Restoring something from quarantine puts a file Defender judged dangerous back on this PC, so it is "
             "done in the Windows Security app: Protection history > the item > Actions.")
        _open_page("history", options)
        return 0
    if words and words[0].lower() in REMOVE_WORDS:
        raise DefenderError("Windows can only remove every active threat at once, not one. Use 'def clean'.", 2)
    if words:
        raise DefenderError("usage: def quarantine", 2)
    reading = _read(["threats", "detections"])
    rows = [row for row in _threat_rows(reading) if row["active"] or row["status"] in ("quarantined", "detected")]
    if options["json"]:
        _core.print_json({"threats": rows})
        return 0
    if not rows:
        print(_net.GREEN + "nothing is active or in quarantine." + _net.RESET)
        return 0
    for row in rows:
        print(_threat_color(row) + f"{row['id']:<5}{row['name'][:40]:<42}{row['status']:<14}"
              f"{', '.join(row['resources'])[:60]}" + _net.RESET)
    print("\n'def clean' removes the active ones. Restoring is done in the Windows Security app ('def open history').")
    return 0


def _clean_cmd(options):
    _net.need_admin()
    reading = _read(["threats"])
    active = [row for row in reading.rows("threats") if row.get("IsActive")]
    if not active:
        if options["json"]:
            _core.print_json({"removed": 0, "still_active": 0})
        else:
            print("no threat is active, so there is nothing to remove.")
        return 0
    names = ", ".join(str(row.get("ThreatName")) for row in active[:5])
    if not _core.confirm(f"Remove {_plural(len(active), 'active threat')} ({names})? Windows Defender removes or "
                         "quarantines the files it blocks them in, and a file you needed can go with them. "
                         "This cannot be undone from here (quarantined files can be restored in the Windows Security "
                         "app). [y/N]: ", options["yes"]):
        _say(options, "cancelled")
        return 0
    _say(options, "removing active threats...")
    _win.powershell("Remove-MpThreat", timeout=300)
    left = sum(1 for row in _read(["threats"]).rows("threats") if row.get("IsActive"))
    if options["json"]:
        _core.print_json({"removed": len(active) - left, "still_active": left})
    else:
        print(f"{_plural(left, 'threat')} still active." if left else "no threat is active now.")
    return 0


# ======================================================================
# PROTECTION SWITCHES — def on|off <protection>, def <protection> [value]
# ======================================================================
def _ps_value(value):
    if isinstance(value, bool):
        return "$true" if value else "$false"
    return str(int(value))


def _policy_hit(spec, policy):
    lowered = {name.lower() for name in policy}  # registry names are not case-sensitive
    return spec.policy if spec.policy and spec.policy.lower() in lowered else None


def _show_switch(spec, options):
    reading = _read(["status", "prefs"])
    status, prefs = reading.row("status"), reading.row("prefs")
    state = spec.state(status, prefs)
    policy = _policy_values()
    managed = _policy_hit(spec, policy)
    if options["json"]:
        _core.print_json({"name": spec.key, "title": spec.title, "state": state, "what": spec.what,
                          "words": [w for w in spec.words], "set_by_policy": bool(managed),
                          "tamper_protected": bool(status.get("IsTamperProtected")) if spec.tamper else False})
        return 0
    color = _net.GREEN if state not in ("off", "unknown") else _net.YELLOW
    print(color + f"{spec.title}: {state}" + _net.RESET)
    print(f"  it {spec.what}.")
    if managed:
        print(f"  A policy sets this ({managed}), so changes here may be refused.")
    if spec.tamper and status.get("IsTamperProtected"):
        print("  Tamper Protection is on: it can only be turned off in the Windows Security app (def open settings).")
    print(f"  change it: {spec.usage()}")
    return 0


def _set_switch(spec, word, options):
    """Set one protection to the value for `word`, then read back what Windows says."""
    word = word.lower()
    if word not in spec.words:
        raise DefenderError(f"usage: {spec.usage()}", 2)
    value = spec.words[word]
    _net.need_admin()
    reading = _read(["status", "prefs"])
    status, prefs = reading.row("status"), reading.row("prefs")
    old = spec.state(status, prefs)
    new = spec.word_of(value)
    if old == new:
        _say(options, f"{spec.title} is already {new}.")
        return 0
    hit = _policy_hit(spec, _policy_values())
    if hit:
        raise DefenderError(f"a policy sets {spec.title} ({POLICY_KEY}\\{hit}), so this PC will not take a change here. "
                            "Ask whoever manages it.")
    lowering = spec.lowers(old, new)
    if lowering and spec.tamper and status.get("IsTamperProtected"):
        raise DefenderError(f"Tamper Protection is on, and it stops anything but the Windows Security app from "
                            f"weakening {spec.title}. Turn Tamper Protection off there first ('def open settings'), "
                            "then run this again.")
    if lowering:
        if not _core.confirm(f"Turn {spec.title} {new}? {spec.risk} To undo: 'def {spec.key} {spec.on_word}'. [y/N]: ",
                             options["yes"]):
            _say(options, "cancelled")
            return 0
    elif spec.ask_on and new != "off":
        if not _core.confirm(f"Turn {spec.title} {new}? Apps Windows does not trust will be blocked from changing files "
                             "in Documents, Pictures, Videos, Music and Desktop, and a program you use may stop saving "
                             "there. To let one through: 'def folders allow <program.exe>'. To undo: 'def folders off'. "
                             "[y/N]: ", options["yes"]):
            _say(options, "cancelled")
            return 0
    _say(options, f"setting {spec.title} to {new}...")
    _win.powershell(f"Set-MpPreference -{spec.pref} {_ps_value(value)}")
    now_reading = _read(["status", "prefs"])
    now = spec.state(now_reading.row("status"), now_reading.row("prefs"))
    if options["json"]:
        _core.print_json({"name": spec.key, "requested": new, "state": now, "changed": now == new})
    elif now == new:
        print(f"{spec.title} is now {now}.")
    else:
        print(f"{spec.title} is still {now}: Windows did not accept the change.")
        if now_reading.row("status").get("IsTamperProtected"):
            print("  Tamper Protection is on. Change it in the Windows Security app: 'def open settings'.")
        elif _policy_values():
            print("  This PC has Defender policies, which may be holding it: 'def why' lists them.")
        elif now_reading.row("status").get("AMRunningMode") and any(
                w in str(now_reading.row("status").get("AMRunningMode")).lower() for w in PASSIVE_WORDS):
            print("  Defender is in passive mode because another antivirus is in charge.")
    return 0 if now == new else 1


def _switch_cmd(key, rest, options):
    spec = SWITCHES[key]
    if not rest:
        return _show_switch(spec, options)
    if len(rest) != 1:
        raise DefenderError(f"usage: {spec.usage()}", 2)
    return _set_switch(spec, rest[0], options)


def _on_off_cmd(rest, on, options):
    if len(rest) != 1 or rest[0].lower() not in SWITCHES:
        raise DefenderError(f"usage: def {'on' if on else 'off'} <{'|'.join(SWITCH_ORDER)}>", 2)
    spec = SWITCHES[rest[0].lower()]
    return _set_switch(spec, spec.on_word if on else spec.off_word, options)


def _tamper_cmd(options):
    status = _read(["status"]).row("status")
    state = _onoff(status.get("IsTamperProtected"))
    if options["json"]:
        _core.print_json({"state": state, "source": status.get("TamperProtectionSource")})
        return 0
    print(f"tamper protection: {state}")
    print("  It stops other programs, scripts and the registry from turning off real-time, behaviour, download and "
          "cloud protection.")
    print("  It can only be changed in the Windows Security app, on purpose: 'def open settings' opens it.")
    return 0


# ======================================================================
# LISTS — exclusions, controlled folder access, attack surface reduction
# ======================================================================
KIND_PARAMS = {"path": ("ExclusionPath", "folder or file"), "ext": ("ExclusionExtension", "extension"),
               "process": ("ExclusionProcess", "process")}
KIND_WORDS = {"path": "path", "folder": "path", "file": "path", "dir": "path", "ext": "ext", "extension": "ext",
              "process": "process", "proc": "process", "exe": "process"}


def _exclusion_rows(reading):
    """Every exclusion, paths then extensions then processes, numbered from 1. None if Windows hides the list."""
    row = reading.row("exclusions")
    lists = {kind: _list(row.get(param)) for kind, (param, _) in KIND_PARAMS.items()}
    if any(_hidden(items) for items in lists.values()):
        return None
    rows = []
    for kind in KIND_PARAMS:
        for value in sorted(lists[kind], key=str.lower):
            rows.append({"kind": kind, "value": value})
    for number, item in enumerate(rows, start=1):
        item["id"] = number
    return rows


def _exclusions_cmd(words, options):
    if words and words[0].lower() == "add":
        return _exclusion_add(words[1:], options)
    if words and words[0].lower() in REMOVE_WORDS:
        return _exclusion_remove(words[1:], options)
    if words:
        raise DefenderError("usage: def exclusions [add path|ext|process <value> | rm <id>]", 2)
    reading = _read(["exclusions"])
    rows = _exclusion_rows(reading) if not reading.failed("exclusions") else None
    if rows is None:
        why = "needs administrator rights" if not _core.is_admin() else "hidden by a policy"
        if options["json"]:
            _core.print_json({"hidden": why, "exclusions": []})
        else:
            print(f"the exclusion list is not available: Windows keeps it from this terminal ({why}).")
        return 0
    if options["json"]:
        _core.print_json({"hidden": None, "exclusions": rows})
        return 0
    if not rows:
        print(_net.GREEN + "no exclusions: Defender looks everywhere." + _net.RESET)
        return 0
    print(f"{'ID':<5}{'KIND':<16}EXCLUDED")
    for row in rows:
        print(f"{row['id']:<5}{KIND_PARAMS[row['kind']][1]:<16}{row['value']}")
    print("\nAn exclusion is a place Defender does not look. 'def exclusions rm <id>' removes one.")
    return 0


def _exclusion_add(words, options):
    if len(words) < 2 or words[0].lower() not in KIND_WORDS:
        raise DefenderError("usage: def exclusions add path|ext|process <value>", 2)
    kind, value = KIND_WORDS[words[0].lower()], " ".join(words[1:]).strip().strip('"')
    if not value or any(ord(ch) < 32 for ch in value):
        raise DefenderError("that value is empty or has control characters", 2)
    if kind == "ext":
        value = "." + value.lstrip(".").lower()
        if not re.fullmatch(r"\.[A-Za-z0-9_-]{1,20}", value):
            raise DefenderError("an extension is letters and digits, such as .iso", 2)
    risky = (kind == "ext" and value in RISKY_EXTENSIONS) or (kind == "path" and _is_broad(value)) or \
        (kind == "process" and value in ("*", "*.exe"))
    _net.need_admin()
    parameter, label = KIND_PARAMS[kind]
    if not _core.confirm(f"Exclude {label} '{value}' from scanning? Defender will not look there, and malware can hide in "
                         f"an excluded place. To undo: 'def exclusions rm <id>' (see 'def exclusions'). [y/N]: ",
                         options["yes"]):
        _say(options, "cancelled")
        return 0
    if risky and not _core.confirm(f"'{value}' covers a lot: a whole drive, a system folder, or a kind of file that "
                                   "programs run from. Malware loves that. Exclude it anyway? [y/N]: ", options["yes"]):
        _say(options, "cancelled")
        return 0
    _say(options, f"excluding {value}...")
    _win.powershell(f"Add-MpPreference -{parameter} $env:W11_VALUE", env={"W11_VALUE": value})
    rows = _exclusion_rows(_read(["exclusions"])) or []
    found = next((r for r in rows if r["kind"] == kind and r["value"].lower() == value.lower()), None)
    if options["json"]:
        _core.print_json({"added": bool(found), "exclusion": found})
    elif found:
        print(f"excluded: {label} '{found['value']}' (id {found['id']}).")
    else:
        _say(options, "Windows did not list the exclusion afterwards. Tamper Protection or a policy may be blocking it.")
    return 0 if found else 1


def _exclusion_remove(words, options):
    if len(words) != 1 or not _isnum(words[0]):
        raise DefenderError("usage: def exclusions rm <id>", 2)
    _net.need_admin()
    rows = _exclusion_rows(_read(["exclusions"]))
    if rows is None:
        raise DefenderError("Windows hides the exclusion list from this terminal (a policy may be hiding it)")
    row = next((r for r in rows if r["id"] == int(words[0])), None)
    if row is None:
        raise DefenderError(f"no exclusion with id {words[0]}. Run 'def exclusions' to see them.", 2)
    parameter, label = KIND_PARAMS[row["kind"]]
    _say(options, f"removing the exclusion for {row['value']}...")
    _win.powershell(f"Remove-MpPreference -{parameter} $env:W11_VALUE", env={"W11_VALUE": row["value"]})
    left = _exclusion_rows(_read(["exclusions"])) or []
    gone = not any(r["kind"] == row["kind"] and r["value"] == row["value"] for r in left)
    if options["json"]:
        _core.print_json({"removed": gone, "exclusion": row})
    else:
        print(f"{label} '{row['value']}' is {'no longer excluded' if gone else 'still excluded'}.")
    return 0 if gone else 1


def _folders_cmd(words, options):
    if words and words[0].lower() in SWITCHES["folders"].words:
        return _set_switch(SWITCHES["folders"], words[0], options)
    if words:
        return _folders_change(words, options)
    reading = _read(["status", "prefs", "folders"])
    state = SWITCHES["folders"].state(reading.row("status"), reading.row("prefs"))
    row = reading.row("folders")
    protected = _list(row.get("ControlledFolderAccessProtectedFolders"))
    allowed = _list(row.get("ControlledFolderAccessAllowedApplications"))
    if options["json"]:
        _core.print_json({"state": state, "protected_folders": protected, "allowed_apps": allowed})
        return 0
    _net.render(f"controlled folder access: {state}", [
        ("guarded", [("always", "Documents, Pictures, Videos, Music, Desktop"), ("added by you", protected or "none")]),
        ("trusted apps", [("added by you", allowed or "none")]),
        ("change it with", [("def folders on|off|audit", "turn it on, off, or log without blocking"),
                            ("def folders add <dir> | rm <dir>", "guard another folder"),
                            ("def folders allow <app.exe> | disallow <app.exe>", "let one program through")]),
    ])
    return 0


def _folders_change(words, options):
    word = words[0].lower()
    if len(words) < 2 or word not in ("add", "rm", "remove", "allow", "disallow"):
        raise DefenderError("usage: def folders [on|off|audit | add <dir> | rm <dir> | allow <app.exe> | disallow <app.exe>]", 2)
    target = " ".join(words[1:]).strip('"')
    if word in ("add", "rm", "remove"):
        parameter, adding, lowers = "ControlledFolderAccessProtectedFolders", word == "add", word != "add"
        if adding and not os.path.isdir(target):
            raise DefenderError(f"'{target}' is not a folder that exists", 2)
    else:
        parameter, adding, lowers = "ControlledFolderAccessAllowedApplications", word == "allow", word == "allow"
        if adding and not (target.lower().endswith(".exe") and os.path.isfile(target)):
            raise DefenderError(f"'{target}' is not a program (.exe) that exists", 2)
    _net.need_admin()
    if lowers and not _core.confirm(
            f"{'Let ' + target + ' change files in the guarded folders' if adding else 'Stop guarding ' + target}? "
            "That weakens ransomware protection for it. To undo: "
            f"'def folders {'disallow' if adding else 'add'} {target}'. [y/N]: ", options["yes"]):
        _say(options, "cancelled")
        return 0
    verb = "Add" if adding else "Remove"
    _win.powershell(f"{verb}-MpPreference -{parameter} $env:W11_VALUE", env={"W11_VALUE": target})
    row = _read(["folders"]).row("folders")
    present = target.lower() in [item.lower() for item in _list(row.get(parameter))]
    ok = present == adding  # adding: wants it listed; removing: wants it gone
    if options["json"]:
        _core.print_json({"target": target, "listed": present, "ok": ok})
    else:
        print({(True, True): f"{target} is now listed.", (True, False): f"{target} is still not listed.",
               (False, True): f"{target} is no longer listed.", (False, False): f"{target} is still listed."}[(adding, ok)])
    return 0 if ok else 1


def _asr_rows(reading):
    """The documented rules (in Microsoft's order, numbered from 1), plus any other rule configured on this PC."""
    row = reading.row("asr")
    ids = [item.lower() for item in _list(row.get("AttackSurfaceReductionRules_Ids"))]
    actions = row.get("AttackSurfaceReductionRules_Actions")
    actions = actions if isinstance(actions, list) else ([] if actions is None else [actions])
    configured = dict(zip(ids, actions))
    rows = [{"guid": guid, "name": name, "mode": ASR_MODES.get(configured.get(guid), "not set")} for guid, name in ASR_RULES]
    known = {guid for guid, _ in ASR_RULES}
    rows += [{"guid": guid, "name": "(a rule this page does not know)", "mode": ASR_MODES.get(act, str(act))}
             for guid, act in configured.items() if guid not in known]
    for number, item in enumerate(rows, start=1):
        item["id"] = number
    return rows


def _asr_cmd(words, options):
    if words and (len(words) != 2 or not _isnum(words[0]) or words[1].lower() not in (*ASR_WORDS, "unset")):
        raise DefenderError("usage: def asr [<n> block|audit|warn|off|unset]", 2)
    if words:
        _net.need_admin()
    reading = _read(["asr"])
    rows = _asr_rows(reading)
    if words:
        return _asr_change(rows, int(words[0]), words[1].lower(), options)
    if options["json"]:
        _core.print_json({"rules": rows})
        return 0
    print(f"{'ID':<5}{'MODE':<10}RULE")
    for row in rows:
        color = {"block": _net.GREEN, "audit": _net.CYAN, "warn": _net.CYAN}.get(row["mode"], _net.GREY)
        print(color + f"{row['id']:<5}{row['mode']:<10}{row['name']}" + _net.RESET)
    print("\nChange one: def asr <id> block|audit|warn|off|unset. Try audit first: it logs what block would stop.")
    return 0


def _asr_change(rows, number, word, options):
    row = next((r for r in rows if r["id"] == number), None)
    if row is None:
        raise DefenderError(f"no rule with id {number}. Run 'def asr' to see them.", 2)
    new_mode = "not set" if word == "unset" else ("block" if word == "on" else word)
    weaker = ASR_STRENGTH.get(new_mode, 0) < ASR_STRENGTH.get(row["mode"], 0)
    if (weaker or word in ("off", "unset", "block", "on")) and not _core.confirm(
            f"Set '{row['name']}' to {word}? "
            + ("Defender guards less against this. " if weaker or word in ("off", "unset") else
               "Block mode can stop programs you use from working; audit mode only logs. ")
            + f"To undo: 'def asr {number} {row['mode'] if row['mode'] != 'not set' else 'unset'}'. [y/N]: ", options["yes"]):
        _say(options, "cancelled")
        return 0
    env = {"W11_GUID": row["guid"]}
    if word == "unset":
        _win.powershell("Remove-MpPreference -AttackSurfaceReductionRules_Ids $env:W11_GUID", env=env)
    else:
        _win.powershell("Add-MpPreference -AttackSurfaceReductionRules_Ids $env:W11_GUID "
                        f"-AttackSurfaceReductionRules_Actions {ASR_WORDS[word]}", env=env)
    now = next((r for r in _asr_rows(_read(["asr"])) if r["guid"] == row["guid"]), row)
    wanted = "not set" if word == "unset" else ("block" if word == "on" else word)
    if options["json"]:
        _core.print_json({"rule": now, "requested": wanted, "changed": now["mode"] == wanted})
    else:
        print(f"'{now['name']}' is now {now['mode']}.")
    return 0 if now["mode"] == wanted else 1


# ======================================================================
# SCHEDULE AND CPU
# ======================================================================
def _schedule_cmd(words, options):
    if not words:
        schedule = _schedule(_read(["prefs"]).row("prefs"))
        if options["json"]:
            _core.print_json(schedule)
            return 0
        print(f"scheduled scan: {schedule['day'] or 'not set'} at {(schedule['time'] or '?')[:5]}, "
              f"{schedule['type'] or 'scan'}")
        print("change it: def schedule day sun|mon|...|every|never time 02:00 type quick|full")
        print("The PC has to be on at that time (Windows catches a missed scan up later).")
        return 0
    changes, i = {}, 0
    while i < len(words):
        key, value = words[i].lower(), words[i + 1].lower() if i + 1 < len(words) else None
        if key == "day" and value in DAY_WORDS:
            changes["ScanScheduleDay"] = DAY_WORDS[value]
        elif key == "time" and value and re.fullmatch(r"([01]?\d|2[0-3]):[0-5]\d", value):
            changes["ScanScheduleTime"] = "'" + value.zfill(5) + ":00'"
        elif key == "type" and value in SCAN_TYPES:
            changes["ScanParameters"] = SCAN_TYPES[value]
        else:
            raise DefenderError("usage: def schedule [day sun..sat|every|never] [time HH:MM] [type quick|full]", 2)
        i += 2
    _net.need_admin()
    if changes.get("ScanScheduleDay") == 8 and not _core.confirm(
            "Stop the scheduled scan? Defender will only scan when you ask. To undo: 'def schedule day every'. [y/N]: ",
            options["yes"]):
        _say(options, "cancelled")
        return 0
    _win.powershell("Set-MpPreference " + " ".join(f"-{name} {value}" for name, value in changes.items()))
    schedule = _schedule(_read(["prefs"]).row("prefs"))
    if options["json"]:
        _core.print_json(schedule)
    else:
        print(f"scheduled scan is now: {schedule['day'] or 'not set'} at {(schedule['time'] or '?')[:5]}, "
              f"{schedule['type'] or 'scan'}.")
    return 0


def _cpu_cmd(words, options):
    if len(words) > 1 or (words and not (_isnum(words[0]) and (int(words[0]) == 0 or 5 <= int(words[0]) <= 100))):
        raise DefenderError("usage: def cpu [0|5-100]   (0 means no limit)", 2)
    if words:
        _net.need_admin()
        _win.powershell(f"Set-MpPreference -ScanAvgCPULoadFactor {int(words[0])}")
    value = _read(["prefs"]).row("prefs").get("ScanAvgCPULoadFactor")
    if options["json"]:
        _core.print_json({"percent": value})
    else:
        print(f"a scan may use about {value}% of the CPU on average" if value else "scans have no CPU limit")
        if not words:
            print("change it: def cpu <5-100>, or def cpu 0 for no limit. It is a target, and scans that run while "
                  "the PC is idle ignore it.")
    return 0


# ======================================================================
# READ-ONLY VIEWS — SmartScreen, device security, offline scan, and opening the Security app
# ======================================================================
def _sac_word(registry_value, text):
    if text:
        return str(text).lower()
    return {0: "off", 1: "on", 2: "evaluation"}.get(registry_value, "not available")


def _smartscreen_cmd(options):
    apps = _net.reg_read(EXPLORER_KEY, "SmartScreenEnabled")
    enable = _net.reg_read(SMARTSCREEN_POLICY_KEY, "EnableSmartScreen")
    level = _net.reg_read(SMARTSCREEN_POLICY_KEY, "ShellSmartScreenLevel")
    edge = _net.reg_read(EDGE_POLICY_KEY, "SmartScreenEnabled")
    store = _net.reg_read(APPHOST_KEY, "EnableWebContentEvaluation", hive=_win.HKCU)
    sac_value = _net.reg_read(SAC_KEY, "VerifiedAndReputablePolicyState")
    reading = _read(["status", "prefs"])
    pua = SWITCHES["pua"].state(reading.row("status"), reading.row("prefs"))
    data = {
        "apps_and_files": str(apps).lower() if apps else "not set",
        "apps_and_files_policy": {"enabled": enable, "level": str(level).lower() if level else None},
        "edge_policy": edge, "store_apps": {1: "on", 0: "off"}.get(store, "not set"), "unwanted_apps": pua,
        "smart_app_control": _sac_word(sac_value, reading.row("status").get("SmartAppControlState")),
    }
    if options["json"]:
        _core.print_json(data)
        return 0
    policy_note = "set by policy" if enable is not None else "your setting"
    _net.render("SmartScreen and Smart App Control (read only)", [
        ("reputation-based protection", [
            ("check apps and files", f"{data['apps_and_files']} ({policy_note})"),
            ("Microsoft Edge", "set by policy: " + ("on" if edge else "off") if edge is not None else "set inside Edge"),
            ("Microsoft Store apps", data["store_apps"]), ("unwanted apps", pua)]),
        ("smart app control", [("state", data["smart_app_control"]),
                               ("note", "Windows 11 only: allows apps with a good reputation or a trusted signature")]),
        ("change it", [("def open browser", "opens App & browser control in the Windows Security app")]),
    ])
    return 0


def _device_cmd(options):
    reading = _read(["deviceguard"] + (["tpm"] if _core.is_admin() else []))
    guard = reading.row("deviceguard")
    running = [int(x) for x in _list(guard.get("Running")) if _isnum(str(x))]
    secure = _net.reg_read(SECURE_BOOT_KEY, "UEFISecureBootEnabled")
    hvci_key = _net.reg_read(HVCI_KEY, "Enabled")
    tpm = reading.row("tpm") if _core.is_admin() else None
    data = {
        "memory_integrity": "on" if 2 in running else ("off" if guard else "unknown"),
        "memory_integrity_setting": hvci_key,
        "virtualisation_based_security": {0: "off", 1: "enabled, not running", 2: "running"}.get(
            guard.get("VirtualizationBasedSecurityStatus"), "unknown"),
        "credential_guard": "running" if 1 in running else "not running",
        "secure_boot": "on" if secure == 1 else ("off" if secure == 0 else "not available (not a UEFI PC?)"),
        "tpm": (("present" if tpm.get("TpmPresent") else "not found") + (", ready" if tpm.get("TpmReady") else ""))
        if tpm else "needs administrator rights",
    }
    if options["json"]:
        _core.print_json(data)
        return 0
    _net.render("device security (read only)", [
        ("core isolation", [("memory integrity", data["memory_integrity"]),
                            ("virtualisation-based security", data["virtualisation_based_security"]),
                            ("credential guard", data["credential_guard"])]),
        ("hardware", [("secure boot", data["secure_boot"]), ("TPM", data["tpm"])]),
        ("change it", [("def open device", "turn memory integrity on in the Windows Security app"),
                       ("hw firmware", "Secure Boot and the TPM in detail (needs administrator for the TPM)")]),
    ])
    return 0


def _offline_cmd(options):
    _net.need_admin()
    if not _core.confirm("Run a Microsoft Defender Offline scan? Windows RESTARTS THIS PC immediately, with no chance to "
                         "cancel, and scans before Windows starts. Unsaved work is lost. It needs Windows Defender to be "
                         "the active antivirus and the Windows Recovery Environment to be on. [y/N]: ", options["yes"]):
        _say(options, "cancelled")
        return 0
    if not _core.confirm("Are you sure? Save and close everything first. Restart and scan now? [y/N]: ", options["yes"]):
        _say(options, "cancelled")
        return 0
    _say(options, "starting the offline scan: the PC restarts now...")
    _win.powershell("Start-MpWDOScan", timeout=120)
    return 0


def _open_page(target, options):
    if target not in OPEN_TARGETS:
        raise DefenderError("usage: def open [" + "|".join(OPEN_TARGETS) + "]", 2)
    uri, label = OPEN_TARGETS[target]
    try:
        _win.open_settings(uri)
        used = uri
    except _net.NetError:
        _win.open_settings(SETTINGS_FALLBACK)
        used = SETTINGS_FALLBACK
    if options["json"]:
        _core.print_json({"opened": used, "page": label})
    else:
        print(f"opened {label}." + (" (the Security app's own link did not open, so this is the Settings page)"
                                     if used == SETTINGS_FALLBACK else ""))
    return 0


# ======================================================================
# COMMAND — app.py calls run(args) with everything after "defender"/"def"/"av"/"wd"
# ======================================================================
def run(args):
    os.system("")  # enables ANSI colour codes in the Windows console
    args, options = _core.split_flags(args)
    wait = any(arg.lower() == "--wait" for arg in args)
    args = [arg for arg in args if arg.lower() != "--wait"]
    if not args:
        args = ["status"]
    elif args[0].lower() in _core.HELP_WORDS:
        print(f"usage: {USAGE}")
        return 0
    word, rest = args[0].lower(), args[1:]
    try:
        if word == "status" and not rest:
            return _status_cmd(options)
        if word == "why" and not rest:
            return _why_cmd(options)
        if word == "scan":
            return _scan_cmd(rest, options, wait)
        if word == "scans":
            return _scans_cmd(rest, options)
        if word in ("update", "signatures") and not rest:
            return _update_cmd(options)
        if word == "threats":
            return _threats_cmd(rest, options)
        if word in ("quarantine", "q"):
            return _quarantine_cmd(rest, options)
        if word == "clean" and not rest:
            return _clean_cmd(options)
        if word in ("on", "off"):
            return _on_off_cmd(rest, word == "on", options)
        if word == "folders":
            return _folders_cmd(rest, options)
        if word in SWITCHES:
            return _switch_cmd(word, rest, options)
        if word == "tamper" and not rest:
            return _tamper_cmd(options)
        if word in ("exclusions", "exclusion", "exclude"):
            return _exclusions_cmd(rest, options)
        if word == "schedule":
            return _schedule_cmd(rest, options)
        if word == "cpu":
            return _cpu_cmd(rest, options)
        if word == "asr":
            return _asr_cmd(rest, options)
        if word == "smartscreen" and not rest:
            return _smartscreen_cmd(options)
        if word == "device" and not rest:
            return _device_cmd(options)
        if word == "events":
            return _events_cmd(rest, options)
        if word == "offline" and not rest:
            return _offline_cmd(options)
        if word == "open" and len(rest) <= 1:
            return _open_page(rest[0].lower() if rest else "app", options)
        raise DefenderError(f"usage: {USAGE}", 2)
    except (DefenderError, _net.NetError) as e:
        print(f"error: {e}", file=sys.stderr)
        return e.code


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
