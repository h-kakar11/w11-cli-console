"""
update: Windows Update, read and changed from the command line. Routed from app.py
("update", "wu", "winupdate" or "updates").

    wu                           status: version, last check, restart pending, services, pause, who manages updates
    wu ls | check                search for pending updates (takes up to a minute), numbered
    wu <id|KB>                   one pending update in full
    wu install <id|KB>... | all | drivers
                                 download and install (administrator; asks first; never restarts the PC)
    wu history [n] [all]         recent installs, with the result and the reason for a failure
    wu failed [n]                only the failures, with their codes
    wu installed                 updates Windows lists as installed
    wu hide <id|KB> | unhide <id|KB|all> | hidden
                                 keep an update from being offered (administrator), and bring it back
    wu uninstall <KB>            remove an installed update (administrator; asks first)
    wu pause [days] | resume     pause updates for up to 35 days (administrator; a policy, see below)
    wu options                   active hours, optional updates, restart notices and the rest, in words
    wu options microsoft on|off  updates for other Microsoft products (administrator)
    wu drivers [on|off]          whether Windows Update includes drivers (administrator)
    wu services                  the services Windows Update runs on
    wu why                       why updates are stuck or failing, and the command that fixes each cause
    wu open [page]               open the Settings page (history, options, optional, restart, delivery)

Status, history, services and why need no administrator rights. Searching for updates needs none either.
Installing, uninstalling, hiding, pausing and the options that change something need an administrator terminal,
and each checks that before it asks anything. Updates are found, downloaded and installed through the Windows
Update Agent (the COM API Windows Update itself uses), from PowerShell. Ids are numbered by title from the last
search, and every action searches again and matches by the update's own id, so a shifted id can never install
the wrong update. A KB number works in place of an id.

Pausing uses the documented Windows Update for Business policy (a start date; Windows adds 35 days to it), not
the private values Settings keeps. Settings may therefore say "some settings are managed by your organization".
This page never restarts the PC: it says when a restart is needed.
"""

import contextlib
import os
import re
import shutil
import subprocess
import sys
import winreg
from datetime import datetime, timedelta, timezone

import _core
import _net
import _win

# ======================================================================
# SETTING INFO — read by app.py to list and route this setting
# ======================================================================
NAME = "update"
ALIASES = ["wu", "winupdate", "updates"]
SUMMARY = "Windows Update: pending, history, install and pause"
# extra words people use, for 'settings search'
KEYWORDS = ["windows update", "patch", "kb", "pending", "pause updates", "restart", "driver update", "hotfix",
            "stuck"]
USAGE = ("wu | wu ls | wu <id|KB> | wu install <id>|all|drivers | wu history [n] | wu failed | wu installed | "
         "wu hide|unhide <id> | wu hidden | wu uninstall <KB> | wu pause [days] | wu resume | wu options | "
         "wu drivers [on|off] | wu services | wu why | wu open [page]")
HELP = [
    ("wu", "status: Windows version, last check, restart pending, and whether anything is wrong"),
    ("wu ls", "search for pending updates, numbered (takes up to a minute)"),
    ("wu install <id>|all", "download and install updates (administrator; asks first; never restarts)"),
    ("wu history", "recent installs, and whether they worked"),
    ("wu why", "updates stuck or failing: what is wrong, and the command that fixes it"),
    ("wu pause [days]", "pause updates for up to 35 days; 'wu resume' ends it (administrator)"),
    ("", "more"),
    ("wu <id>", "one pending update: size, KB, severity, whether it needs a restart"),
    ("wu install drivers", "install the driver updates Windows offers (optional updates need their ids)"),
    ("wu failed", "only the failures, with their codes explained"),
    ("wu installed", "updates Windows lists as installed"),
    ("wu hide <id> | unhide | hidden", "keep an update from being offered, and bring it back (administrator)"),
    ("wu uninstall <KB>", "remove an installed update (administrator; asks first)"),
    ("wu options", "active hours, optional updates, restart notices, Delivery Optimization, in words"),
    ("wu options microsoft on|off", "updates for other Microsoft products (administrator)"),
    ("wu drivers on|off", "whether Windows Update includes drivers (administrator)"),
    ("wu services", "the services Windows Update runs on, and whether they are healthy"),
    ("wu open [page]", "open Settings: history, options, optional, restart or delivery"),
]
TIP = ("Ids come from the last 'wu ls' and every action matches by the update's own id, so a shifted id never "
       "installs the wrong update; a KB number (wu install KB5031356) always works. This page never restarts the PC.")
RUN_ALONE = True  # typing 'wu' on its own shows the status, which reads local state and changes nothing

# ======================================================================
# CONSTANTS
# ======================================================================
SETTINGS_PAGES = {  # 'wu open <page>'
    "": "ms-settings:windowsupdate", "history": "ms-settings:windowsupdate-history",
    "options": "ms-settings:windowsupdate-options", "optional": "ms-settings:windowsupdate-optionalupdates",
    "restart": "ms-settings:windowsupdate-restartoptions", "delivery": "ms-settings:delivery-optimization",
}
NT_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
AU_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update"
CBS_PENDING_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
SESSION_KEY = r"SYSTEM\CurrentControlSet\Control\Session Manager"
UX_KEY = r"SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"  # where Settings keeps its own choices: read only here
POLICY_KEY = r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
POLICY_AU_KEY = POLICY_KEY + r"\AU"
DELIVERY_POLICY_KEY = r"SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
SERVICES_KEY = r"SYSTEM\CurrentControlSet\Services"

SERVICES = [  # (service name, name people know, what it does)
    ("wuauserv", "Windows Update", "searches for, downloads and installs updates"),
    ("UsoSvc", "Update Orchestrator", "decides when scans, downloads and restarts happen"),
    ("BITS", "Background Intelligent Transfer", "downloads update files quietly in the background"),
    ("DoSvc", "Delivery Optimization", "fetches update files, also from other PCs"),
    ("cryptsvc", "Cryptographic Services", "checks that updates are signed"),
]
START_WORDS = {0: "boot", 1: "system", 2: "automatic", 3: "manual", 4: "disabled"}

PENDING = "IsInstalled=0 and IsHidden=0"  # the WUA search criteria this page uses (fixed text, never user input)
HIDDEN = "IsInstalled=0 and IsHidden=1"
SEARCH_TIMEOUT = 600
STATUS_TIMEOUT = 120
LONG_TIMEOUT = 4 * 3600  # downloads and installs can take hours
LIST_FRESH_HOURS = 6  # a saved 'wu ls' list is trusted for ids this long
STALE_CHECK_DAYS = 7
LOW_SPACE_GB, VERY_LOW_SPACE_GB = 10, 3
HISTORY_DEFAULT, HISTORY_MAX = 20, 500
PAUSE_DAYS = 35  # Windows adds 35 days to the pause start date, so this is the longest pause
PAUSE_NAMES = ("PauseFeatureUpdatesStartTime", "PauseQualityUpdatesStartTime")
DRIVER_POLICY = "ExcludeWUDriversInQualityUpdate"  # 1 = Windows Update leaves drivers out
MICROSOFT_UPDATE = "7971f918-a847-4430-9279-4a52d1efe18d"  # "Microsoft Update": updates for Office and other Microsoft products
POLICY_RECORD = "update-policy.json"  # what 'wu pause' and 'wu drivers' wrote, so 'wu resume' removes exactly that
# The Windows Update Agent writes history times and the "last search" times without saying which zone they are in.
# They are read as UTC, the way the registry's LastSuccessTime values are documented. If Settings > Windows Update >
# Update history shows a different hour for the same update, flip these.
HISTORY_IS_UTC = True
COM_DATES_ARE_UTC = True

RESULT_WORDS = {0: "not started", 1: "in progress", 2: "succeeded", 3: "succeeded with errors", 4: "failed",
                5: "cancelled"}
OPERATION_WORDS = {1: "install", 2: "uninstall"}
REBOOT_WORDS = {0: "never", 1: "always", 2: "maybe"}  # InstallationBehavior.RebootBehavior
KB_WORD = re.compile(r"^(?:kb)?(\d{6,8})$", re.IGNORECASE)
KB_IN_TITLE = re.compile(r"\((KB\d{6,8})\)", re.IGNORECASE)
GUID = re.compile(r"^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$", re.IGNORECASE)
HEX_CODE = re.compile(r"(?<![0-9A-Fa-f])(?:0x)?([0-9A-Fa-f]{8})(?![0-9A-Fa-f])")

# Plain words for the codes people actually meet (Windows Update Agent and Win32 codes, as unsigned numbers)
HRESULT_TEXT = {
    0x80240016: "another install is running, or Windows is waiting for a restart before it can install",
    0x80240017: "the update does not apply to this PC",
    0x80240022: "every update in the batch failed",
    0x8024001E: "the service or the PC was shutting down, so the operation did not finish",
    0x80240020: "no one is signed in at the desktop, so Windows could not finish",
    0x8024000B: "the operation was cancelled",
    0x80240034: "the update failed to download",
    0x80240FFF: "Windows Update hit a problem it has no code for",
    0x8024402C: "Windows could not look up the update server's name (a proxy or DNS problem)",
    0x80244022: "the update server was busy (HTTP 503); try again later",
    0x80240438: "there is no network route to the update server",
    0x80248007: "Windows Update's local database is missing information it needs",
    0x80070005: "access was denied",
    0x80070070: "the disk is full",
    0x80070422: "the Windows Update service is turned off (disabled)",
    0x80073712: "Windows' component store is damaged",
    0x800F0922: "Windows could not finish installing the update's parts (often low space on the system "
                "partition, or a VPN in use)",
    0x800F081F: "Windows could not find the files it needs to finish the update",
    0x80072EE2: "the connection to the update server timed out",
    0x80072EE7: "the update server's name could not be found (check the network and DNS)",
    0x80072EFD: "Windows could not connect to the update server",
    0x80072F8F: "a secure connection failed (often the PC's date and time are wrong)",
}
POLICY_TEXT = {  # update policy values people meet, in plain words (anything else is shown by its name)
    "WUServer": "updates come from your organisation's update server",
    "WUStatusServer": "update reports go to your organisation's server",
    "UseWUServer": "Windows uses an update server instead of Microsoft's",
    "NoAutoUpdate": "automatic updates are turned off",
    "AUOptions": "the automatic update mode is set",
    "ScheduledInstallDay": "the install day is set",
    "ScheduledInstallTime": "the install time is set",
    "NoAutoRebootWithLoggedOnUsers": "no automatic restart while someone is signed in",
    "DisableWindowsUpdateAccess": "access to Windows Update is blocked",
    "SetDisableUXWUAccess": "the Windows Update page in Settings is limited",
    "DoNotConnectToWindowsUpdateInternetLocations": "Windows Update on the internet is not used",
    "DeferFeatureUpdates": "feature updates are delayed",
    "DeferFeatureUpdatesPeriodInDays": "feature updates are delayed by a number of days",
    "DeferQualityUpdates": "quality updates are delayed",
    "DeferQualityUpdatesPeriodInDays": "quality updates are delayed by a number of days",
    "PauseFeatureUpdatesStartTime": "feature updates are paused from a start date",
    "PauseQualityUpdatesStartTime": "quality updates are paused from a start date",
    "BranchReadinessLevel": "the servicing channel is set",
    "TargetReleaseVersion": "the Windows version is pinned",
    "TargetReleaseVersionInfo": "the Windows version Windows stays on",
    "ProductVersion": "the product Windows stays on",
    "SetActiveHours": "active hours are set",
    "ActiveHoursStart": "active hours start",
    "ActiveHoursEnd": "active hours end",
    DRIVER_POLICY: "drivers are left out of Windows Update",
}
DELIVERY_MODES = {
    0: "only from Microsoft (no sharing with other PCs)", 1: "from Microsoft and PCs on your local network",
    2: "from Microsoft and PCs in your group", 3: "from Microsoft and PCs on the internet",
    99: "simple mode (no peer-to-peer)", 100: "bypass (downloaded directly by the background transfer service)",
}


class UpdateError(Exception):
    """An error with an exit code: 1 for system errors, 2 for bad usage."""

    def __init__(self, message, code=1):
        super().__init__(message)
        self.code = code


# ======================================================================
# POWERSHELL — the Windows Update Agent (COM). Values reach the scripts through the environment, never the text.
# ======================================================================
# Local state only: when Windows last searched and installed, whether it wants a restart, and recent history
PS_STATUS = r"""
$out = [ordered]@{}
try {
    $au = New-Object -ComObject Microsoft.Update.AutoUpdate
    $out.LastSearch = $au.Results.LastSearchSuccessDate
    $out.LastInstall = $au.Results.LastInstallationSuccessDate
} catch { $out.AutoUpdateError = $_.Exception.Message }
try {
    $out.RebootRequired = [bool](New-Object -ComObject Microsoft.Update.SystemInfo).RebootRequired
} catch { $out.SystemInfoError = $_.Exception.Message }
try {
    $searcher = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
    $total = $searcher.GetTotalHistoryCount()
    $take = [Math]::Min($total, 60)
    $rows = @()
    if ($take -gt 0) {
        foreach ($h in $searcher.QueryHistory(0, $take)) {
            $rows += [pscustomobject]@{ Date = $h.Date; Title = [string]$h.Title; ResultCode = [int]$h.ResultCode;
                HResult = [int]$h.HResult; Operation = [int]$h.Operation }
        }
    }
    $out.History = $rows
} catch { $out.HistoryError = $_.Exception.Message }
[pscustomobject]$out
"""
# W11_CRITERIA: a fixed search criteria string from this file. Every field a person might want is read here once.
PS_SEARCH = r"""
$session = New-Object -ComObject Microsoft.Update.Session
$session.ClientApplicationID = 'w11-cli-console'
$found = $session.CreateUpdateSearcher().Search($env:W11_CRITERIA)
foreach ($u in $found.Updates) {
    $kb = @(); foreach ($k in $u.KBArticleIDs) { $kb += [string]$k }
    $cats = @(); foreach ($c in $u.Categories) { $cats += [string]$c.Name }
    $urls = @(); foreach ($m in $u.MoreInfoUrls) { $urls += [string]$m }
    $row = [ordered]@{
        UpdateID = [string]$u.Identity.UpdateID; Revision = [int]$u.Identity.RevisionNumber; Title = [string]$u.Title
        KB = $kb; Categories = $cats; MaxSize = [double]$u.MaxDownloadSize; MinSize = [double]$u.MinDownloadSize
        Severity = [string]$u.MsrcSeverity; Type = [int]$u.Type; BrowseOnly = [bool]$u.BrowseOnly
        Downloaded = [bool]$u.IsDownloaded; Hidden = [bool]$u.IsHidden; Eula = [bool]$u.EulaAccepted
        Mandatory = [bool]$u.IsMandatory; Reboot = [int]$u.InstallationBehavior.RebootBehavior
        Uninstallable = [bool]$u.IsUninstallable; Description = [string]$u.Description
        SupportUrl = [string]$u.SupportUrl; MoreInfo = $urls; ReleaseNotes = [string]$u.ReleaseNotes
    }
    if ([int]$u.Type -eq 2) {
        $row.DriverManufacturer = [string]$u.DriverManufacturer; $row.DriverModel = [string]$u.DriverModel
        $row.DriverClass = [string]$u.DriverClass; $row.DriverProvider = [string]$u.DriverProvider
        $row.DriverVerDate = $u.DriverVerDate
    }
    [pscustomobject]$row
}
"""
# W11_COUNT: how many history entries, newest first
PS_HISTORY = r"""
$searcher = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
$total = $searcher.GetTotalHistoryCount()
$take = [Math]::Min($total, [int]$env:W11_COUNT)
if ($take -gt 0) {
    foreach ($h in $searcher.QueryHistory(0, $take)) {
        [pscustomobject]@{ Date = $h.Date; Title = [string]$h.Title; ResultCode = [int]$h.ResultCode
            HResult = [int]$h.HResult; Operation = [int]$h.Operation; UpdateID = [string]$h.UpdateIdentity.UpdateID }
    }
}
"""
# W11_IDS: comma-separated update ids (checked against GUID before they get here). Searches again, so the objects exist.
PS_DOWNLOAD = r"""
$ids = @($env:W11_IDS -split ',')
$session = New-Object -ComObject Microsoft.Update.Session
$session.ClientApplicationID = 'w11-cli-console'
$found = $session.CreateUpdateSearcher().Search('IsInstalled=0 and IsHidden=0')
$want = New-Object -ComObject Microsoft.Update.UpdateColl
$seen = @(); $already = 0
foreach ($u in $found.Updates) {
    $id = [string]$u.Identity.UpdateID
    if ($ids -contains $id) {
        $seen += $id
        if (-not $u.EulaAccepted) { $u.AcceptEula() }
        if ($u.IsDownloaded) { $already += 1 } else { [void]$want.Add($u) }
    }
}
$missing = @(); foreach ($id in $ids) { if ($seen -notcontains $id) { $missing += $id } }
$rows = @(); $code = 2; $hresult = 0
if ($want.Count -gt 0) {
    $downloader = $session.CreateUpdateDownloader()
    $downloader.Updates = $want
    $result = $downloader.Download()
    $code = [int]$result.ResultCode; $hresult = [int]$result.HResult
    for ($i = 0; $i -lt $want.Count; $i++) {
        $one = $result.GetUpdateResult($i)
        $rows += [pscustomobject]@{ UpdateID = [string]$want.Item($i).Identity.UpdateID; Title = [string]$want.Item($i).Title;
            ResultCode = [int]$one.ResultCode; HResult = [int]$one.HResult }
    }
}
[pscustomobject]@{ Missing = $missing; Already = $already; ResultCode = $code; HResult = $hresult; Updates = $rows }
"""
PS_INSTALL = r"""
$ids = @($env:W11_IDS -split ',')
$session = New-Object -ComObject Microsoft.Update.Session
$session.ClientApplicationID = 'w11-cli-console'
$found = $session.CreateUpdateSearcher().Search('IsInstalled=0 and IsHidden=0')
$want = New-Object -ComObject Microsoft.Update.UpdateColl
$seen = @(); $notDownloaded = @()
foreach ($u in $found.Updates) {
    $id = [string]$u.Identity.UpdateID
    if ($ids -contains $id) {
        $seen += $id
        if ($u.IsDownloaded) { [void]$want.Add($u) } else { $notDownloaded += $id }
    }
}
$missing = @(); foreach ($id in $ids) { if ($seen -notcontains $id) { $missing += $id } }
$rows = @(); $code = 2; $hresult = 0; $restart = $false
if ($want.Count -gt 0) {
    $installer = $session.CreateUpdateInstaller()
    $installer.Updates = $want
    $installer.AllowSourcePrompts = $false
    $result = $installer.Install()
    $code = [int]$result.ResultCode; $hresult = [int]$result.HResult; $restart = [bool]$result.RebootRequired
    for ($i = 0; $i -lt $want.Count; $i++) {
        $one = $result.GetUpdateResult($i)
        $rows += [pscustomobject]@{ UpdateID = [string]$want.Item($i).Identity.UpdateID; Title = [string]$want.Item($i).Title;
            ResultCode = [int]$one.ResultCode; HResult = [int]$one.HResult; RebootRequired = [bool]$one.RebootRequired }
    }
}
[pscustomobject]@{ Missing = $missing; NotDownloaded = $notDownloaded; ResultCode = $code; HResult = $hresult;
    RebootRequired = $restart; Updates = $rows }
"""
# W11_IDS, W11_HIDE ('1' hides, '0' brings back)
PS_HIDE = r"""
$hide = ($env:W11_HIDE -eq '1')
$ids = @($env:W11_IDS -split ',')
$session = New-Object -ComObject Microsoft.Update.Session
$session.ClientApplicationID = 'w11-cli-console'
if ($hide) { $criteria = 'IsInstalled=0 and IsHidden=0' } else { $criteria = 'IsInstalled=0 and IsHidden=1' }
foreach ($u in $session.CreateUpdateSearcher().Search($criteria).Updates) {
    if ($ids -contains [string]$u.Identity.UpdateID) {
        $u.IsHidden = $hide
        [pscustomobject]@{ UpdateID = [string]$u.Identity.UpdateID; Title = [string]$u.Title; Hidden = [bool]$u.IsHidden }
    }
}
"""
PS_HOTFIXES = r"""
Get-HotFix | Sort-Object -Property InstalledOn -Descending | ForEach-Object {
    $when = $null
    if ($_.InstalledOn) { $when = $_.InstalledOn.ToString('yyyy-MM-dd') }
    [pscustomobject]@{ Id = [string]$_.HotFixID; Description = [string]$_.Description; InstalledOn = $when;
        InstalledBy = [string]$_.InstalledBy }
}
"""
PS_HOTFIX_ONE = r"""
try { $h = @(Get-HotFix -Id $env:W11_KB)[0] } catch { $h = $null }
if ($h) {
    $when = $null
    if ($h.InstalledOn) { $when = $h.InstalledOn.ToString('yyyy-MM-dd') }
    [pscustomobject]@{ Id = [string]$h.HotFixID; Description = [string]$h.Description; InstalledOn = $when }
}
"""
PS_UPDATE_SERVICES = r"""
$manager = New-Object -ComObject Microsoft.Update.ServiceManager
foreach ($s in $manager.Services) {
    [pscustomobject]@{ ServiceID = [string]$s.ServiceID; Name = [string]$s.Name; Managed = [bool]$s.IsManaged;
        RegisteredWithAU = [bool]$s.IsRegisteredWithAU; Default = [bool]$s.IsDefaultAUService }
}
"""
# asfAllowPendingRegistration (1) + asfAllowOnlineRegistration (2) + asfRegisterServiceWithAU (4)
PS_MICROSOFT_ON = "$manager = New-Object -ComObject Microsoft.Update.ServiceManager\n" \
                  "[void]$manager.AddService2('" + MICROSOFT_UPDATE + "', 7, '')"
PS_MICROSOFT_OFF = "$manager = New-Object -ComObject Microsoft.Update.ServiceManager\n" \
                   "$manager.RemoveService('" + MICROSOFT_UPDATE + "')"


# ======================================================================
# SMALL HELPERS — times, sizes, messages
# ======================================================================
def _is_num(word):
    """Plain digits only: str.isdigit() also accepts characters such as superscript 2, which int() rejects."""
    return re.fullmatch(r"[0-9]+", word) is not None


def _as_list(value):
    """PowerShell writes a one-item list as the item itself sometimes; always get a list."""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _utc_to_local(moment):
    """A naive datetime that is in UTC, as a naive local one."""
    return moment.replace(tzinfo=timezone.utc).astimezone().replace(tzinfo=None)


def _when(value, utc=False):
    """A time from Windows as a naive local datetime, or None. Text with a Z or an offset knows its zone; other text
    is read as UTC when utc is true. Dates before 2000 are Windows' way of saying 'never'."""
    if isinstance(value, datetime):
        moment = value
    elif isinstance(value, str) and value.strip():
        try:
            moment = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    if moment.year < 2000:
        return None
    if moment.tzinfo is not None:
        return moment.astimezone().replace(tzinfo=None)
    return _utc_to_local(moment) if utc else moment


def _iso(moment):
    return moment.isoformat(timespec="seconds") if moment else None


def _when_text(moment):
    return f"{_win.ago(moment)} ({moment:%Y-%m-%d %H:%M})" if moment else "unknown"


def _size(count):
    if not count:
        return "-"
    if count >= 1024 ** 3:
        return f"{count / 1024 ** 3:.1f} GB"
    if count >= 1024 ** 2:
        return f"{count / 1024 ** 2:.0f} MB"
    return f"{max(count / 1024, 1):.0f} KB"


def _hresult(value):
    """A signed 32-bit result as the unsigned number Windows documents."""
    return (value or 0) & 0xFFFFFFFF


def _code_text(value):
    """'0x80070070 (the disk is full)' for a result code Windows gave; '' for success."""
    value = _hresult(value)
    if value == 0:
        return ""
    known = HRESULT_TEXT.get(value)
    if known is None and (value >> 16) == 0xC190:
        known = "a driver or device problem stopped the upgrade, so Windows went back to the earlier version"
    return f"0x{value:08X}" + (f" ({known})" if known else "")


def _reason(message):
    """Windows' error text with the first code it contains explained in plain words."""
    for match in HEX_CODE.finditer(message or ""):
        known = HRESULT_TEXT.get(int(match.group(1), 16))
        if known:
            return f"{message} -- {known}"
    return message


def _is_definition(title):
    lowered = (title or "").lower()
    return "security intelligence update" in lowered or "definition update" in lowered


def _kb_of(title):
    match = KB_IN_TITLE.search(title or "")
    return match.group(1).upper() if match else None


def _note(options, text=""):
    """Progress and explanation: stdout normally, stderr with --json so that stdout stays pure data."""
    print(text, file=sys.stderr if options["json"] else sys.stdout)


def _ask(question, options):
    """_core.confirm, with the question on stderr when --json is on, so stdout stays pure data."""
    if not options["json"]:
        return _core.confirm(question, options["yes"])
    with contextlib.redirect_stdout(sys.stderr):
        return _core.confirm(question, options["yes"])


def _wua(script, timeout, env=None):
    """Run a Windows Update Agent script and return its objects; failures carry a plain-words reason."""
    try:
        return _win.powershell_json(script, timeout, env)
    except _net.NetError as e:
        raise UpdateError(_reason(str(e)), e.code)


# ======================================================================
# READING THE PC — registry and services; none of this needs administrator rights
# ======================================================================
def _reg(path, name, default=None):
    return _net.reg_read(path, name, default)


def _key_exists(path):
    try:
        with winreg.OpenKey(_win.HKLM, path):
            return True
    except OSError:
        return False


def _windows():
    product = _reg(NT_KEY, "ProductName") or "Windows"
    build = str(_reg(NT_KEY, "CurrentBuildNumber") or _reg(NT_KEY, "CurrentBuild") or "")
    ubr = _reg(NT_KEY, "UBR")
    if build.isdigit() and int(build) >= 22000:
        product = product.replace("Windows 10", "Windows 11")  # Windows 11 still writes "Windows 10" here
    edition = str(_reg(NT_KEY, "EditionID") or "")
    return {
        "name": product, "version": _reg(NT_KEY, "DisplayVersion") or _reg(NT_KEY, "ReleaseId") or "",
        "build": f"{build}.{ubr}" if build and ubr is not None else build, "edition_id": edition,
        "home": edition.lower().startswith("core"),  # Core, CoreN, CoreSingleLanguage: Windows Home
    }


def _restart_flags():
    """Why Windows thinks a restart is waiting: [{"key", "text"}] from the three places it records that."""
    found = []
    if _key_exists(AU_KEY + r"\RebootRequired"):
        found.append({"key": "windows-update", "text": "Windows Update is waiting for a restart"})
    if _key_exists(CBS_PENDING_KEY):
        found.append({"key": "servicing", "text": "Windows' servicing stack is waiting for a restart"})
    if _reg(SESSION_KEY, "PendingFileRenameOperations"):
        found.append({"key": "files", "text": "files are waiting to be replaced at the next restart "
                                              "(programs do this too, not only updates)"})
    return found


def _record():
    """What this page wrote into the update policy: {"pause": {...}, "drivers": {...}}."""
    return _win.load_json(POLICY_RECORD, {}) or {}


def _ours_names():
    record = _record()
    names = set()
    if "pause" in record:
        names.update(PAUSE_NAMES)
    if "drivers" in record:
        names.add(DRIVER_POLICY)
    return names


def _policies():
    """The update policy values on this PC: [{"name", "value", "meaning", "ours"}]. 'ours' means 'wu pause' or
    'wu drivers' wrote it; the rest come from Group Policy or device management."""
    ours = _ours_names()
    found = []
    for key, is_au in ((POLICY_KEY, False), (POLICY_AU_KEY, True)):
        for name, (value, _) in sorted(_win.reg_values(_win.HKLM, key).items()):
            found.append({"name": name, "value": value, "meaning": POLICY_TEXT.get(name),
                          "ours": name in ours and not is_au})
    return found


def _policy_date(value):
    try:
        return datetime.strptime(str(value)[:10], "%Y-%m-%d")
    except ValueError:
        return None


def _pause_state():
    """Whether updates are paused and until when: {"paused", "until", "source"}. Settings keeps its pause in its own
    values (read here, never written); a policy pause is a start date plus 35 days."""
    now = datetime.now()
    candidates = []
    for name in ("PauseUpdatesExpiryTime", "PauseFeatureUpdatesEndTime", "PauseQualityUpdatesEndTime"):
        end = _when(_reg(UX_KEY, name), utc=True)
        if end and end > now:
            candidates.append((end, "Settings"))
    ours = _ours_names()
    for name in PAUSE_NAMES:
        start = _policy_date(_reg(POLICY_KEY, name))
        if start and start + timedelta(days=PAUSE_DAYS) > now:
            candidates.append((start + timedelta(days=PAUSE_DAYS),
                               "wu pause" if name in ours else "your organisation's policy"))
    if not candidates:
        return {"paused": False, "until": None, "source": None}
    end, source = max(candidates)
    return {"paused": True, "until": end.strftime("%Y-%m-%d"), "source": source}


def _services():
    rows = []
    for name, display, purpose in SERVICES:
        path = f"{SERVICES_KEY}\\{name}"
        start = _reg(path, "Start")
        startup = START_WORDS.get(start, "unknown")
        if start == 2 and _reg(path, "DelayedAutostart") == 1:
            startup = "automatic (delayed)"
        rows.append({"name": name, "display": display, "purpose": purpose, "state": _net.service_state(name),
                     "startup": startup, "on_demand": _key_exists(path + r"\TriggerInfo")})
    return rows


def _active_hours():
    if _reg(POLICY_KEY, "SetActiveHours") == 1:
        start, end, source = _reg(POLICY_KEY, "ActiveHoursStart"), _reg(POLICY_KEY, "ActiveHoursEnd"), "policy"
    else:
        start, end, source = _reg(UX_KEY, "ActiveHoursStart"), _reg(UX_KEY, "ActiveHoursEnd"), "Settings"
    if not isinstance(start, int) or not isinstance(end, int):
        return None
    return {"start": start, "end": end, "source": source}


def _free_space():
    """(free GB, drive) for the drive Windows is on; (None, drive) if it cannot be read."""
    drive = os.environ.get("SystemDrive", "C:")
    try:
        return shutil.disk_usage(drive + "\\").free / 1024 ** 3, drive
    except OSError:
        return None, drive


# ======================================================================
# READING WINDOWS UPDATE — history, and the search
# ======================================================================
def _history_rows(rows):
    """History entries as dicts, newest first."""
    entries = []
    for row in rows:
        title = row.get("Title") or ""
        code = row.get("ResultCode")
        hresult = _hresult(row.get("HResult"))
        entries.append({
            "date": _when(row.get("Date"), HISTORY_IS_UTC), "title": title, "kb": _kb_of(title),
            "operation": OPERATION_WORDS.get(row.get("Operation"), "other"), "result_code": code,
            "result": RESULT_WORDS.get(code, f"result {code}"), "hresult": f"0x{hresult:08X}" if hresult else None,
            "reason": _code_text(row.get("HResult")) or None, "update_id": row.get("UpdateID") or None,
        })
    entries.sort(key=lambda entry: entry["date"] or datetime.min, reverse=True)
    return entries


def _history(count):
    rows = _wua(PS_HISTORY, STATUS_TIMEOUT, {"W11_COUNT": str(count)})
    return _history_rows(rows)


def _kind(row, categories):
    if row.get("Type") == 2:
        return "driver"
    names = " ".join(categories).lower()
    title = (row.get("Title") or "").lower()
    if "definition" in names or _is_definition(title):
        return "definition"
    if "upgrade" in names or title.startswith("feature update"):
        return "feature"
    if ("cumulative update" in title or "security updates" in names or "critical updates" in names
            or "update rollups" in names or "service packs" in names):
        return "quality"
    return "other"


def _update(row):
    categories = [str(c) for c in _as_list(row.get("Categories"))]
    kb = [f"KB{str(k).upper().removeprefix('KB')}" for k in _as_list(row.get("KB")) if str(k).strip()]
    kind = _kind(row, categories)
    driver = None
    if kind == "driver":
        driver = {"manufacturer": row.get("DriverManufacturer") or None, "model": row.get("DriverModel") or None,
                  "class": row.get("DriverClass") or None, "provider": row.get("DriverProvider") or None,
                  "date": _iso(_when(row.get("DriverVerDate")))}
    return {
        "update_id": str(row.get("UpdateID") or ""), "revision": row.get("Revision"), "title": row.get("Title") or "",
        "kb": kb, "kind": kind, "optional": bool(row.get("BrowseOnly")), "severity": row.get("Severity") or None,
        "size": int(row.get("MaxSize") or 0), "min_size": int(row.get("MinSize") or 0), "categories": categories,
        "restart": REBOOT_WORDS.get(row.get("Reboot"), "maybe"), "downloaded": bool(row.get("Downloaded")),
        "hidden": bool(row.get("Hidden")), "licence_accepted": bool(row.get("Eula")),
        "mandatory": bool(row.get("Mandatory")), "description": row.get("Description") or "",
        "support_url": row.get("SupportUrl") or None, "more_info": [str(u) for u in _as_list(row.get("MoreInfo"))],
        "release_notes": row.get("ReleaseNotes") or None, "uninstallable": bool(row.get("Uninstallable")),
        "driver": driver,
    }


def _numbered(updates):
    """Sorted by title and numbered from 1. Every list, and every id, comes from here."""
    updates = sorted(updates, key=lambda u: (u["title"].lower(), u["update_id"]))
    for number, update in enumerate(updates, start=1):
        update["id"] = number
    return updates


def _search(criteria):
    return _numbered([_update(row) for row in _wua(PS_SEARCH, SEARCH_TIMEOUT, {"W11_CRITERIA": criteria})])


def _list_file(name):
    return f"update-list-{name}.json"


def _remember(name, updates):
    """Save a numbered list so that 'wu install 3' means the update the person saw as 3."""
    _win.save_json(_list_file(name), {
        "saved": _iso(datetime.now()),
        "updates": [{"id": u["id"], "update_id": u["update_id"], "title": u["title"]} for u in updates],
    })


def _recent(name):
    """The list saved by the last 'wu ls' (or 'wu hidden'), if it is fresh; else None."""
    saved = _win.load_json(_list_file(name))
    when = _when(saved.get("saved")) if isinstance(saved, dict) else None
    if when is None or datetime.now() - when > timedelta(hours=LIST_FRESH_HOURS):
        return None
    return saved.get("updates") or []


def _pick(word, updates, name):
    """The update(s) a word names: an id from the last list, a KB number, or a (start of an) update id."""
    if _is_num(word) and len(word) <= 4:
        number = int(word)
        saved = _recent(name)
        if saved is not None:
            entry = next((e for e in saved if e["id"] == number), None)
            if entry is None:
                raise UpdateError(f"no update {number} in the last list. Run 'wu ls' to see them.", 2)
            update = next((u for u in updates if u["update_id"].lower() == entry["update_id"].lower()), None)
            if update is None:
                raise UpdateError(f"update {number} ({entry['title']}) is not there any more (installed, hidden or "
                                  "superseded). Run 'wu ls' for the current list.", 2)
            return [update]
        update = next((u for u in updates if u["id"] == number), None)
        if update is None:
            raise UpdateError(f"no update {number}. Run 'wu ls' to see them.", 2)
        return [update]
    match = KB_WORD.match(word)
    if match:
        wanted = "KB" + match.group(1)
        found = [u for u in updates if wanted in u["kb"]]
        if not found:
            raise UpdateError(f"{wanted} is not in the list. Run 'wu ls' to see what is pending.", 2)
        return found
    if re.fullmatch(r"[0-9a-fA-F-]{8,36}", word):
        found = [u for u in updates if u["update_id"].lower().startswith(word.lower())]
        if len(found) == 1:
            return found
        raise UpdateError(f"'{word}' matches {len(found)} updates. Use an id or a KB number.", 2)
    raise UpdateError(f"'{word}' is not an update id or a KB number. Run 'wu ls' to see them.", 2)


# ======================================================================
# STATE AND CHECKS — one set of rules behind 'wu' and 'wu why', so they cannot disagree
# ======================================================================
def _state():
    wua, wua_error = {}, None
    try:
        rows = _wua(PS_STATUS, STATUS_TIMEOUT)
        wua = rows[0] if rows else {}
    except UpdateError as e:
        wua_error = str(e)
    wua_error = wua_error or wua.get("AutoUpdateError") or wua.get("HistoryError")
    history = _history_rows(_as_list(wua.get("History")))
    seen = [_when(wua.get("LastSearch"), COM_DATES_ARE_UTC),
            _when(_reg(AU_KEY + r"\Results\Detect", "LastSuccessTime"), True)]
    last_check = max((moment for moment in seen if moment), default=None)
    installed = [h for h in history if h["operation"] == "install" and h["result_code"] in (2, 3)
                 and not _is_definition(h["title"])]
    failed = [h for h in history if h["result_code"] == 4]
    restart = _restart_flags()
    if wua.get("RebootRequired"):
        restart.insert(0, {"key": "agent", "text": "Windows Update says a restart is needed to finish an update"})
    free, drive = _free_space()
    return {
        "windows": _windows(), "last_check": last_check, "last_install": installed[0] if installed else None,
        "last_failure": failed[0] if failed else None, "restart": restart, "pause": _pause_state(),
        "services": _services(), "policies": _policies(), "active_hours": _active_hours(), "free_gb": free,
        "drive": drive, "agent_error": wua_error, "history": history,
    }


def _checks(state):
    """Every check as {"key", "level" (ok, info, warn, bad), "message", "fix"}."""
    checks = []

    def add(key, level, message, fix=None):
        checks.append({"key": key, "level": level, "message": message, "fix": fix})

    broken = [row for row in state["services"] if row["startup"] == "disabled"]
    for row in broken:
        add("service-" + row["name"], "bad", f"{row['display']} ({row['name']}) is turned off (disabled), so Windows "
            "Update cannot work.", f"svc {row['name']} manual   (administrator)")
    crypt = next((row for row in state["services"] if row["name"] == "cryptsvc"), None)
    if crypt and crypt["state"] == "STOPPED" and crypt["startup"] != "disabled":
        add("service-cryptsvc", "warn", "Cryptographic Services is stopped; Windows Update needs it to check that "
            "updates are signed.", "svc cryptsvc on   (administrator)")
    if not broken and not (crypt and crypt["state"] == "STOPPED"):
        add("services", "ok", "The services Windows Update runs on are not turned off.")
    if state["agent_error"] and not broken:
        add("agent", "bad", f"The Windows Update Agent did not answer: {state['agent_error']}",
            "wu services   (then 'svc wuauserv manual' if it is disabled)")
    elif not state["agent_error"]:
        add("agent", "ok", "The Windows Update Agent answers.")

    foreign = [p for p in state["policies"] if not p["ours"]]
    if foreign:
        stops = [p for p in foreign if p["name"] in ("NoAutoUpdate", "DisableWindowsUpdateAccess") and p["value"] == 1]
        names = ", ".join(sorted(p["name"] for p in foreign))
        if stops:
            add("policy", "warn", "Your organisation's policy turns off automatic updates or access to Windows "
                f"Update ({names}).", "Ask whoever manages this PC. This page does not change policy it did not write.")
        else:
            add("policy", "info", f"Your organisation sets update policy on this PC ({len(foreign)} setting(s): "
                f"{names}). This page does not change policy it did not write.")
    else:
        add("policy", "ok", "No policy from your organisation is changing how updates work.")

    pause = state["pause"]
    if pause["paused"]:
        add("paused", "warn", f"Updates are paused until {pause['until']} (set by {pause['source']}).",
            "wu resume" if pause["source"] == "wu pause" else "Settings > Windows Update > Resume updates   (wu open)")
    else:
        add("paused", "ok", "Updates are not paused.")

    real = [flag for flag in state["restart"] if flag["key"] != "files"]
    if real:
        add("restart", "warn", "A restart is waiting to finish updates: " + "; ".join(f["text"] for f in real) + ".",
            "Restart Windows when you are ready. This page never restarts the PC.")
    elif state["restart"]:
        add("restart", "info", "Some files are waiting to be replaced at the next restart (programs do this too, "
            "not only updates).")
    else:
        add("restart", "ok", "No restart is waiting.")

    last = state["last_check"]
    if last is None:
        add("last-check", "info", "Windows does not say when it last checked for updates.", "wu check")
    elif (datetime.now() - last).days >= STALE_CHECK_DAYS:
        add("last-check", "warn", f"Windows last checked for updates {_win.ago(last)}.",
            "wu check   (and make sure the PC is online)")
    else:
        add("last-check", "ok", f"Windows last checked for updates {_win.ago(last)}.")

    failure, success = state["last_failure"], state["last_install"]
    if failure and failure["date"] and (success is None or not success["date"] or failure["date"] > success["date"]) \
            and datetime.now() - failure["date"] < timedelta(days=30):
        add("failure", "warn", f"The last update that failed was {failure['title'] or 'an update'} on "
            f"{failure['date']:%Y-%m-%d}" + (f": {failure['reason']}" if failure["reason"] else "") + ".",
            "wu failed   (every failure, with its code)")
    else:
        add("failure", "ok", "No update has failed since the last one installed.")

    free = state["free_gb"]
    if free is not None and free < VERY_LOW_SPACE_GB:
        add("space", "bad", f"Only {free:.1f} GB is free on {state['drive']}. Updates need room to unpack.",
            "Free some space: 'apps ls' to find programs to remove, or Settings > System > Storage.")
    elif free is not None and free < LOW_SPACE_GB:
        add("space", "warn", f"{free:.1f} GB is free on {state['drive']}. Large updates need more than that.",
            "Free some space: 'apps ls' to find programs to remove, or Settings > System > Storage.")
    elif free is not None:
        add("space", "ok", f"{free:.0f} GB is free on {state['drive']}.")
    return checks


def _verdict(checks):
    levels = {check["level"] for check in checks}
    return "bad" if "bad" in levels else "warn" if "warn" in levels else "ok"


LEVEL_COLORS = {"ok": _net.GREEN, "info": _net.CYAN, "warn": _net.YELLOW, "bad": _net.RED}


# ======================================================================
# SHOWING — status, the update list, one update
# ======================================================================
def _service_text(row):
    state = {"RUNNING": "running", "STOPPED": "stopped"}.get(row["state"], row["state"].lower())
    if row["startup"] == "disabled":
        return "turned off (disabled)"
    note = " (Windows starts it when needed)" if row["state"] == "STOPPED" and (
        row["on_demand"] or row["startup"] == "manual") else ""
    return f"{state}, {row['startup']}{note}"


def _status(options):
    state = _state()
    checks = _checks(state)
    verdict = _verdict(checks)
    if options["json"]:
        last, failure = state["last_install"], state["last_failure"]
        _core.print_json({
            "verdict": verdict, "windows": state["windows"], "last_check": _iso(state["last_check"]),
            "last_install": {"title": last["title"], "kb": last["kb"], "date": _iso(last["date"])} if last else None,
            "last_failure": {"title": failure["title"], "date": _iso(failure["date"]),
                             "hresult": failure["hresult"], "reason": failure["reason"]} if failure else None,
            "restart_pending": bool(state["restart"]), "restart_reasons": [f["key"] for f in state["restart"]],
            "pause": state["pause"],
            "services": [{k: row[k] for k in ("name", "display", "state", "startup", "on_demand")}
                         for row in state["services"]],
            "policies": [{k: p[k] for k in ("name", "value", "meaning", "ours")} for p in state["policies"]],
            "managed_by_policy": any(not p["ours"] for p in state["policies"]),
            "active_hours": state["active_hours"], "free_gb": round(state["free_gb"], 1) if state["free_gb"] else None,
            "agent_error": state["agent_error"], "checks": checks,
        })
        return 0
    problems = [c for c in checks if c["level"] in ("warn", "bad", "info")]
    if verdict == "ok":
        print(_net.GREEN + "Windows Update looks healthy." + _net.RESET)
    else:
        print(LEVEL_COLORS[verdict] + "Windows Update needs attention:" + _net.RESET)
    for check in problems:
        print(LEVEL_COLORS[check["level"]] + f"  {check['message']}" + _net.RESET)
        if check["fix"]:
            print(_net.GREY + f"    fix: {check['fix']}" + _net.RESET)
    print()
    win, last = state["windows"], state["last_install"]
    managed = [p for p in state["policies"] if not p["ours"]]
    sections = [
        ("this PC", [("Windows", f"{win['name']} {win['version']}".strip()), ("build", win["build"] or "-")]),
        ("updates", [
            ("last checked", _when_text(state["last_check"])),
            ("last installed", f"{last['title']} ({_win.ago(last['date'])})" if last else "none in the history"),
            ("restart waiting", "yes: " + "; ".join(f["text"] for f in state["restart"]) if state["restart"] else "no"),
            ("paused", f"until {state['pause']['until']} ({state['pause']['source']})" if state["pause"]["paused"]
             else "no"),
            ("managed by policy", f"yes: {len(managed)} setting(s), 'wu options' lists them" if managed else "no"),
        ]),
        ("services", [(f"{row['display']} ({row['name']})", _service_text(row)) for row in state["services"]]),
        ("next", [
            ("wu check", "search for pending updates now"),
            ("wu why", "every check, with the command that fixes what is wrong"),
            ("wu history", "what installed recently, and what failed"),
            ("wu help", "everything this page can do"),
        ]),
    ]
    _net.render("Windows Update", sections)
    return 0


def _row_color(update):
    if update["severity"] == "Critical":
        return _net.RED
    if update["severity"] == "Important":
        return _net.YELLOW
    if update["optional"] or update["kind"] in ("driver", "definition"):
        return _net.GREY
    return ""


def _kind_text(update):
    return update["kind"] + (" (optional)" if update["optional"] else "")


def _brief(update):
    keys = ("id", "update_id", "title", "kb", "kind", "optional", "severity", "size", "restart", "downloaded",
            "hidden", "licence_accepted")
    return {key: update[key] for key in keys}


def _list(options):
    _note(options, "searching Windows Update (this can take a minute)...")
    updates = _search(PENDING)
    _remember("pending", updates)
    if options["json"]:
        _core.print_json({"searched": _iso(datetime.now()), "count": len(updates),
                          "total_size": sum(u["size"] for u in updates), "updates": [_brief(u) for u in updates]})
        return 0
    if not updates:
        print(_net.GREEN + f"You're up to date: Windows Update found nothing to install ({datetime.now():%H:%M})."
              + _net.RESET)
        print("Hidden updates are listed by 'wu hidden'. 'wu why' checks that updates are able to arrive.")
        return 0
    width = max(30, shutil.get_terminal_size((110, 24)).columns - 58)
    print(f"{'ID':<5}{'KB':<12}{'KIND':<22}{'SIZE':<10}{'RESTART':<9}TITLE")
    for update in updates:
        title = update["title"] if len(update["title"]) <= width else update["title"][:width - 1] + "…"
        print(_row_color(update) + f"{update['id']:<5}{(update['kb'] or ['-'])[0]:<12}{_kind_text(update):<22}"
              f"{_size(update['size']):<10}{update['restart']:<9}{title}" + _net.RESET)
    regular = [u for u in updates if _is_regular(u)]
    print(f"\n{len(updates)} update(s), about {_size(sum(u['size'] for u in updates))}. "
          f"'wu install <id>' installs one, 'wu install all' installs the {len(regular)} regular one(s) "
          "(not drivers, optional updates or feature updates). 'wu <id>' explains one.")
    return 0


def _show(word, options):
    _note(options, "searching Windows Update (this can take a minute)...")
    updates = _search(PENDING)
    update = _pick(word, updates, "pending")[0]
    if options["json"]:
        _core.print_json(update)
        return 0
    description = " ".join(update["description"].split())
    if len(description) > 320:
        description = description[:319] + "…"
    sections = [
        ("update", [
            ("kind", _kind_text(update)), ("KB", update["kb"]), ("severity", update["severity"]),
            ("download size", _size(update["size"])),
            ("restart", {"never": "not needed", "always": "always needed", "maybe": "may be needed"}[update["restart"]]),
            ("downloaded already", "yes" if update["downloaded"] else "no"),
            ("licence terms", "accepted" if update["licence_accepted"] else "not accepted yet; installing accepts them"),
            ("categories", update["categories"]),
        ]),
        ("about it", [("what it is", description), ("support page", update["support_url"]),
                      ("more information", update["more_info"][:2]), ("release notes", update["release_notes"])]),
    ]
    if update["driver"]:
        driver = update["driver"]
        sections.append(("driver", [("manufacturer", driver["manufacturer"]), ("model", driver["model"]),
                                    ("class", driver["class"]), ("provider", driver["provider"]),
                                    ("version date", driver["date"])]))
    sections.append(("what you can do", [
        (f"wu install {update['id']}", "download and install it (administrator; asks first)"),
        (f"wu hide {update['id']}", "keep Windows from offering it (administrator; 'wu unhide' brings it back)"),
    ]))
    _net.render(f"{update['id']}  {update['title']}", sections)
    return 0


# ======================================================================
# INSTALLING — download, then install; the PC is never restarted
# ======================================================================
def _is_regular(update):
    """What 'wu install all' takes: not a driver, not optional, not a feature update (a Windows upgrade)."""
    return update["kind"] in ("quality", "definition", "other") and not update["optional"]


def _selection(words, updates):
    """The updates the words name; 'all' and 'drivers' are words, anything else is an id or a KB number."""
    chosen = []
    for word in words:
        lowered = word.lower()
        if lowered == "all":
            found = [u for u in updates if _is_regular(u)]
        elif lowered == "drivers":
            found = [u for u in updates if u["kind"] == "driver"]
        else:
            found = _pick(word, updates, "pending")
        chosen += [u for u in found if u not in chosen]
    return chosen


def _result_line(update, code, hresult, restart):
    word = RESULT_WORDS.get(code, f"result {code}")
    color = {2: _net.GREEN, 3: _net.YELLOW}.get(code, _net.RED)
    reason = _code_text(hresult)
    text = f"  {word:<22}{update['title']}" + (f"   [{reason}]" if reason and code not in (2,) else "")
    return color + text + (_net.GREY + "   (restart needed)" if restart else "") + _net.RESET


def _install(words, options):
    if not words:
        raise UpdateError("usage: wu install <id|KB>... | all | drivers", 2)
    for word in words:
        if word.lower() not in ("all", "drivers") and not (_is_num(word) and len(word) <= 4) \
                and not KB_WORD.match(word) and not re.fullmatch(r"[0-9a-fA-F-]{8,36}", word):
            raise UpdateError(f"'{word}' is not an update id, a KB number, 'all' or 'drivers'. "
                              "Run 'wu ls' to see them.", 2)
    _net.need_admin()
    _note(options, "searching Windows Update (this can take a minute)...")
    updates = _search(PENDING)
    chosen = _selection(words, updates)
    if not chosen:
        _note(options, "nothing to install: Windows Update found no regular updates. Drivers and optional updates "
                       "need their id ('wu ls').")
        if options["json"]:
            _core.print_json({"requested": [], "installed": [], "restart_required": False, "missing": []})
        return 0
    total = sum(u["size"] for u in chosen)
    for update in chosen:
        _note(options, f"  {update['id']:<4}{(update['kb'] or ['-'])[0]:<12}{_size(update['size']):<9}{update['title']}")
    notes = []
    if any(u["kind"] == "feature" for u in chosen):
        notes.append("This includes a feature update (a Windows upgrade): it is large, takes a long time and "
                     "restarts the PC several times. ")
    if any(u["restart"] != "never" for u in chosen):
        notes.append("Some of these need a restart afterwards; this page never restarts the PC. ")
    if any(not u["licence_accepted"] for u in chosen):
        notes.append("Some have licence terms, which installing accepts. ")
    if not _ask(f"Download and install {len(chosen)} update(s), about {_size(total)}? {''.join(notes)}"
                "This can take a long time. To remove one later: 'wu uninstall <KB>'. [y/N]: ", options):
        _note(options, "cancelled")
        return 0
    ids = ",".join(u["update_id"] for u in chosen)
    if not all(GUID.match(i) for i in ids.split(",")):
        raise UpdateError("Windows Update gave an update id this page will not pass on", 1)
    env = {"W11_IDS": ids}
    _note(options, f"downloading {len(chosen)} update(s)... (this can take a long time)")
    download = _wua(PS_DOWNLOAD, LONG_TIMEOUT, env)[0]
    bad = [row for row in _as_list(download.get("Updates")) if row.get("ResultCode") not in (2, 3)]
    for row in bad:
        _note(options, _result_line({"title": row.get("Title")}, row.get("ResultCode"), row.get("HResult"), False))
    _note(options, "installing... (this can take a long time; Ctrl+C does not stop Windows once it is installing)")
    install = _wua(PS_INSTALL, LONG_TIMEOUT, env)[0]
    by_id = {u["update_id"].lower(): u for u in chosen}
    results, failures, restart = [], 0, bool(install.get("RebootRequired"))
    for row in _as_list(install.get("Updates")):
        update = by_id.get(str(row.get("UpdateID")).lower(), {"title": row.get("Title"), "kb": []})
        code = row.get("ResultCode")
        failures += 1 if code in (4, 5) else 0
        _note(options, _result_line(update, code, row.get("HResult"), row.get("RebootRequired")))
        results.append({"update_id": row.get("UpdateID"), "title": row.get("Title"), "kb": update.get("kb", []),
                        "result": RESULT_WORDS.get(code, f"result {code}"), "result_code": code,
                        "hresult": f"0x{_hresult(row.get('HResult')):08X}" if row.get("HResult") else None,
                        "reason": _code_text(row.get("HResult")) or None,
                        "restart_required": bool(row.get("RebootRequired"))})
    skipped = [by_id[i.lower()] for i in _as_list(install.get("NotDownloaded")) if i.lower() in by_id]
    for update in skipped:
        failures += 1
        _note(options, _net.RED + f"  not downloaded       {update['title']}" + _net.RESET)
    missing = [by_id[i.lower()] for i in _as_list(install.get("Missing")) if i.lower() in by_id]
    for update in missing:
        _note(options, _net.YELLOW + f"  no longer pending    {update['title']}" + _net.RESET)
    restart = restart or any(f["key"] != "files" for f in _restart_flags())
    done = sum(1 for r in results if r["result_code"] in (2, 3))
    _note(options, f"\n{done} of {len(chosen)} update(s) installed" + (f", {failures} failed" if failures else "") + ".")
    if restart:
        _note(options, _net.YELLOW + "A restart is needed to finish. Restart Windows when you are ready (this page "
                                     "never restarts the PC)." + _net.RESET)
    if failures:
        _note(options, "'wu failed' lists the failures with their codes; 'wu why' checks what could be in the way.")
    if options["json"]:
        _core.print_json({"requested": [_brief(u) for u in chosen], "installed": results,
                          "not_downloaded": [u["update_id"] for u in skipped],
                          "missing": [u["update_id"] for u in missing], "restart_required": restart})
    return 1 if failures else 0


# ======================================================================
# HISTORY — what installed, what failed, and what Windows lists as installed
# ======================================================================
def _history_words(words, failed_only):
    count, include_definitions = HISTORY_DEFAULT, False
    for word in words:
        if word.lower() == "all" and not failed_only:
            include_definitions = True
        elif _is_num(word) and 1 <= int(word) <= HISTORY_MAX:
            count = int(word)
        else:
            raise UpdateError(f"usage: wu {'failed [n]' if failed_only else 'history [n] [all]'}   "
                              f"(n from 1 to {HISTORY_MAX})", 2)
    return count, include_definitions


def _history_cmd(words, options, failed_only=False):
    count, include_definitions = _history_words(words, failed_only)
    _note(options, "reading the update history...")
    entries = _history(max(200, count * 10))
    if failed_only:
        entries = [e for e in entries if e["result_code"] in (3, 4, 5)]
    elif not include_definitions:
        entries = [e for e in entries if not _is_definition(e["title"])]
    entries = entries[:count]
    if options["json"]:
        _core.print_json({"count": len(entries), "includes_definitions": include_definitions,
                          "entries": [{**e, "date": _iso(e["date"])} for e in entries]})
        return 0
    if not entries:
        print("no matching entries in the update history" if failed_only else "the update history is empty")
        return 0
    print(f"{'DATE':<18}{'RESULT':<24}{'KB':<12}TITLE")
    colors = {2: _net.GREEN, 3: _net.YELLOW, 4: _net.RED, 5: _net.GREY}
    for entry in entries:
        date = f"{entry['date']:%Y-%m-%d %H:%M}" if entry["date"] else "-"
        result = entry["result"] if entry["operation"] == "install" else f"{entry['operation']}: {entry['result']}"
        width = max(30, shutil.get_terminal_size((110, 24)).columns - 54)
        title = entry["title"] if len(entry["title"]) <= width else entry["title"][:width - 1] + "…"
        print(colors.get(entry["result_code"], "") + f"{date:<18}{result:<24}{entry['kb'] or '-':<12}{title}" + _net.RESET)
        if entry["result_code"] in (3, 4, 5) and entry["reason"]:
            print(colors[entry["result_code"]] + f"{'':<18}{entry['reason']}" + _net.RESET)
    print(f"\n{len(entries)} entr{'y' if len(entries) == 1 else 'ies'}, newest first."
          + ("" if failed_only or include_definitions else " Defender definition updates are left out ('wu history all')."))
    return 0


def _installed(options):
    _note(options, "reading the installed updates...")
    rows = _wua(PS_HOTFIXES, SEARCH_TIMEOUT)
    items = [{"kb": r.get("Id"), "description": r.get("Description") or None, "installed_on": r.get("InstalledOn"),
              "installed_by": r.get("InstalledBy") or None} for r in rows]
    if options["json"]:
        _core.print_json({"count": len(items), "updates": items})
        return 0
    print(f"{'KB':<12}{'INSTALLED':<12}DESCRIPTION")
    for item in items:
        print(f"{item['kb'] or '-':<12}{item['installed_on'] or '-':<12}{item['description'] or '-'}")
    print(f"\n{len(items)} update(s). Windows lists cumulative and security updates here; some others (.NET, Defender) "
          "only appear in 'wu history'.")
    return 0


# ======================================================================
# HIDING — keep an update from being offered; reversible
# ======================================================================
def _hidden_cmd(options):
    _note(options, "searching Windows Update (this can take a minute)...")
    updates = _search(HIDDEN)
    _remember("hidden", updates)
    if options["json"]:
        _core.print_json({"count": len(updates), "updates": [_brief(u) for u in updates]})
        return 0
    if not updates:
        print("no updates are hidden")
        return 0
    print(f"{'ID':<5}{'KB':<12}{'KIND':<22}TITLE")
    for update in updates:
        print(_net.GREY + f"{update['id']:<5}{(update['kb'] or ['-'])[0]:<12}{_kind_text(update):<22}{update['title']}"
              + _net.RESET)
    print(f"\n{len(updates)} hidden update(s). 'wu unhide <id|KB>' brings one back; 'wu unhide all' brings back all.")
    return 0


def _hide_cmd(words, options, hide):
    verb = "hide" if hide else "unhide"
    if not words:
        raise UpdateError(f"usage: wu {verb} <id|KB>" + ("" if hide else " | all"), 2)
    for word in words:
        if not ((_is_num(word) and len(word) <= 4) or KB_WORD.match(word) or (not hide and word.lower() == "all")):
            raise UpdateError(f"'{word}' is not an update id or a KB number", 2)
    _net.need_admin()
    _note(options, "searching Windows Update (this can take a minute)...")
    name, criteria = ("pending", PENDING) if hide else ("hidden", HIDDEN)
    updates = _search(criteria)
    chosen = []
    for word in words:
        found = updates if word.lower() == "all" else _pick(word, updates, name)
        chosen += [u for u in found if u not in chosen]
    if not chosen:
        _note(options, "no hidden updates")
        return 0
    env = {"W11_IDS": ",".join(u["update_id"] for u in chosen), "W11_HIDE": "1" if hide else "0"}
    _note(options, f"{'hiding' if hide else 'bringing back'} {len(chosen)} update(s)...")
    rows = _wua(PS_HIDE, SEARCH_TIMEOUT, env)
    done = {str(r.get("UpdateID")).lower(): r.get("Hidden") for r in rows}
    result = []
    for update in chosen:
        now_hidden = done.get(update["update_id"].lower())
        ok = now_hidden is hide
        result.append({"update_id": update["update_id"], "title": update["title"], "hidden": now_hidden, "ok": ok})
        _note(options, (_net.GREEN if ok else _net.RED) + f"  {'hidden' if now_hidden else 'visible':<9}{update['title']}"
              + _net.RESET)
    _note(options, ("Windows will not offer them. 'wu unhide <id|KB>' brings one back." if hide
                    else "Windows offers them again. 'wu ls' lists them."))
    if options["json"]:
        _core.print_json({"action": verb, "updates": result})
    return 0 if all(r["ok"] for r in result) else 1


# ======================================================================
# UNINSTALLING — wusa.exe, the documented tool for removing an installed update
# ======================================================================
def _run_code(args, timeout):
    """(exit code, output) of a Windows tool; the code matters here (3010 means 'done, restart needed')."""
    try:
        result = subprocess.run(args, capture_output=True, text=True, encoding="oem", errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired:
        raise UpdateError(f"{args[0]} took longer than {timeout} s")
    except (OSError, subprocess.SubprocessError) as e:
        raise UpdateError(f"could not run {args[0]}: {e}")
    return result.returncode, (result.stdout + result.stderr).strip()


def _hotfix(kb):
    rows = _wua(PS_HOTFIX_ONE, SEARCH_TIMEOUT, {"W11_KB": kb})
    return rows[0] if rows else None


def _uninstall(words, options):
    match = KB_WORD.match(words[0]) if len(words) == 1 else None
    if not match:
        raise UpdateError("usage: wu uninstall <KB>   (for example wu uninstall KB5031356)", 2)
    kb = "KB" + match.group(1)
    _net.need_admin()
    _note(options, f"checking that {kb} is installed...")
    found = _hotfix(kb)
    if found is None:
        raise UpdateError(f"{kb} is not listed as installed ('wu installed' lists what Windows reports). "
                          "Some updates, such as .NET and Defender ones, cannot be removed this way.", 2)
    if not _ask(f"Uninstall {kb} ({found.get('Description') or 'update'})? Programs that depend on it may stop "
                "working, Windows may offer it again ('wu hide' stops that), and a restart may be needed. "
                f"To get it back: 'wu install {kb}'. [y/N]: ", options):
        _note(options, "cancelled")
        return 0
    _note(options, f"removing {kb}...")
    code, text = _run_code(["wusa", "/uninstall", f"/kb:{kb[2:]}", "/quiet", "/norestart"], LONG_TIMEOUT)
    code &= 0xFFFFFFFF
    if code == 5:
        raise UpdateError(_net.ADMIN_HINT)
    if code not in (0, 3010):
        why = {0x240007: f"Windows says {kb} is not installed", 87: "Windows did not accept the request"}.get(
            code, _net.explain(text) if text else f"wusa stopped with code {code}")
        _win.open_settings(SETTINGS_PAGES["history"])
        raise UpdateError(f"{why}. Windows no longer removes many updates silently, so I opened the update history in "
                          f"Settings: choose Uninstall updates there, or run 'wusa /uninstall /kb:{kb[2:]}' yourself.")
    still = _hotfix(kb)
    restart = code == 3010
    result = {"kb": kb, "removed": still is None, "restart_required": restart or still is not None}
    if still is None:
        _note(options, f"{kb} is no longer listed as installed.")
    else:
        _note(options, f"{kb} is still listed; Windows usually finishes removing it after a restart.")
    if restart or still is not None:
        _note(options, _net.YELLOW + "A restart is needed to finish. This page never restarts the PC." + _net.RESET)
    if options["json"]:
        _core.print_json(result)
    return 0


# ======================================================================
# PAUSING — the Windows Update for Business policy: a start date, and Windows adds 35 days to it
# ======================================================================
def _pause_cmd(words, options):
    days = PAUSE_DAYS
    if words:
        if len(words) != 1 or not _is_num(words[0]) or not 1 <= int(words[0]) <= PAUSE_DAYS:
            raise UpdateError(f"usage: wu pause [days]   (1 to {PAUSE_DAYS}; the default is {PAUSE_DAYS})", 2)
        days = int(words[0])
    if _windows()["home"]:
        _win.open_settings(SETTINGS_PAGES[""])
        _note(options, "Windows Home does not apply the update policy this page would write, so it cannot pause "
                       "updates. I opened Settings: choose Pause updates there.")
        return 0
    foreign = [p for p in _policies() if not p["ours"] and (
        p["name"] in PAUSE_NAMES or p["name"].startswith("Defer"))]
    if foreign:
        raise UpdateError("your organisation already sets update pausing or delay on this PC ("
                          + ", ".join(p["name"] for p in foreign) + "). This page does not change policy it did "
                          "not write.")
    _net.need_admin()
    start = datetime.now().date() - timedelta(days=PAUSE_DAYS - days)
    until = start + timedelta(days=PAUSE_DAYS)
    if not _ask(f"Pause Windows updates for {days} day(s), until {until:%Y-%m-%d}? Nothing will install until then, "
                "including security fixes. This writes the Windows Update for Business policy, so Settings may say "
                "'Some settings are managed by your organization'. To undo: 'wu resume'. [y/N]: ", options):
        _note(options, "cancelled")
        return 0
    _note(options, f"pausing updates until {until:%Y-%m-%d}...")
    record = _record()
    record["pause"] = {"start": start.isoformat(), "until": until.isoformat(), "written": _iso(datetime.now())}
    _win.save_json(POLICY_RECORD, record)  # first: values this page writes must be marked as its own
    try:
        for name in PAUSE_NAMES:
            _win.reg_write(_win.HKLM, POLICY_KEY, name, start.isoformat(), winreg.REG_SZ)
    except _net.NetError:
        for name in PAUSE_NAMES:  # undo the half-written pause
            with contextlib.suppress(_net.NetError):
                _win.reg_delete(_win.HKLM, POLICY_KEY, name)
        record.pop("pause", None)
        with contextlib.suppress(_net.NetError):
            _win.save_json(POLICY_RECORD, record)
        raise
    now = _pause_state()
    if now["paused"]:
        _note(options, f"Updates are paused until {now['until']}. Settings may not show the date; 'wu' does. "
                       "To undo: 'wu resume'.")
        _note(options, "Windows picks the policy up the next time it works out updates; 'gpupdate /force' applies "
                       "it at once.")
    else:
        _note(options, _net.YELLOW + "The values are written, but Windows does not report a pause. Check "
                                     "'wu options' and Settings > Windows Update." + _net.RESET)
    if options["json"]:
        _core.print_json({"action": "pause", "days": days, **now})
    return 0 if now["paused"] else 1


def _resume_cmd(options):
    ours = _ours_names() & set(PAUSE_NAMES)
    present = {name: _reg(POLICY_KEY, name) for name in PAUSE_NAMES if _reg(POLICY_KEY, name)}
    foreign = [name for name in present if name not in ours]
    if foreign:
        raise UpdateError("the pause comes from your organisation's policy (" + ", ".join(foreign) + "). This page "
                          "does not change policy it did not write.")
    state = _pause_state()
    if not present:
        if state["paused"] and state["source"] == "Settings":
            _win.open_settings(SETTINGS_PAGES[""])
            _note(options, f"Updates are paused until {state['until']}, and Settings made that pause. I opened "
                           "Settings: choose Resume updates there.")
            return 0
        _note(options, "Updates are not paused.")
        if options["json"]:
            _core.print_json({"action": "resume", **state})
        return 0
    _net.need_admin()
    _note(options, "resuming updates...")
    for name in present:
        _win.reg_delete(_win.HKLM, POLICY_KEY, name)
    record = _record()
    record.pop("pause", None)
    _win.save_json(POLICY_RECORD, record)
    now = _pause_state()
    if now["paused"]:
        _note(options, f"Updates are still paused until {now['until']} ({now['source']}).")
    else:
        _note(options, "Updates are not paused any more. Windows catches up the next time it checks ('wu check').")
    if options["json"]:
        _core.print_json({"action": "resume", **now})
    return 1 if now["paused"] else 0


# ======================================================================
# OPTIONS — Settings > Windows Update > Advanced options, in words; changes only where Windows documents them
# ======================================================================
def _update_services():
    rows = _wua(PS_UPDATE_SERVICES, STATUS_TIMEOUT)
    return [{"id": r.get("ServiceID"), "name": r.get("Name"), "registered_with_au": bool(r.get("RegisteredWithAU")),
             "managed": bool(r.get("Managed")), "default": bool(r.get("Default"))} for r in rows]


def _microsoft_update_on():
    try:
        rows = _update_services()
    except UpdateError:
        return None
    return any(r["id"] and r["id"].lower() == MICROSOFT_UPDATE and r["registered_with_au"] for r in rows)


def _flag(name):
    value = _reg(UX_KEY, name)
    return None if value is None else bool(value)


def _options_data():
    policies = {p["name"]: p["value"] for p in _policies()}
    delivery = _reg(DELIVERY_POLICY_KEY, "DODownloadMode")
    return {
        "active_hours": _active_hours(), "microsoft_update": _microsoft_update_on(),
        "latest_updates_first": _flag("IsContinuousInnovationOptedIn"),
        "download_over_metered": _flag("AllowAutoWindowsUpdateDownloadOverMeteredNetwork"),
        "restart_notifications": _flag("RestartNotificationsAllowed2"),
        "delivery_optimization_policy": None if delivery is None else {
            "mode": delivery, "meaning": DELIVERY_MODES.get(delivery, "a mode this page does not know")},
        "drivers_included": policies.get(DRIVER_POLICY) != 1, "pause": _pause_state(),
        "policies": [{k: p[k] for k in ("name", "value", "meaning", "ours")} for p in _policies()],
    }


def _yes_no(value, yes="on", no="off"):
    return "not recorded" if value is None else yes if value else no


def _options(words, options):
    if words:
        if words[0].lower() in ("microsoft", "ms", "other") and len(words) == 2:
            return _microsoft_cmd(words[1], options)
        raise UpdateError("usage: wu options | wu options microsoft on|off", 2)
    data = _options_data()
    if options["json"]:
        _core.print_json(data)
        return 0
    hours = data["active_hours"]
    delivery = data["delivery_optimization_policy"]
    _net.render("Windows Update options", [
        ("when updates may restart the PC", [
            ("active hours", f"{hours['start']}:00 to {hours['end']}:00 (from {hours['source']})" if hours
             else "not recorded; Windows picks them"),
            ("restart notifications", _yes_no(data["restart_notifications"])),
        ]),
        ("what Windows Update fetches", [
            ("get the latest updates as soon as they are available", _yes_no(data["latest_updates_first"])),
            ("updates for other Microsoft products (Office and others)", _yes_no(data["microsoft_update"])),
            ("drivers in Windows Update", "included" if data["drivers_included"] else "left out (wu drivers on)"),
            ("download over metered connections", _yes_no(data["download_over_metered"], "allowed", "not allowed")),
        ]),
        ("sharing and pausing", [
            ("Delivery Optimization", f"{delivery['mode']}: {delivery['meaning']} (policy)" if delivery
             else "no policy; the choice is in Settings (wu open delivery)"),
            ("paused", f"until {data['pause']['until']} ({data['pause']['source']})" if data["pause"]["paused"]
             else "no"),
        ]),
        ("policy values set on this PC", [(p["name"], f"{p['value']}  {p['meaning'] or ''}".strip() + (
            "  (set by this page)" if p["ours"] else "  (your organisation)")) for p in data["policies"]]
         or [("none", "-")]),
        ("change it", [
            ("wu options microsoft on|off", "updates for other Microsoft products (administrator)"),
            ("wu drivers on|off", "whether Windows Update includes drivers (administrator)"),
            ("wu pause [days] | wu resume", "pause updates (administrator)"),
            ("wu open options|restart|optional|delivery", "the rest is changed in Settings: Windows has no documented "
             "way for a program to change it"),
        ]),
    ])
    print(_net.GREY + "Values marked 'from Settings' are read from where Settings keeps them; nothing here writes them."
          + _net.RESET)
    return 0


def _microsoft_cmd(word, options):
    try:
        on = _net.on_off(word, "wu options microsoft on")
    except _net.NetError as e:
        raise UpdateError(str(e), e.code)
    _net.need_admin()
    now = _microsoft_update_on()
    if now is on:
        _note(options, f"updates for other Microsoft products are already {'on' if on else 'off'}.")
        return 0
    if not on and not _ask("Turn off updates for other Microsoft products? Office and other Microsoft software then stop "
                           "getting security updates through Windows Update. To undo: 'wu options microsoft on'. "
                           "[y/N]: ", options):
        _note(options, "cancelled")
        return 0
    _note(options, f"turning updates for other Microsoft products {'on' if on else 'off'}...")
    _wua(PS_MICROSOFT_ON if on else PS_MICROSOFT_OFF, SEARCH_TIMEOUT)
    after = _microsoft_update_on()
    _note(options, f"updates for other Microsoft products are now {_yes_no(after)}.")
    if options["json"]:
        _core.print_json({"action": "options microsoft", "microsoft_update": after})
    return 0 if after is on else 1


# ======================================================================
# DRIVERS — one documented policy: ExcludeWUDriversInQualityUpdate
# ======================================================================
def _drivers_state():
    value = _reg(POLICY_KEY, DRIVER_POLICY)
    ours = DRIVER_POLICY in _ours_names()
    return {"drivers_included": value != 1, "policy_value": value,
            "set_by": None if value is None else "wu drivers" if ours else "your organisation"}


def _drivers_cmd(words, options):
    state = _drivers_state()
    if not words:
        if options["json"]:
            _core.print_json(state)
            return 0
        print(f"Windows Update {'includes' if state['drivers_included'] else 'leaves out'} drivers"
              + (f" (set by {state['set_by']})" if state["set_by"] else "") + ".")
        print("'wu drivers off' leaves them out, 'wu drivers on' puts them back. 'wu ls' shows the driver updates "
              "Windows is offering now.")
        return 0
    if len(words) != 1:
        raise UpdateError("usage: wu drivers [on|off]", 2)
    try:
        on = _net.on_off(words[0], "wu drivers off")
    except _net.NetError as e:
        raise UpdateError(str(e), e.code)
    if on == state["drivers_included"]:
        _note(options, f"Windows Update already {'includes' if on else 'leaves out'} drivers.")
        if options["json"]:
            _core.print_json(state)
        return 0
    if state["set_by"] == "your organisation":
        raise UpdateError("your organisation sets whether drivers are included. This page does not change policy it "
                          "did not write.")
    _net.need_admin()
    if not on and not _ask("Leave drivers out of Windows Update? Drivers for your hardware then stop arriving through "
                           "Windows Update; get them from the maker's site or install them with 'dvc driver add'. "
                           "To undo: 'wu drivers on'. [y/N]: ", options):
        _note(options, "cancelled")
        return 0
    _note(options, f"{'including' if on else 'leaving out'} drivers...")
    record = _record()
    if on:
        _win.reg_delete(_win.HKLM, POLICY_KEY, DRIVER_POLICY)
        record.pop("drivers", None)
        _win.save_json(POLICY_RECORD, record)
    else:
        record["drivers"] = {"written": _iso(datetime.now())}
        _win.save_json(POLICY_RECORD, record)  # first: the value must be marked as this page's own
        try:
            _win.reg_write(_win.HKLM, POLICY_KEY, DRIVER_POLICY, 1, winreg.REG_DWORD)
        except _net.NetError:
            record.pop("drivers", None)
            with contextlib.suppress(_net.NetError):
                _win.save_json(POLICY_RECORD, record)
            raise
    after = _drivers_state()
    _note(options, f"Windows Update now {'includes' if after['drivers_included'] else 'leaves out'} drivers.")
    if _windows()["home"] and not on:
        _note(options, "Windows Home may ignore this policy; if drivers still arrive, use Settings > Windows Update > "
                       "Advanced options.")
    if options["json"]:
        _core.print_json(after)
    return 0 if after["drivers_included"] is on else 1


# ======================================================================
# SERVICES, WHY, OPEN
# ======================================================================
def _services_cmd(options):
    rows = _services()
    if options["json"]:
        _core.print_json({"services": [{k: row[k] for k in ("name", "display", "purpose", "state", "startup", "on_demand")}
                                       for row in rows]})
        return 0
    print(f"{'SERVICE':<12}{'STATE':<10}{'STARTS':<22}WHAT IT DOES")
    for row in rows:
        color = _net.RED if row["startup"] == "disabled" else _net.GREEN if row["state"] == "RUNNING" else _net.GREY
        print(color + f"{row['name']:<12}{row['state'].lower():<10}{row['startup']:<22}{row['purpose']}" + _net.RESET)
    print("\nWindows Update, Update Orchestrator and Background Intelligent Transfer are normally stopped when nothing is "
          "updating: Windows starts them when needed. Only 'disabled' is a problem. Use 'svc <name> manual' to undo "
          "a disabled service (administrator).")
    return 0


def _why(options):
    state = _state()
    checks = _checks(state)
    verdict = _verdict(checks)
    if options["json"]:
        _core.print_json({"verdict": verdict, "checks": checks})
        return 0
    marks = {"ok": "ok  ", "info": "note", "warn": "warn", "bad": "BAD "}
    for check in checks:
        print(LEVEL_COLORS[check["level"]] + f"  {marks[check['level']]}  {check['message']}" + _net.RESET)
        if check["fix"] and check["level"] != "ok":
            print(_net.GREY + f"        fix: {check['fix']}" + _net.RESET)
    problems = sum(1 for c in checks if c["level"] in ("warn", "bad"))
    print()
    if problems:
        print(LEVEL_COLORS[verdict] + f"{problems} thing(s) could be in the way of updates." + _net.RESET)
    else:
        print(_net.GREEN + "Nothing found that would stop updates. 'wu check' looks for updates now." + _net.RESET)
    return 0


def _open(words):
    if len(words) > 1 or (words and words[0].lower() not in SETTINGS_PAGES):
        raise UpdateError("usage: wu open [" + "|".join(page for page in SETTINGS_PAGES if page) + "]", 2)
    page = words[0].lower() if words else ""
    _win.open_settings(SETTINGS_PAGES[page])
    print(f"opened Settings: {SETTINGS_PAGES[page]}")
    return 0


# ======================================================================
# COMMAND — app.py calls run(args) with everything after "update"/"wu"
# ======================================================================
def _dispatch(word, rest, options):
    if word == "status" and not rest:
        return _status(options)
    if word in ("ls", "list", "check", "search") and not rest:
        return _list(options)
    if word == "install":
        return _install(rest, options)
    if word == "history":
        return _history_cmd(rest, options)
    if word == "failed":
        return _history_cmd(rest, options, failed_only=True)
    if word == "installed" and not rest:
        return _installed(options)
    if word == "hide":
        return _hide_cmd(rest, options, True)
    if word == "unhide":
        return _hide_cmd(rest, options, False)
    if word == "hidden" and not rest:
        return _hidden_cmd(options)
    if word in _net.REMOVE_WORDS:
        return _uninstall(rest, options)
    if word == "pause":
        return _pause_cmd(rest, options)
    if word == "resume" and not rest:
        return _resume_cmd(options)
    if word == "options":
        return _options(rest, options)
    if word == "drivers":
        return _drivers_cmd(rest, options)
    if word == "services" and not rest:
        return _services_cmd(options)
    if word == "why" and not rest:
        return _why(options)
    if word == "open":
        return _open(rest)
    if not rest and ((_is_num(word) and len(word) <= 4) or KB_WORD.match(word) or GUID.match(word)):
        return _show(word, options)
    raise UpdateError(f"usage: {USAGE}", 2)


def run(args):
    """Run one update command; returns an exit code."""
    os.system("")  # enables ANSI colour codes in the Windows console
    args, options = _core.split_flags(args)
    if not args:
        args = ["status"]
    elif args[0].lower() in _core.HELP_WORDS:
        print(f"usage: {USAGE}")
        return 0
    word, rest = args[0].lower(), args[1:]
    try:
        return _dispatch(word, rest, options)
    except (UpdateError, _net.NetError) as e:
        print(f"error: {e}", file=sys.stderr)
        return e.code


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
