# w11-cli-console

Change Windows 11 settings from the command line. Run `app.py`, then type `settings` to see every setting in one list, with the first command to type for each.

## Setup

```powershell
py -m pip install -r requirements.txt
py app.py
```

## Commands

| Setting | Aliases | What it does |
|---|---|---|
| brightness | `bn`, `b`, `bright`, `screen`, `monitor` | Screen brightness |
| volume | `vm`, `vol` | System and per-app volume |
| startup | `su`, `start` | Apps that start with Windows |
| apps | `app` | Installed apps, and uninstalling them |
| process | `prc` | Running processes, ending them, live system stats |
| wifi | `internet`, `wf` | Join Wi-Fi, known networks, and every Wi-Fi setting |
| ethernet | `eth`, `lan`, `wired` | Wired network: details, IP, DNS, 802.1X, metered |
| hotspot | `hs`, `mobilehotspot` | Share this PC's internet as a Wi-Fi hotspot |
| settings | `menu` | Every setting in one list, and how to open each |
| location | `lc` | Location services, which apps can use it, and the override |
| regedit | `reg` | Windows Registry: an interactive editor, and direct commands (`reg get`, `reg set`, `reg del` ...) |
| services | `svc` | Windows services: list, search, status, dependencies, failures, start, stop, restart, startup type |
| hardware | `hw` | Processor, graphics, memory, drives, motherboard, BIOS, USB, sensors, and a full report |
| system | `sys` | Uptime, load, processes, startup programs, power, PATH, inventory, and an overall health check |
| device | `dvc` | Devices and drivers, as in Device Manager: status, errors, tree, search, and turning a device on, off or restarting it |
| firewall | `fw` | Windows Firewall: turn a network profile on or off, list the rules, and turn one rule on or off |
| events | `evt` | Windows event logs: errors, crashes, shutdowns, boots, timelines, export and watch |
| netmon | `net`, `nm`, `traffic` | Live network monitor: connections, programs and domains, traffic per adapter, kill and block |
| batch | `cs` | Several changes as one operation: preview, approve once, apply, report, undo |
| rollback | `rb`, `undo` | Undo a saved change or batch, and list what was changed |
| catalog | `cat` | Every command and change operation as data: arguments, admin, side effects |

Every name can be shortened as shown, and `ls` can be written as `list`. `rm` can also be written as `remove`, `delete`, `uninstall` or `del`. So `vm list` and `volume ls` do the same thing.

Run `py app.py` for an interactive console, or pass a command directly, e.g. `py app.py bn 40`. Type `settings` to see every setting, numbered, with what it does. Type a setting's name on its own, such as `vm` or `wifi`, to see a short blue list of what it can do. Use `help` to list everything.

### Brightness

```
bn 40          set to 40 (set is optional: bn set 40 also works)
bn get         print current brightness
bn up 10       raise by 10 (default step 5)
bn down        lower by 5
bn info        show backend: ddc or wmi
```

External monitors use DDC/CI, so turn on DDC/CI in the monitor's OSD menu if the command reports no control. Laptop panels use WMI.

### Volume

```
vm ls          list every audio source with its id (0 = system)
vm 3           show source 3's volume
vm 3 50        set source 3 to 50%
vm chrome 50   the same, by name (system works too); every session of the app is set
```

Each app is one id, even if it has several audio sessions. Ids are alphabetical, so they can shift when apps start or stop playing. Prefer the name in scripts. Changes go through the shared change engine (see "Previewing, undoing and batches"), so `--dry-run` shows the exact change and `rb last` undoes it. Windows may store the level a percent off, so the read-back allows 1%.

### Startup

```
su ls          list startup apps with id and state
su 3           show whether app 3 is enabled
su 3 off       stop app 3 starting at sign-in
su 3 on        start it at sign-in again
su rm 3        remove app 3 from startup entirely (asks you to confirm first)
su user/run/OneDrive off    the same by stable key (the KEY column of su ls; a plain name works if it is unique)
```

`on` and `off` change the same switch as Task Manager's Startup tab, so nothing is deleted. Changes apply at the next sign-in. All-users apps need an administrator terminal. `rm` saves the Run value, or the shortcut file, to the journal first, so `rb last` puts it back. Ids shift; keys do not.

### Apps

```
apps ls        list installed apps, alphabetical, with ids
apps rm 5      uninstall app 5 (asks you to confirm first)
```

Lists the same apps as Settings > Installed apps, including Store apps. Uninstalling can't be undone.

### Process

```
prc ls            programs, alphabetical, one id each, with a process count (red = Windows system)
prc ls /verbose   live CPU, RAM, GPU, Wi-Fi and disk usage, then every process on its own row
prc kill 12       end every process with program 12's name (system programs ask you twice)
```

Ids follow the list, so check the name in the prompt before you say y. Ending a process loses its unsaved work.

### Wi-Fi

```
wifi ls           list Wi-Fi networks in range with id, signal, security and state
wifi status       show the network you are connected to
wifi on           join the strongest saved network in range
wifi 3 on         join network 3 (asks for the password if it is new)
wifi 3 off        disconnect, if you are connected to network 3
wifi off          disconnect from Wi-Fi
wifi rm 3         forget network 3's saved password (asks you to confirm first)
```

Ids are alphabetical, so they can shift when networks come and go. Run `wifi ls` first. Windows only shows network names when Location is on for apps, so turn that on if `wifi ls` asks for it. Passwords are typed hidden and saved by Windows; the temporary file used to add a network is deleted straight away.

```
wifi info                 everything about the connection, like ipconfig /all but grouped and coloured
wifi known                every saved network, in range or not ("Manage known networks")
wifi known rm 2           forget saved network 2 (asks first)
wifi known 2 auto off     stop joining network 2 automatically
wifi known 2 metered on   metered connection for network 2 (also: random on|off|daily)
wifi metered on|off       metered connection for the network you are on
wifi random on|off        random hardware addresses
wifi auth                 802.1X sign-in for work and school networks (method, mode, remember, sso)
wifi hotspot ...          the hotspot page, the same as hs
```

`ip`, `dns`, `share` and `features` work the same on Wi-Fi and Ethernet; see below.

### Ethernet

```
eth info                  everything about the wired connection
eth metered on|off        metered connection (restarts the Data Usage service)
eth auth                  802.1X sign-in, and what it is set to
eth auth on|off           turn 802.1X on (starts Wired AutoConfig) or off
eth auth method peap|certificate|ttls
eth auth mode user|computer|both|guest
eth auth remember on|off  remember my credentials
eth auth fallback on|off  fall back to unauthorised network access
eth auth sso before|after|off
eth ls                    wired adapters, then eth <id> <command> for one of them
```

### Wi-Fi and Ethernet: IP, DNS, sharing and features

Replace `wifi` with `eth` for the wired connection.

```
wifi ip                         how this PC gets its address, and what it has now
wifi ip auto                    get an address from the router (DHCP)
wifi ip manual 192.168.1.50/24 192.168.1.1    a fixed address and gateway (asks first)
wifi dns auto                   use the router's DNS servers
wifi dns 1.1.1.1 8.8.8.8        your own DNS servers (IPv6 servers work too)
wifi share                      Internet Connection Sharing, with the home network choices
wifi share on 2                 share this connection with home network 2 (asks first)
wifi share off
wifi features                   Client for Microsoft Networks, File and Printer Sharing, QoS,
                                IPv4, LLDP, IPv6 and the two topology drivers, with ids 1-8
wifi features ipv6 off          untick one for this adapter (ids or short names work)
wifi features install           what can be installed; then features install <id>
wifi features install file <driver.inf> client|service|protocol <component id>
wifi features rm lldp           uninstall from every adapter (asks first)
```

Reading needs no administrator rights. Changing IP, DNS, sharing, features, metered Ethernet or Ethernet 802.1X needs an administrator terminal, and the page says so before doing anything. IPv4 and IPv6 can be turned off but not uninstalled, because they are part of Windows.

### Mobile hotspot

```
hs on                     turn the hotspot on, then show its name, password and band
hs off
hs status                 name, password, band, security, devices connected
hs name "Study Room"      rename it
hs password               change the password (typed hidden, twice); hs password <new> also works
hs band 2.4|5|any         the band (6 GHz where the adapter supports it)
hs devices                devices connected now
hs from / hs on <id>      which connections can be shared, and share one
hs security wpa2|wpa3     where the adapter supports more than one
hs sleep on|off           turn it off by itself when nothing is connected
hs over wifi|bluetooth    opens Settings at 'Share over'
```

The hotspot uses Windows' tethering API, the one Settings uses, so it needs no administrator rights. Windows does not let programs read or change 'Share over' (Wi-Fi or Bluetooth), so `hs over` opens the Mobile hotspot page in Settings for that one choice. Changes made while the hotspot is on apply the next time it starts.

### For scripts and AI agents

Add `--json` to a reading command (`wifi info`, `wifi known`, `wifi ip`, `eth info`, `hs status`, `lc why` and others) for machine-readable output. Add `--yes` to answer a confirmation in advance, and only after the person has agreed to that change. Without `--yes` and with no one to answer, a confirmation counts as no. Exit codes are 0 for success, 1 for a system error (including "needs administrator") and 2 for bad usage.

With `--json`, a failed command prints `{"ok": false, "exit_code": ..., "error": {"code": ..., "message": ...}}` on standard error. The `code` is one of `usage`, `not_found`, `ambiguous`, `needs_admin`, `access_denied`, `confirmation_required`, `plan_changed`, `nothing_to_undo`, `too_large`, `verify_failed`, `busy`, `timeout`, `unsupported` or `failed`. A change that goes through the change engine prints one object on standard output: `ok`, `status`, `journal_id`, `plan_hash`, `needs_admin`, `preflight`, `restart_needed`, `changes` (each with `before`, `after`, `status` and the read-back value) and `undo`. With `--json` and no `--yes`, a command that would ask a question stops with `confirmation_required` (exit 2) instead of guessing.

Prefer names, paths and keys to list positions in scripts: `svc Spooler`, `su user/run/OneDrive`, `vm chrome`, `reg get HKCU\... name`. Ids are numbered from the current list and shift.

### Location

```
lc                       list every location setting, with what it is set to now
lc why                   say why location is off or blocked, and what would fix it
lc on | lc off           location services for the whole PC (off needs administrator)
lc access on | lc access off   let apps use your location, or block all of them
lc apps                  list apps that have asked for location, with ids
lc apps 3 on | off       let app 3 use location, or block it
lc recent                apps that used location in the last 7 days
lc override on | off     allow location override (a remote device's location)
```

For scripts and AI agents, add `--json` to `lc`, `lc why` or `lc apps` for machine-readable output. The same goes for `vm ls` and `vm <id>`, `bn get` and `bn info`, `su ls` and `su <id>`, `apps ls`, `prc ls` (the list, not `/verbose`), `dvc` and `fw`. `--yes` answers the confirmations in `su rm`, `apps rm`, `prc kill`, and the `dvc` and `fw` changes. If a policy from an organisation (Group Policy or device management) is turning location off, `lc on` refuses and explains why. Only after the PC's owner agrees, `lc on --override-management` from an administrator terminal overrides it. The policy may be set back at the next refresh.

Location services is the master switch. `lc off` sets the Windows policy "Turn off location" (`DisableLocation` under `HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors`), the same value `gpedit.msc` writes. `lc on` sets it back to 0. Nothing is deleted. Windows applies policy changes at the next refresh, or run `gpupdate /force` to apply now.

Access for apps and the per-app switches are per user and need no administrator rights. Ids follow the list, so run `lc apps` first.

### Registry

Direct commands, for scripts and for people who know what they want. Paths start with a hive (`HKCU`, `HKLM`, `HKCR`, `HKU`, `HKCC`) and use backslashes.

```
reg ls HKCU\Software\Example              list a key's values and subkeys
reg get HKCU\Software\Example Port        show one value (--json for type and data)
reg set HKCU\Software\Example Port --type dword --value 8080
reg set HKCU\Software\Example Name --type sz --value "hello"
reg del HKCU\Software\Example Port        delete a value (asks first)
reg mkkey HKCU\Software\Example\New      create a key
reg rmkey HKCU\Software\Example\New      delete a key and everything under it (asks first)
```

Types are `sz`, `expand_sz`, `multi_sz` (items separated by `;`), `dword`, `qword` and `binary` (hex). Every change saves the old value first, so `reg set`, `reg del`, `reg mkkey` and `reg rmkey` all take `--dry-run`, `--json` and `--yes`, and `rb last` undoes them. A key with more than 2000 items inside is refused. Key security (ACLs) and timestamps are not saved. Whether a change needs a restart or sign-out depends on who reads the value, so it is always reported as unknown. Changing `HKLM` needs an administrator terminal, and the command says so before it asks anything.

Type `regedit` for the interactive editor. It lists the root hives with numbers. Type a number to open that key or show that value, `ls` to list, `cd` to move, and `0` or `exit` to leave.

```
regedit
Registry> 2                     open HKEY_CURRENT_USER
Registry HKCU> cd Software      move into a key (lists it)
Registry HKCU\Software> cd "Control Panel"    quotes keep spaces
Registry HKCU\Control Panel> add "Tag" dword 8080
Registry HKCU\Control Panel> get "Tag"         show a value
Registry HKCU\Control Panel> set Tag 9000
Registry HKCU\Control Panel> rm Tag            asks first
Registry HKCU\Control Panel> exit
```

Commands: `ls`, `cd`, `pwd`, `get`, `add`, `set`, `rm`, `mkdir`, `rmdir`, `help`, `clear`, `exit`. Deleting asks first, and a key with anything under it needs its name typed. The top two levels of a hive can't be deleted.

### Previewing, undoing and batches

Registry, service, startup and volume changes share one engine (`_ops.py`). Other pages do not use it yet, and `--dry-run` on them exits 2.

```
svc Spooler off --dry-run            show the exact change (before and after), what it needs, and stop
svc Spooler off --yes --json         apply it; the result says applied, failed or unverified, and whether a restart is needed
rb ls                                every saved change, newest first
rb show <id>                         one entry in full
rb last --dry-run                    what undoing the latest change would put back
rb last                              undo it (asks first; --yes answers in advance)
cs changes.json --dry-run            preview a batch; the result has a plan hash
cs changes.json --yes --expect <hash>   apply the batch only if it is still the plan that was previewed
cs changes.json --yes --atomic       if one change fails, put the earlier ones back
```

A batch file is `{"changes": [{"page": "services", "op": "state", "args": {"service": "Spooler", "state": "stopped"}}, ...]}`; `cs -` reads it from standard input. Every change is planned before anything is applied: one bad change, or two changes to the same target, stops the whole batch with nothing changed. The batch asks once for the group. Changes then run in order, each read back after it is made. The first failure stops the rest, which are reported as skipped. The result lists what succeeded, what failed, and the `rb` command that undoes it. Before it asks, it says which changes need administrator rights (and refuses if this terminal is not elevated) and which may cut connectivity.

Undo reads the current state first and warns if something changed it again since. Journals are kept in `%LOCALAPPDATA%\w11-cli-console\journal.json`, the last 200 entries.

### The command catalog

```
cat                       every page and its change operations
cat services              one page: its commands, and each operation's arguments
cat --json                the same as data, for an agent
```

Each change operation lists its arguments, whether it changes the system, whether it needs administrator rights, whether it needs a restart or sign-out, its side effects, and whether it takes `--dry-run`. Older read and change commands are listed from their help text with those fields set to `null` and `declared: false`, meaning nobody has said what they need; the catalog does not guess.

### Services

Type `svc` to list every Windows service with its id, state and startup type. Ids are numbered by name, so they shift when services are added or removed. A name works in place of an id.

```
svc ls                          list every service
svc 12                          show one service
svc search print                find services by name or display name
svc status Spooler Dhcp         state, process id and last exit code
svc failed                      set to start, but stopped with an error
svc failures 3                  service failure events from the last 3 days
svc stuck 20                    services still waiting to start or stop after 20 s
svc deps 12 | dependents 12     what it needs, and what needs it
svc tree 12                     the whole chain it waits for
svc exe 12                      the program it runs, and whether that file is on disk
svc triggers 12                 what starts it on demand
svc permissions 12             who may control it (raw security descriptor)
svc groups | accounts          services by load-order group, or by the account they run as
svc delayed | disabled          services set to delayed start, or never to start
svc 12 on                       start it
svc Spooler off                 stop it (asks first)
svc 12 restart                  stop and start it again
svc 12 auto                     start with Windows
svc 12 manual                   start only when something needs it
svc 12 disabled                 never start it (asks first)
svc Spooler delayed             start shortly after Windows has started
svc Spooler off --dry-run       show the exact change and stop (any change takes --dry-run, --json, --yes)
```

Listing, showing and every read-only view need no administrator rights. Starting, stopping, restarting and changing the startup type need an administrator terminal, and the page checks that before it announces anything. Stopping a service and setting one to disabled ask first. A stopped service can stop other programs from working until it starts again, and a disabled service stays off after a restart until it is set back to manual or auto. Setting it back undoes that, as does `rb last`. Boot, system and unknown start types (drivers) are refused. Stopping a connectivity service such as DHCP Client or DNS Client is flagged as likely to cut the network.

### Hardware

Type `hw` to see what the PC is made of and how it is doing: processor, graphics, memory, drives, motherboard, BIOS, USB and PCI devices, battery and sensors. Readings that Windows keeps from ordinary users say "needs administrator rights". Nothing here changes the PC.

```
hw cpu | hw cpu usage 10          the processor, its cores and caches; live use
hw cpu features | hw cpu topology  instruction sets, and cores, caches and NUMA nodes
hw gpu | hw gpu memory             graphics cards, video memory, displays and drivers
hw gpu processes | hw gpu errors   what uses the graphics card; graphics errors from the event log
hw ram | hw ram modules | hw ram pressure 5   memory in use, the sticks, and when memory runs short
hw ram test                        how to run Windows' memory test (it is not started here)
hw storage | hw storage inspect 2 drives, one in full; the health and temperature of each
hw storage performance 10 | hw storage errors 7   how busy the drives are; disk errors
hw storage space C:\Users          what is using the space in a folder
hw board | hw bios | hw firmware   motherboard, BIOS version and boot mode, and Secure Boot
hw pci | hw usb | hw battery | hw fans | hw sensors   devices and sensors
hw report                          everything above, as JSON
```

Health, temperature, BitLocker and failure prediction for the drives, and TPM details, need an administrator terminal. A desktop PC has no battery, and fan and temperature sensors depend on the board. Those readings say "not exposed on this PC" rather than failing.

### System

Type `sys` to see how Windows is running right now and whether anything needs attention.

```
sys health                      each check marked ok, warn or bad, with the reason
sys load 10                     CPU, memory, disk and GPU busy time, sampled for 10 s
sys load watch 120              watch for 2 minutes and list the moments that spiked, with the busiest process
sys processes 15                the processes using the most CPU and memory
sys uptime                      when Windows last started, and whether fast startup is on
sys startup                     programs and scheduled tasks that start with Windows or at sign-in
sys power                       the power plan, sleep and display timers, and sleep states
sys battery                     power source and charge
sys environment                 PATH entries that are duplicated, missing or refer to an unknown variable
sys inventory                   hardware, Windows, drivers and installed programs
```

`sys health` reads the event logs for the last day and week, and flags drive space under 20%, memory under 10% free, a restart waiting to finish, devices with problems, blue screens, GPU and service failures. A service failure points to `svc failures`, and boot history is in `evt boot`.

### Devices

Type `dvc` to list every device Windows knows about, the same list as Device Manager, with its id, state and class. Ids are numbered by name, so they shift when devices come and go. A name works in place of an id.

```
dvc ls                          every device, 40 to a page
dvc ls absent                   devices that are not connected right now
dvc ls class display            one class (display, monitor, usb, audio endpoint and so on)
dvc ls mfg advanced sort class  filter by manufacturer, and sort by class
dvc 12                          one device: its driver, what it plugs into, its status
dvc errors                      problem devices, disabled devices and missing drivers
dvc drivers                     every driver package: provider, version, date, file
dvc drivers 12                  one device's driver
dvc tree                        connected devices, by what they are plugged into
dvc search VID_1E71             find by name, class, hardware ID, vendor or driver provider
dvc usb | displays | audio | storage
dvc report                      the whole inventory as JSON, for scripts and agents
dvc 12 enable                   turn device 12 on (administrator)
dvc 12 disable                 turn it off (administrator; asks first, twice for keyboards, mice, network and screens)
dvc 12 restart                 restart it (administrator; asks first)
dvc driver add new.inf         install a driver package, which is how a driver is updated (administrator; asks first)
dvc driver rm 12               remove device 12's driver package (administrator; asks first)
```

Reading needs no administrator rights. "Disabled" means turned off in Device Manager, and "not connected" means the device is known to Windows but is not plugged in or present right now.

The changes use `pnputil`, the Windows tool that Device Manager's own commands use. Each change checks for administrator rights before it asks anything, reads the device back afterwards, and says what Windows reports now. `dvc driver rm` only removes packages you installed (`oem` packages); the ones that came with Windows are refused. Removing a driver can stop the device working until another driver is installed, so the question says so. A driver update here means installing a newer `.inf`; there is no "update driver" for a device that finds one on its own.

### Firewall

Type `fw` to see each network profile (domain, private, public): whether the firewall is on, what it does by default for incoming and outgoing traffic, and which networks this PC is connected to. The rules come after that.

```
fw                             each profile, and the networks this PC is on
fw rules                       every rule, numbered by name, 40 to a page
fw rules in block              incoming rules that block
fw rules off                   rules that are turned off
fw rules search print          find by name
fw rule 12                     one rule in full: its program, ports and addresses
fw rule 12 on | off            turn one rule on or off (administrator; asks first)
fw on | off public             turn the firewall on or off for one profile, or all three (administrator)
```

Reading needs no administrator rights. Turning a profile off asks first, and warns when you are on a public network. Turning the firewall off also stops every rule for that profile from applying, including the blocks that `net block` made. Rule ids are numbered by name, so they shift as rules come and go. Rules that `net block` made show up here too, marked as made by `net block`. Rules are not deleted from this page.

### Event logs

Type `evt` to see the commands. It reads the Windows event logs (the same logs as Event Viewer), and the answers keep the record number and provider of each event, so a result can be looked up again with `evt inspect`. Times can be `2h` (two hours ago), `3d`, `today`, or `2026-10-15 14:30`.

```
evt errors                      errors, critical events and warnings from the last day
evt errors --level critical --source Kernel-PnP --since 3d
evt recent 100 --oldest         the newest 100 events, shown oldest first
evt search disk                 find text in messages, ids, providers and computer names
evt inspect 4312 --log System   one event in full, with its fields and XML
evt crashes                     application crashes, with the faulting module and exception code
evt shutdowns                   clean and unexpected shutdowns, restarts and blue screens
evt boot                        each boot, how the one before ended, and problems in its first 10 minutes
evt drivers | evt services | evt network
evt security --failed           failed sign-ins (the Security log)
evt correlate --by process      group events by time, provider, id, process or activity
evt timeline "2026-10-15 14:30" everything within 15 minutes of that moment
evt frequency                   repeated errors, and spikes in them
evt baseline save, then evt baseline
evt filter --log System --id 7045 --user SYSTEM --since 7d --json
evt export report.csv --since 1d
evt watch --level error         print new errors as they happen (Ctrl+C stops)
evt list providers              every log and the providers that write to it
evt clear Application --backup Application.evtx
```

Most logs need no administrator rights. The Security log, and the Diagnostics-Performance log (which holds boot times), do: the page says so when it cannot read them. `evt clear` needs administrator rights and asks you to type the log's name. Clearing cannot be undone, so it wants a copy with `--backup` (or `--no-backup`). `--yes` does not skip it.

Windows writes event messages in the language of the PC, and not every provider's message file is installed, so some messages are blank. The baseline is saved to `%LOCALAPPDATA%\w11-cli-console\events-baseline.json`, outside this folder.

### Network monitor

`net` opens this page. `nm` and `traffic` work too.

```
net                        overview: interfaces, connections, busiest programs, findings
net live [seconds]         live view, redrawn every 2 s (Ctrl+C stops and saves a sample)
net ls                     every connection, with program, domain and how long it has been open
net ls --sort seen         longest open first (also: program, remote, port, state, domain, proto)
net ls --state listen --loopback --process svchost.exe --ip 192.168.1.50 --proto tcp
net 12                     one connection in full: its program, why it exists, what you can do
net procs                  traffic by program: connections, peers, domains, and what each one is
net iface                  Wi-Fi and Ethernet: speed, bytes since Windows started, rate now
net history [days]         totals and busiest programs from earlier net live sessions
net history clear          delete the saved samples (asks first)
net kill 12                end the program that owns connection 12 (asks first; Windows parts refused)
net block 12               block the remote address of connection 12, in and out (administrator; asks first)
net block 203.0.113.9      block an address directly
net block ls               list the blocks this page made
net unblock 203.0.113.9    remove them
```

`net ls` hides connections that stay on this PC; `--loopback` shows them. Ids follow the list, so check the program in `net 12` before you kill or block. A few addresses are refused, so blocking cannot cut this PC off: its own addresses, its router, and its DNS servers.

What it can and cannot tell you:

- **Bytes** are counted per adapter (`net iface`, and `net history`). Windows does not give ordinary users byte counts per connection or per program, so `net procs` shows connections and peers instead.
- **Domains** come from the names Windows looked up recently (its DNS cache), then from a reverse lookup of the address. Some addresses have no name.
- **"Open for"** is the time since `net` first saw a connection. It is not the time since the connection began, which Windows does not report.
- **Why it exists** is a best guess from the port, the program and the address. It says "usually" and "likely" because a program can use any port.
- **Blocks** are Windows Firewall rules named `w11-cli-console-block-<ip>-out` and `-in`. `net unblock` removes them.

Samples are saved to `%LOCALAPPDATA%\w11-cli-console\net-history.jsonl` once a minute while `net live` runs, and kept for 30 days. The first-seen times are in `net-seen.json` in the same folder.

## Tests

```powershell
py -m unittest discover -s tests -t .
```

The tests fake Windows (the registry, `sc`, audio sessions, the Startup folder), so they run anywhere and prove the logic, the exit codes, the confirmation questions, rollback and a failure partway through a batch. They do not prove that Windows accepts the calls. `tests/SMOKE.md` is the checklist to run on a disposable Windows 11 machine; it has not been run yet.

## Adding a setting

Create a `.py` file in this folder. `app.py` loads it automatically. It needs:

```python
NAME = "mysetting"          # command name
ALIASES = ["ms"]            # optional short names
SUMMARY = "what it does"
USAGE = "ms <args>"
HELP = [("ms <args>", "what this does")]   # the blue intro shown when the name is typed alone
TIP = "optional: one line of example or advice"

def run(args):             # args = words after the name
    ...
    return 0                # exit code: 0 ok, 1 device error, 2 bad usage
```

## Files

- `app.py`: the console and command routing
- `_core.py`: code shared by app.py and the pages (finding pages, drawing intros, --json and --yes)
- `_ops.py`: the change engine: plan, preview, journal, apply with read-back, rollback, batches
- `batch.py`, `rollback.py`, `catalog.py`: the `cs`, `rb` and `cat` pages
- `tests/`: unit tests with Windows faked (`py -m unittest discover -s tests -t .`), and `tests/SMOKE.md`, a checklist for a disposable Windows machine
- `_net.py`: code shared by the wifi and ethernet pages (adapter details, IP, DNS, sharing, features, 802.1X)
- `intro.txt`: the banner shown when the console starts
- `settings.py`: the `settings` list, which shows every setting
- `brightness.py`, `volume.py`, `startup.py`, `apps.py`, `process.py`, `wifi.py`, `ethernet.py`, `hotspot.py`, `location.py`, `regedit.py`, `services.py`, `device.py`, `events.py`, `hardware.py`, `system.py`, `netmon.py`, `firewall.py`: settings
- `_probe.py`: code shared by hardware and system (one PowerShell call per group of readings, the processor API, power status, tables)
- `fashion.txt`: the pattern every new page follows, and what each setting is for
- `brightness.ahk`: the older AutoHotkey version of brightness
- `requirements.txt`: Python packages (`pycaw`, `psutil`, `comtypes`, and the `winrt` packages the hotspot uses)
