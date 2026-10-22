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
| regedit | — | Interactive Windows Registry Editor |
| services | `svc` | Windows services: list, search, status, dependencies, failures, start, stop, restart, startup type |
| hardware | `hw` | Processor, graphics, memory, drives, motherboard, BIOS, USB, sensors, and a full report |
| system | `sys` | Uptime, load, processes, startup programs, power, PATH, inventory, and an overall health check |
| device | `dvc` | Devices and drivers, as in Device Manager: status, errors, tree, search, and turning a device on, off or restarting it |
| firewall | `fw` | Windows Firewall: turn a network profile on or off, list the rules, and turn one rule on or off |
| events | `evt` | Windows event logs: errors, crashes, shutdowns, boots, timelines, export and watch |
| netmon | `net`, `nm`, `traffic` | Live network monitor: connections, programs and domains, bytes per program, traffic per adapter, kill and block |
| defender | `def`, `av`, `wd` | Windows Defender: status, scans, threats, protection switches, exclusions, schedule, SmartScreen and device security |
| privacy | `priv`, `perm`, `permissions` | App permissions: which apps can use the camera, microphone, location and more, what is using them now, and the general privacy settings |
| display | `dsp`, `res`, `resolution` | Resolution, refresh rate, rotation, HDR, arrangement and scale of each screen |
| bluetooth | `bt` | Bluetooth: turn it on or off, list, scan, pair and remove devices, and find out why it is not working |
| sound | `snd`, `audio` | Sound devices: choose the default speakers and microphone, device volume and mute, level meters, and why there is no sound |
| environment | `env`, `vars` | Environment variables and PATH: set, delete, edit the PATH, with a backup before every change and undo |
| update | `wu`, `winupdate`, `updates` | Windows Update: pending updates, history, install, hide, uninstall, pause, and why updates are stuck |

Every name can be shortened as shown, and `ls` can be written as `list`. `rm` can also be written as `remove`, `delete`, `uninstall` or `del`. So `vm list` and `volume ls` do the same thing.

Run `py app.py` for an interactive console, or pass a command directly, e.g. `py app.py bn 40`. Type `settings` to see every setting, numbered, with what it does. Type a setting's name on its own, such as `vm` or `wifi`, to see a short blue list of what it can do. Use `help` to list everything. `settings search night light` finds the setting and command for something you want to do, and `settings --json` lists every setting and command as data.

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
```

Each app is one id, even if it has several audio sessions. Ids are alphabetical, so they can shift when apps start or stop playing. Run `vm ls` first.

### Startup

```
su ls          list startup apps with id and state
su 3           show whether app 3 is enabled
su 3 off       stop app 3 starting at sign-in
su 3 on        start it at sign-in again
su rm 3        remove app 3 from startup entirely (asks you to confirm first)
```

This changes the same switch as Task Manager's Startup tab, so nothing is deleted. Changes apply at the next sign-in. All-users apps need an administrator terminal.

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

Start with `settings --json`: every setting, its short forms and every command with what it does, as data (`settings dsp --json` gives one). `settings search <words>` finds the command for a task, and `--json` works there too.

Add `--json` to a reading command (`wifi info`, `wifi known`, `eth info`, `hs status`, `lc why`, `fw`, `dvc ls`, `net`, `def`, `priv`, `dsp`, `bt ls`, `snd`, `env ls`, `wu` and others) for machine-readable output with the same keys every time: no colour and no prose, and the questions and progress lines go to stderr. Add `--yes` to answer a confirmation in advance, and only after the person has agreed to that change. Without `--yes` and with no one to answer, a confirmation counts as no. A few questions are never answered by `--yes` because a person has to decide them: pairing with a code to compare (`bt pair`, which takes `--code` instead), deleting a protected variable (`env rm Path`), and the Event Viewer log clear. Exit codes are 0 for success, 1 for a system error (including "needs administrator") and 2 for bad usage.

Pages whose bare name is a status (`fw`, `net`, `lc`, `def`, `priv`, `dsp`, `bt`, `snd`, `wu`) run it when typed alone, and `<name> help` shows the intro. Every change reads the setting back and reports what Windows says now.

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

### Registry editor

Type `regedit` to open an interactive editor. It lists the root hives with numbers. Type a number to open that key or show that value, `ls` to list, `cd` to move, and `0` or `exit` to leave.

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

Commands: `ls`, `cd`, `pwd`, `get`, `add`, `set`, `rm`, `mkdir`, `rmdir`, `help`, `clear`, `exit`. Types are `sz`, `expand_sz`, `multi_sz` (items separated by `;`), `dword`, `qword` and `binary` (hex). Deleting asks first, and a key with anything under it needs its name typed. The top two levels of a hive can't be deleted. The editor uses Windows' own permissions, so changing `HKLM` needs an administrator terminal.

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
```

Listing, showing and every read-only view need no administrator rights. Starting, stopping, restarting and changing the startup type need an administrator terminal, and the page checks that before it announces anything. Stopping a service and setting one to disabled ask first. A stopped service can stop other programs from working until it starts again, and a disabled service stays off after a restart until it is set back to manual or auto. Setting it back undoes that.

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
dvc 12 disable                  turn it off (administrator; asks first, twice for keyboards, mice, network and screens)
dvc 12 restart                  restart it (administrator; asks first)
dvc rescan                      scan for hardware changes and say what appeared (administrator)
dvc rollback 12                 put back the driver device 12 had before its current one (administrator; asks first)
dvc driver add new.inf          install a driver package, which is how a driver is updated (administrator; asks first)
dvc driver rm 12                remove device 12's driver package (administrator; asks first)
dvc drivers export D:/drivers   copy the drivers you installed into a folder; add an id for just that device's (administrator; asks first)
dvc backup                      save an inventory of every device and driver as a JSON snapshot
dvc backup ls | rm 2            list the saved snapshots, or delete one (asks first)
dvc diff                        what changed since the newest snapshot: new and missing devices, state, drivers, problems
dvc diff 2 | dvc diff old.json  compare with an older snapshot or a file
```

Reading needs no administrator rights. "Disabled" means turned off in Device Manager, and "not connected" means the device is known to Windows but is not plugged in or present right now.

The changes use `pnputil`, the tool Device Manager's own commands use (the rollback uses Windows' driver-installation API). Each change checks for administrator rights before it asks, reads the device back, and says what Windows reports now. When a change worked but needs a restart, the page says so. `driver rm` and `drivers export` only touch packages you installed (`oem`); ones that came with Windows are refused. Removing a driver can stop the device working until another driver is installed, so the question says so. A driver update here means installing a newer `.inf`; Windows Update's own driver updates are `wu ls` and `wu install drivers`. `dvc backup` saves a JSON snapshot to `%LOCALAPPDATA%\w11-cli-console\device-snapshots`, outside this folder, with no administrator rights. `dvc diff` lists new devices, devices Windows no longer lists, state changes (an unplugged device is 'no longer connected', not 'removed'), driver changes and problems that appeared or went away. `dvc rollback` only works when Windows kept the previous driver. In the console, type folder paths with forward slashes (`D:/drivers`), because the console eats backslashes.

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
net bytes [seconds]        bytes per program and address, measured for 10 s with a Windows trace session (administrator)
net bytes last | clear     show the last measurement, or delete it
net ls --bytes             add the measured bytes to the connection list
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

- **Bytes** per adapter need no administrator rights (`net iface`, `net history`). Per program, address and protocol they come from `net bytes`, a measurement window of 10 s by default. It runs a Windows trace session with logman and always stops it. Counts are payload only, TCP and UDP, loopback excluded unless `--loopback`. `net procs` and `net <id>` show the last result for an hour. If a run is killed hard, `logman stop w11-cli-console-net -ets` stops the session.
- **Domains** come from the names Windows looked up recently (its DNS cache), then from a reverse lookup of the address. Some addresses have no name.
- **"Open for"** is the time since `net` first saw a connection. It is not the time since the connection began, which Windows does not report.
- **Why it exists** is a best guess from the port, the program and the address. It says "usually" and "likely" because a program can use any port.
- **Blocks** are Windows Firewall rules named `w11-cli-console-block-<ip>-out` and `-in`. `net unblock` removes them.

Samples are saved to `%LOCALAPPDATA%\w11-cli-console\net-history.jsonl` once a minute while `net live` runs, and kept for 30 days. The first-seen times are in `net-seen.json` in the same folder.

### Windows Defender

```
def                        is Defender protecting this PC, and what needs attention
def why                    what is wrong, and the command that fixes each thing
def scan | scan full | scan C:\Downloads   start a scan in the background (--wait stays until done)
def scan status | stop     is a scan running; end it
def update                 get the newest virus signatures
def threats | threats 2    what Defender found; one detection in full
def quarantine | clean     threats still active; remove every active threat (asks)
def off realtime           turn a protection off (asks); def on realtime turns it on
def cloud advanced | samples never | pua audit | network on | folders on
def exclusions add path D:\Work | rm 1
def schedule day sun time 02:00 type full
def asr 3 audit | smartscreen | device | tamper | events 7 protection
def open settings          open the Windows Security app
```

Reading needs no administrator rights, except the exclusion list and the TPM. Every change needs an administrator terminal, and the page checks that before it asks anything. Turning protection off, adding an exclusion and `def clean` ask first. Tamper Protection can only be changed in the Windows Security app, and the page tells you when it is the reason a change was refused. A policy from an organisation is also reported, not overridden. `def clean` removes all active threats at once. Restoring from quarantine is done in the Security app. `def offline` restarts the PC immediately.

### Privacy

```
priv                          every permission: who may use it, and what is using it right now
priv now                      what is using your camera, microphone, location or screen this second
priv recent [days] [all]      sensitive permissions apps used lately (7 days by default)
priv sensitive                camera, microphone, location, screen capture: who can use each
priv camera                   one permission: its switches, and every app that has asked, numbered
priv camera off | on          block, or allow, all your apps for the camera
priv camera 3 off             block one app (ids come from 'priv camera'; a name works too)
priv camera desktop on|off    "Let desktop apps access your camera"
priv camera device on|off     the switch for every user of this PC (administrator; asks first)
priv why camera [3]           why apps (or app 3) cannot use it, and the command that fixes it
priv app zoom                 everything one app can access
priv app zoom off             block that app from everything (asks first)
priv general                  advertising ID, tailored experiences, language list, app launch tracking,
                              diagnostic data, activity history
priv general ads off          turn one of them off
priv general diagnostics required | default    (administrator; sets a Windows policy)
priv open camera              open that page in Settings
```

Windows keeps a chain of switches for each permission, and the first one that says no wins. The order is: an organisation policy, the switch for this PC, your switch for all apps, the switch for desktop programs, then the app itself. Your switches and the app switches need no administrator rights; only `device` does, and the page checks that before it asks. Turning a permission off asks nothing. Turning one on asks first, as does allowing a sensitive app.

Where a policy owns a switch, the page refuses and says why. It never works around a policy. `diagnostics` and `activity` can only be changed through a Windows policy, which Settings then shows as managed. The page says so before it asks, and `default` removes the policy value again. Windows records when each app last started and stopped using a permission. An app that started and has not stopped is "in use". A desktop program marked in use that is not running is listed as not counted, because it stopped without Windows noticing. Windows keeps only the latest use per app, not a full history. Location is read here and changed with `lc`.

### Display

```
dsp                       each display: resolution, refresh rate, scale, HDR, position, what could be better
dsp 1                     one display in full
dsp 1 modes               supported resolutions and refresh rates (--all adds unusual modes)
dsp 1 res 1920x1080       change the resolution (1080p, 1440p, 4k work; 1920x1080@144 sets the rate too)
dsp 1 hz 144              change the refresh rate
dsp 1 rotate portrait     0, 90, 180, 270 (landscape, portrait, flipped)
dsp 2 right-of 1          place a display (left-of, above, below), or dsp 2 pos 2560 0
dsp 2 primary             make display 2 the main display
dsp layout                draw where the displays sit
dsp 1 hdr on|off          HDR
dsp project extend        Win+P: extend, duplicate, internal (PC screen only), external
dsp scale                 each display's scale and the one Windows recommends
dsp nightlight            opens Settings (no API for Night light)
dsp brightness 40         the same as bn
```

Nothing needs administrator rights. Without an id the main display is used. A change is applied unsaved and goes back after 15 seconds unless you press `y`, as in Settings, so a bad mode cannot leave a black screen. `--yes` tests and saves at once. Scale and Night light have no documented API, so they open the right Settings page. Ids follow the Windows names, so they shift when a display is plugged in or out.

### Bluetooth

```
bt                          the radio, and your paired devices
bt on | off                 turn Bluetooth on or off
bt ls                       paired devices: kind, connected or not, battery, address
bt 3                        one device in full (an id, a name or an address works)
bt scan [seconds] [--all]   look for nearby devices that are in pairing mode (10 s by default)
bt pair 2                   pair with number 2 from the last scan (asks first)
bt pair AA:BB:CC:DD:EE:FF --pin 0000    --pin gives a PIN; --code gives the number the device shows
bt rm 3                     unpair device 3 (asks first)
bt why                      Bluetooth is not working: what is wrong and what fixes it
bt service [restart]        the Bluetooth Support Service (restart needs administrator)
bt connect 3 | disconnect 3 shows the state and opens Settings
bt send [file] | receive    Windows' Bluetooth File Transfer wizard
bt more | open              the classic Bluetooth Settings dialog, or the Settings page
```

Nothing here needs administrator rights except restarting the service. Put the device in pairing mode before `bt scan` can see it. Ids are numbered by name and shift when devices come and go, so run `bt ls` first. `bt scan` numbers are for `bt pair` only. Turning Bluetooth off asks first when devices are connected, because a Bluetooth keyboard or mouse stops working. `--yes` never answers a "does the code match?" question, because a person has to compare the numbers; a person can read the number to an agent, which passes it with `--code`. Windows has no documented way for a program to connect or disconnect a device that is already paired, so `bt connect` and `bt disconnect` open Settings. Battery comes from a property many devices fill in and Microsoft does not document, so "-" means "the device does not say". Removing a device means pairing it again.

### Sound

```
snd                          playback and recording devices, default ones marked
snd 3                        one device: format, volume, level
snd default 2                make device 2 the default (add "calls" for the calls device only)
snd 3 volume 40              set a device's volume (snd 3 40 works too); mute | unmute | toggle
snd out | snd in            the default speakers / microphone on one line; snd out volume 40
snd level 10                 live level meter; "snd level listen" opens the microphone
snd test                     play a short tone through the default output
snd why                      no sound? the usual causes with fixes; snd why in for a silent microphone
snd mono                     whether Mono audio is on (changing it opens Settings)
snd startup off              turn the startup sound off as a policy (administrator)
snd classic recording        the classic Sound dialog
snd apps | snd disable 3 | snd open    pages of Settings, where Windows has no API
```

Nothing here needs administrator rights except `snd startup`. Ids are numbered playback first, then recording, so they shift: run `snd` first. A name works too. One app's volume is `vm`. Windows has no documented way to choose the default device. `snd default` uses an undocumented interface that SoundVolumeView and SoundSwitch also use. It reads the default back, and if Windows did not change it, it opens Settings > System > Sound. Mono audio, per-app output devices and turning a device on or off have no documented way either, so those open the right Settings page. A microphone level of 0% can mean no program is using the microphone. `snd level listen` opens it for the measurement, shows Windows' microphone indicator, records nothing, and asks first.

### Environment variables

```
env ls                                        your variables and the PC's, numbered
env ls system search java                     one scope, or search names and values
env JAVA_HOME                                 one variable in full (env show Path for the variable called Path)
env set JAVA_HOME "C:\Java\jdk-21"            set a variable for you (add --system for everyone; administrator)
env rm JAVA_HOME                              delete it (asks first)
env path                                      PATH entries in order; missing folders and duplicates flagged
env path add "C:\Tools" --front               add a folder (--front searches it first)
env path rm 3 | move 3 up | clean             remove, reorder, or drop empty/missing/duplicate entries
env where Path | env find tools | env expand "%USERPROFILE%\bin"
env backups | env diff | env undo             every change saves the whole scope first
env export vars.json | env import vars.json
```

Reading needs no administrator rights; system changes do, checked before asking. A new program gets system variables then yours (yours win, except PATH, where yours come after the system's). Open terminals keep their old copy, so open a new one. In the console, put paths in quotes or the backslashes are lost. Every change saves a JSON backup of the whole scope first, and `env undo` run twice goes forward again. Names Windows relies on (Path, PATHEXT, ComSpec, windir and the like) need their name typed, and `--yes` does not answer for them. Import skips protected names.

### Windows Update

Type `wu` to see how updates are doing: the Windows version, when Windows last checked, whether a restart is waiting, whether updates are paused or managed by an organisation, and the services Windows Update runs on. It starts with a verdict and the command that fixes anything wrong.

```
wu                          status and verdict
wu ls                       search for pending updates (up to a minute), numbered
wu 3 | wu KB5031356         one update: size, severity, whether it needs a restart
wu install 3                download and install update 3 (administrator; asks first)
wu install all              every regular update (not drivers, optional or feature updates)
wu install drivers          the driver updates Windows offers
wu history 30 | wu failed   recent installs and their results | only the failures, with their codes explained
wu installed                updates Windows lists as installed
wu hide 3 | wu unhide 1 | wu hidden    keep an update from being offered, and bring it back (administrator)
wu uninstall KB5031356      remove an installed update (administrator; asks first)
wu pause 14 | wu resume     pause updates up to 35 days (administrator)
wu options                  active hours, optional updates, restart notices, Delivery Optimization
wu options microsoft on     updates for other Microsoft products (administrator)
wu drivers off              leave drivers out of Windows Update (administrator; asks first)
wu services | wu why        the services, and every reason updates might be stuck
wu open options             open that Settings page (history, options, optional, restart, delivery)
```

Reading and searching need no administrator rights. Installing, uninstalling, hiding, pausing and the two options that change something need an administrator terminal, and the page checks that before it asks anything. Ids come from the last `wu ls`, and every action searches again and matches the update's own id, so a shifted id never installs the wrong update; a KB number always works. This page never restarts the PC: it says when a restart is needed.

Pausing uses the documented Windows Update for Business policy (a start date, to which Windows adds 35 days), not the private values Settings keeps. Settings may therefore say "Some settings are managed by your organization" and may not show the date; `wu` does. Windows Home ignores that policy, so on Home `wu pause` opens Settings instead. `wu resume` removes exactly what `wu pause` wrote and never touches an organisation's policy. Uninstalling uses `wusa`; Windows no longer removes many updates silently, and then the page opens the update history in Settings. Times from the Windows Update Agent are read as UTC.

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
- `_net.py`: code shared by the wifi and ethernet pages (adapter details, IP, DNS, sharing, features, 802.1X)
- `_win.py`: code shared by the newer pages (PowerShell, the registry, Settings links, small data files)
- `intro.txt`: the banner shown when the console starts
- `settings.py`: the `settings` list, which shows every setting
- `brightness.py`, `volume.py`, `startup.py`, `apps.py`, `process.py`, `wifi.py`, `ethernet.py`, `hotspot.py`, `location.py`, `regedit.py`, `services.py`, `device.py`, `events.py`, `hardware.py`, `system.py`, `netmon.py`, `firewall.py`, `defender.py`, `privacy.py`, `display.py`, `bluetooth.py`, `sound.py`, `environment.py`, `update.py`: settings
- `_probe.py`: code shared by hardware and system (one PowerShell call per group of readings, the processor API, power status, tables)
- `fashion.txt`: the pattern every new page follows, and what each setting is for
- `brightness.ahk`: the older AutoHotkey version of brightness
- `requirements.txt`: Python packages (`pycaw`, `psutil`, `comtypes`, and the `winrt` packages the hotspot and Bluetooth pages use)
