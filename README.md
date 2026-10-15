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
| brightness | `bn`, `b`, `bright`, `screen`, `monitor`, `display` | Screen brightness |
| volume | `vm`, `vol` | System and per-app volume |
| startup | `su`, `start` | Apps that start with Windows |
| apps | `app` | Installed apps, and uninstalling them |
| process | `prc` | Running processes, ending them, live system stats |
| wifi | `net`, `internet`, `wf` | Join Wi-Fi, known networks, and every Wi-Fi setting |
| ethernet | `eth`, `lan`, `wired` | Wired network: details, IP, DNS, 802.1X, metered |
| hotspot | `hs`, `mobilehotspot` | Share this PC's internet as a Wi-Fi hotspot |
| settings | `menu` | Every setting in one list, and how to open each |
| location | `lc` | Location services, which apps can use it, and the override |
| regedit | — | Interactive Windows Registry Editor |

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

Add `--json` to a reading command (`wifi info`, `wifi known`, `wifi ip`, `eth info`, `hs status`, `lc why` and others) for machine-readable output. Add `--yes` to answer a confirmation in advance, and only after the person has agreed to that change. Without `--yes` and with no one to answer, a confirmation counts as no. Exit codes are 0 for success, 1 for a system error (including "needs administrator") and 2 for bad usage.

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

For scripts and AI agents, add `--json` to `lc`, `lc why` or `lc apps` for machine-readable output. If a policy from an organisation (Group Policy or device management) is turning location off, `lc on` refuses and explains why. Only after the PC's owner agrees, `lc on --override-management` from an administrator terminal overrides it. The policy may be set back at the next refresh.

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
- `intro.txt`: the banner shown when the console starts
- `settings.py`: the `settings` list, which shows every setting
- `brightness.py`, `volume.py`, `startup.py`, `apps.py`, `process.py`, `wifi.py`, `ethernet.py`, `hotspot.py`, `location.py`, `regedit.py`: settings
- `fashion.txt`: the pattern every new page follows, and what each setting is for
- `brightness.ahk`: the older AutoHotkey version of brightness
- `requirements.txt`: Python packages (`pycaw`, `psutil`, `comtypes`, and the `winrt` packages the hotspot uses)
