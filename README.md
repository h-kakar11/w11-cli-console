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
| wifi | `net`, `internet`, `wf` | Join and leave Wi-Fi networks, forget saved ones |
| settings | `menu` | Every setting in one list, and how to open each |

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
- `_core.py`: code shared by app.py and the settings page (finding pages, drawing intros)
- `intro.txt`: the banner shown when the console starts
- `settings.py`: the `settings` list, which shows every setting
- `brightness.py`, `volume.py`, `startup.py`, `apps.py`, `process.py`, `wifi.py`: settings
- `fashion.txt`: the pattern every new page follows, and what each setting is for
- `brightness.ahk`: the older AutoHotkey version of brightness
- `requirements.txt`: Python packages (`pycaw`)
