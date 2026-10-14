# w11-cli-console

Change Windows 11 settings from the command line. `app.py` is the settings page: run it, then use a setting by name or alias.

## Setup

```powershell
py -m pip install -r requirements.txt
py app.py
```

## Commands

| Setting | Aliases | What it does |
|---|---|---|
| brightness | `bn`, `b`, `bright`, `screen`, `monitor`, `display` | Screen brightness |
| volume | `vm` | System and per-app volume |
| startup | `su` | Apps that start with Windows |

Run `py app.py` for an interactive console, or pass a command directly, e.g. `py app.py bn 40`. Use `help` to list everything.

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
```

This changes the same switch as Task Manager's Startup tab, so nothing is deleted. Changes apply at the next sign-in. All-users apps need an administrator terminal.

## Adding a setting

Create a `.py` file in this folder. `app.py` loads it automatically. It needs:

```python
NAME = "mysetting"          # command name
ALIASES = ["ms"]            # optional short names
SUMMARY = "what it does"
USAGE = "ms <args>"

def run(args):             # args = words after the name
    ...
    return 0                # exit code: 0 ok, 1 device error, 2 bad usage
```

## Files

- `app.py`: the settings page and console
- `intro.txt`: the banner shown when the console starts
- `brightness.py`, `volume.py`, `startup.py`: settings
- `brightness.ahk`: the older AutoHotkey version of brightness
- `requirements.txt`: Python packages (`pycaw`)
