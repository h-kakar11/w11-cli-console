# w11-cli-console

## this is just a cli that you can use to alter loads of settings on w11.

the aim is to try and replace the windows settings app by having a CLI instead, with more functionality, and more customisation. 

## brightness

`brightness.ahk` is a command-line screen brightness tool for Windows 11, ported from the brightness code in the [top bar](https://github.com/h-kakar11/ahk-top-bar-windows11) AutoHotkey script. It needs [AutoHotkey v2](https://www.autohotkey.com/).

```
AutoHotkey64.exe brightness.ahk get            # print current brightness (0-100)
AutoHotkey64.exe brightness.ahk set 40         # set brightness to 40
AutoHotkey64.exe brightness.ahk up 10          # raise by 10 (default step: 5)
AutoHotkey64.exe brightness.ahk down           # lower by 5
AutoHotkey64.exe brightness.ahk info           # print backend: ddc or wmi
```

- **DDC/CI first.** External monitors are driven over the video cable through `dxva2`. Many monitors ship with DDC/CI switched off in their OSD menu, so turn it on there if the command reports no control.
- **WMI fallback.** Laptop built-in panels are controlled through `WmiMonitorBrightness`.
- Exit codes: `0` success, `1` a device error (or no control found), `2` bad usage. Results go to stdout, errors to stderr.
- Commands act on the primary monitor, and only its first physical monitor, matching the top bar.
- The default step size is set by `DEFAULT_STEP` at the top of `brightness.ahk`.
