#Requires AutoHotkey v2.0
#SingleInstance Off

; ======================================================================
; brightness.ahk — command-line screen brightness for Windows 11
; Ported from the brightness code in "top bar.ahk".
;
;   brightness.ahk get            print current brightness (0-100)
;   brightness.ahk set 40         set brightness to 40
;   brightness.ahk up [step]      raise brightness (default step: 5)
;   brightness.ahk down [step]    lower brightness (default step: 5)
;   brightness.ahk info           print which backend is in use (ddc / wmi)
;
; DDC/CI is tried first (external monitors over the video cable), then
; WMI (laptop built-in panels). Many monitors ship with DDC/CI switched
; off in their OSD menu.
; ======================================================================

; ======================================================================
; CONFIG
; ======================================================================
DEFAULT_STEP := 5   ; percent per up/down when no step is given

; ======================================================================
; ENTRY
; ======================================================================
ExitApp(Run())

Run() {
    global DEFAULT_STEP
    if A_Args.Length = 0
        return Fail(Usage(), 2)

    cmd := StrLower(A_Args[1])
    arg := A_Args.Has(2) ? A_Args[2] : ""

    if (cmd = "help" || cmd = "-h" || cmd = "--help") {
        Out(Usage())
        return 0
    }
    if !(cmd = "get" || cmd = "set" || cmd = "up" || cmd = "down" || cmd = "info")
        return Fail("unknown command: " A_Args[1] "`n" Usage(), 2)

    if cmd = "set" {
        if !IsNumber(arg)
            return Fail("set needs a number from 0 to 100", 2)
    } else if cmd = "up" || cmd = "down" {
        if arg = ""
            arg := DEFAULT_STEP
        if !IsNumber(arg)
            return Fail(cmd " needs a number for the step size", 2)
    }

    ctx := OpenBrightness()
    try {
        if ctx["mode"] = ""
            return Fail("no brightness control found. Turn on DDC/CI in the monitor's OSD menu, or run on a laptop panel.", 1)

        switch cmd {
            case "info":
                Out(ctx["mode"])
            case "get":
                Out(GetBrightness(ctx))
            case "set":
                Out(SetBrightness(ctx, arg))
            case "up":
                Out(SetBrightness(ctx, GetBrightness(ctx) + arg))
            case "down":
                Out(SetBrightness(ctx, GetBrightness(ctx) - arg))
        }
        return 0
    } catch Error as e {
        return Fail(e.Message, 1)
    } finally {
        CloseBrightness(ctx)
    }
}

Usage() {
    return "usage: brightness.ahk <get | set N | up [step] | down [step] | info>"
}

Out(text) {
    FileAppend(text "`n", "*")
}

Fail(text, code) {
    FileAppend("error: " text "`n", "**")
    return code
}

; ======================================================================
; BRIGHTNESS — DDC/CI first, then WMI. Same logic as the top bar, but
; the monitor handles are opened per command and released in CloseBrightness
; because a CLI process is short-lived.
; ======================================================================
OpenBrightness() {
    ctx := Map("mode", "", "handle", 0, "arr", 0, "count", 0, "min", 0, "max", 100)
    try {
        hmon := DllCall("MonitorFromWindow", "Ptr", 0, "UInt", 1, "Ptr")   ; PRIMARY
        if hmon && DllCall("dxva2\GetNumberOfPhysicalMonitorsFromHMONITOR", "Ptr", hmon, "UInt*", &n := 0) && n {
            arr := Buffer(n * (A_PtrSize + 256), 0)
            if DllCall("dxva2\GetPhysicalMonitorsFromHMONITOR", "Ptr", hmon, "UInt", n, "Ptr", arr) {
                h := NumGet(arr, 0, "Ptr")
                if DllCall("dxva2\GetMonitorBrightness", "Ptr", h, "UInt*", &mn := 0, "UInt*", &cur := 0, "UInt*", &mx := 0) {
                    ctx["mode"] := "ddc", ctx["handle"] := h, ctx["arr"] := arr, ctx["count"] := n
                    ctx["min"] := mn, ctx["max"] := (mx > mn ? mx : 100)
                    return ctx
                }
                DllCall("dxva2\DestroyPhysicalMonitors", "UInt", n, "Ptr", arr)
            }
        }
    }
    try {
        for b in ComObjGet("winmgmts:\\.\root\wmi").ExecQuery("SELECT * FROM WmiMonitorBrightness") {
            ctx["mode"] := "wmi"
            return ctx
        }
    }
    return ctx
}

CloseBrightness(ctx) {
    if (ctx["mode"] = "ddc" && ctx["arr"])
        try DllCall("dxva2\DestroyPhysicalMonitors", "UInt", ctx["count"], "Ptr", ctx["arr"])
}

GetBrightness(ctx) {
    if ctx["mode"] = "ddc" {
        if DllCall("dxva2\GetMonitorBrightness", "Ptr", ctx["handle"], "UInt*", &mn := 0, "UInt*", &cur := 0, "UInt*", &mx := 0) {
            span := mx - mn
            return span > 0 ? Round((cur - mn) * 100 / span) : cur
        }
        throw Error("DDC/CI read failed")
    }
    for b in ComObjGet("winmgmts:\\.\root\wmi").ExecQuery("SELECT * FROM WmiMonitorBrightness")
        return b.CurrentBrightness
    throw Error("WMI brightness read failed")
}

SetBrightness(ctx, pct) {
    pct := Max(0, Min(100, Round(pct)))
    if ctx["mode"] = "ddc" {
        raw := ctx["min"] + Round((ctx["max"] - ctx["min"]) * pct / 100)
        if !DllCall("dxva2\SetMonitorBrightness", "Ptr", ctx["handle"], "UInt", raw)
            throw Error("DDC/CI write failed")
    } else if ctx["mode"] = "wmi" {
        for m in ComObjGet("winmgmts:\\.\root\wmi").ExecQuery("SELECT * FROM WmiMonitorBrightnessMethods")
            m.WmiSetBrightness(1, pct)
    }
    return pct
}
