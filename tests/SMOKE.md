# Smoke test on a disposable Windows 11 machine

The automated tests (`py -m unittest discover -s tests -t .`) fake Windows: a dictionary stands in for the registry, a small
state machine for `sc`, plain objects for audio sessions. They prove the logic, the output, the exit codes, the confirmation
questions and the rollback. They do **not** prove that Windows accepts the calls.

**This runbook has not been run.** The change operations (`reg`, `svc`, `su`, `vm`, `cs`, `rb`) were written and tested on Linux.
Run this on a throwaway Windows 11 VM (snapshot it first), once from a normal terminal and once from an administrator terminal.
Every step names what to expect. Anything different is a bug to report, not something to work around.

Use `--json` where shown and check `ok`, `status` and the exit code (`echo %ERRORLEVEL%` / `$LASTEXITCODE`).

## 0. Setup

```powershell
py -m pip install -r requirements.txt
py -m unittest discover -s tests -t .      # the fakes must pass here too
py app.py cat --json > catalog.json        # opens, lists every operation
```

## 1. Registry (normal terminal, HKCU only)

```powershell
py app.py reg mkkey HKCU\Software\w11smoke --dry-run        # plan only; key must not exist afterwards
py app.py reg mkkey HKCU\Software\w11smoke --yes
py app.py reg set HKCU\Software\w11smoke Tag --type sz --value 100 --yes
py app.py reg get HKCU\Software\w11smoke Tag                # 100
py app.py reg set HKCU\Software\w11smoke Tag --type dword --value 7 --yes   # type change; journal keeps the old sz
py app.py rb last --yes                                     # Tag is "100" (sz) again
py app.py reg del HKCU\Software\w11smoke Tag --yes
py app.py rb last --yes                                     # Tag is back
py app.py reg rmkey HKCU\Software\w11smoke --yes
py app.py rb last --yes                                     # key and its values are back
```

Check in `regedit.exe` that types (REG_SZ / REG_DWORD / REG_MULTI_SZ / REG_BINARY / REG_EXPAND_SZ) round-trip exactly.
Check `reg set HKLM\SOFTWARE\w11smoke ...` from a normal terminal: `needs_admin`, exit 1, nothing written.

## 2. Services (administrator terminal)

Use a harmless service, e.g. `Fax` or `WSearch`.

```powershell
py app.py svc WSearch off --dry-run --json      # before/after, needs_admin true
py app.py svc WSearch off --yes --json          # status applied; read-back stopped
py app.py rb last --yes                         # running again
py app.py svc WSearch manual --yes
py app.py rb last --yes                         # startup type restored
py app.py svc WSearch delayed --yes
py app.py svc WSearch auto --yes                # KNOWN RISK: does 'sc config start=auto' clear the delayed flag?
py app.py rb last --yes                         # should be back to "auto (delayed)"
```

Look at: delayed-auto handling (the page may report `unverified`), the wording `sc` gives for access denied, and a service
that takes longer than 15 s to stop. From a normal terminal every change must refuse with `needs_admin` before asking anything.

## 3. Startup apps

Add a throwaway `HKCU\...\Run` value (`reg set ... Run w11smoke --type sz --value notepad.exe`) and a shortcut in the Startup folder.

```powershell
py app.py su ls --json                          # keys like user/run/w11smoke
py app.py su user/run/w11smoke off --yes        # Task Manager's Startup tab now shows it Disabled
py app.py rb last --yes                         # enabled again; the StartupApproved value is removed or restored
py app.py su rm user/run/w11smoke --yes
py app.py rb last --yes                         # Run value back with its original type
```

Check an all-users entry from a normal terminal (`needs_admin`), and one that Windows protects (the page should say so).

## 4. Volume

Play audio in a browser.

```powershell
py app.py vm ls
py app.py vm chrome 20 --dry-run --json
py app.py vm chrome 20 --yes
py app.py rb last --yes
py app.py vm system 30 --yes                    # read-back within 1 percent counts as applied
```

## 5. A batch with a failure partway

Save as `batch.json` (change names to match what you have; make the second one fail, e.g. a service that does not exist is
caught at planning, so use a protected one such as `RpcSs` for a run-time refusal):

```json
{"changes": [
  {"page": "regedit", "op": "set", "args": {"path": "HKCU\\Software\\w11smoke", "name": "A", "type": "dword", "value": "1"}},
  {"page": "services", "op": "state", "args": {"service": "RpcSs", "state": "stopped"}}
]}
```

```powershell
py app.py cs batch.json --dry-run               # exact plan, plan_hash, nothing changed
py app.py cs batch.json --yes --expect <plan_hash>
py app.py cs batch.json --yes --atomic          # first change is rolled back when the second fails
py app.py rb ls
```

Expected: exit 1, the failed change named, the rest `skipped`, and an `undo` command in the output.

## 6. Cleanup

```powershell
py app.py reg rmkey HKCU\Software\w11smoke --yes
```

Then revert the VM snapshot. Record what differed in `fashion.txt` under OPEN ISSUES.
