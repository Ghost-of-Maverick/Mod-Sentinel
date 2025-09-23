#!/usr/bin/env python3
# vmware_experiments.py
# python3 vmware_experiments.py --esxi 192.168.136.149 --user root --password "pass" --insecure --config ./experiments.yaml
import argparse
import ssl
import sys
import time
import os
import shutil
from typing import List, Dict, Any, Tuple, Optional
from urllib.parse import urlparse, urlunparse
from typing import Optional
import requests
from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim
from sympy import content
import base64

try:
    import yaml  # type: ignore
except Exception:
    yaml = None

# ---------------- UI / cores ---------------- #
CSI = "\x1b["
RESET = CSI + "0m"
BOLD = CSI + "1m"
GREEN = CSI + "32m"
YELLOW = CSI + "33m"
RED = CSI + "31m"
CYAN = CSI + "36m"

def die(msg: str, code: int = 1):
    print(f"{RED}[ERRO]{RESET} {msg}", file=sys.stderr); sys.exit(code)

def info(msg: str):
    print(f"{GREEN}[INFO]{RESET} {msg}")

def warn(msg: str):
    print(f"{YELLOW}[AVISO]{RESET} {msg}")

def note(msg: str):
    print(f"{CYAN}[NOTE]{RESET} {msg}")

def now_ts() -> str:
    return time.strftime("%Y%m%d-%H%M%S")

# ---------------- ESXi connection & URL fix ---------------- #
ESXI_HOST_GLOBAL: Optional[str] = None

def esxi_connect(host: str, user: str, password: str, insecure: bool):
    global ESXI_HOST_GLOBAL
    ESXI_HOST_GLOBAL = host
    if insecure:
        ctx = ssl._create_unverified_context()
        return SmartConnect(host=host, user=user, pwd=password, sslContext=ctx)
    return SmartConnect(host=host, user=user, pwd=password)

def fix_esxi_url(url: str) -> str:
    global ESXI_HOST_GLOBAL
    if not ESXI_HOST_GLOBAL:
        return url
    try:
        u = urlparse(url)
        new_netloc = f"{ESXI_HOST_GLOBAL}:443"
        return urlunparse((u.scheme or "https", new_netloc, u.path, u.params, u.query, u.fragment))
    except Exception:
        return url

def find_vm_by_name(content, name: str) -> vim.VirtualMachine:
    view = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)
    try:
        for vm in view.view:
            if vm.name == name:
                return vm
    finally:
        view.Destroy()
    raise ValueError(f"VM '{name}' não encontrada")

def wait_for_task(task: vim.Task, label: str = "Tarefa"):
    while True:
        state = task.info.state
        if state == 'success':
            return task.info.result
        if state == 'error':
            details = task.info.error.msg if task.info.error else 'erro desconhecido'
            raise RuntimeError(f"{label} falhou: {details}")
        time.sleep(1)

def _find_snapshot(snapshot_tree, name: str):
    if snapshot_tree is None:
        return None
    for n in snapshot_tree:
        if n.name == name:
            return n.snapshot
        c = _find_snapshot(n.childSnapshotList, name)
        if c:
            return c
    return None

# ---------------- Guest operations (robust & fixed) ---------------- #
def guest_auth(user: str, password: str) -> vim.NamePasswordAuthentication:
    return vim.NamePasswordAuthentication(username=user, password=password, interactiveSession=False)

def _escape_single_quotes_for_bash(s: str) -> str:
    # escape single quotes for safe wrapping inside single quotes in bash:
    # ' -> '\''  which in Python is: s.replace("'", "'\"'\"'")
    return s.replace("'", "'\"'\"'")

def guest_run(si, vm, auth, command: List[str], timeout_sec: int = 0, label: str = "run") -> Tuple[int, int]:
    if vm.guest.toolsRunningStatus != 'guestToolsRunning':
        warn(f"[{vm.name}] VMware Tools não running -> guest_run skipped")
        return (-1, 0)

    pm = si.content.guestOperationsManager.processManager
    program = command[0]
    args_list = command[1:] if len(command) > 1 else []

    # If program is bash-ish and there are multiple args (like -c and not a single quoted cmd),
    # ensure we pass a single arguments string to bash -c '...'
    if os.path.basename(program).startswith("bash"):
        # assemble the actual command text from args_list
        if len(args_list) == 0:
            bash_args = None
        else:
            # if args_list already one string, use it; otherwise join
            joined = " ".join(args_list)
            # Escape single quotes and wrap in single quotes so -c receives a single argument
            escaped = _escape_single_quotes_for_bash(joined)
            bash_args = f"-c '{escaped}'"
        spec = vim.vm.guest.ProcessManager.ProgramSpec(programPath=program, arguments=bash_args)
    else:
        spec = vim.vm.guest.ProcessManager.ProgramSpec(programPath=program, arguments=" ".join(args_list) or None)

    info(f"[{vm.name}:{label}] → {program} {spec.arguments or ''}")
    try:
        pid = pm.StartProgramInGuest(vm, auth, spec)
    except Exception as e:
        warn(f"[{vm.name}:{label}] StartProgramInGuest falhou: {e}")
        return (-1, 0)

    start_ts = time.time()
    poll = 1
    while True:
        try:
            procs = pm.ListProcessesInGuest(vm, auth, [pid])
        except Exception as e:
            warn(f"[{vm.name}:{label}] ListProcessesInGuest erro (retry): {e}")
            time.sleep(poll)
            continue

        if not procs:
            dur = int(time.time() - start_ts)
            info(f"[{vm.name}:{label}] process {pid} not found (exited quickly) dur={dur}s")
            return (0, dur)

        p = procs[0]
        if getattr(p, "endTime", None) is not None:
            rc = int(getattr(p, "exitCode", 0) or 0)
            dur = int(time.time() - start_ts)
            info(f"[{vm.name}:{label}] finished pid={pid} exit={rc} dur={dur}s")
            return (rc, dur)

        if timeout_sec and (time.time() - start_ts) > timeout_sec:
            warn(f"[{vm.name}:{label}] timeout after {timeout_sec}s (process may continue in guest)")
            return (-1, int(time.time() - start_ts))

        time.sleep(poll)

def guest_start_background(si, vm, auth, shell_cmd: str,
                          log_path: str = "/tmp/attack.out",
                          pidfile: str = "/tmp/attack.pid",
                          pidfile_wait_sec: int = 8) -> int:
    if vm.guest.toolsRunningStatus != 'guestToolsRunning':
        warn(f"[{vm.name}] VMware Tools not running -> start_background skipped")
        return -1

    # Normalize guest command path (if relative assume /temp/)
    cmd_in_guest = shell_cmd
    if cmd_in_guest.startswith("~/"):
        cmd_in_guest = cmd_in_guest.replace("~/", "/")
    if not cmd_in_guest.startswith("/"):
        cmd_in_guest = f"/temp/{cmd_in_guest}"

    # Compose inner command to run wrapper (wrapper will create pidfile & log)
    inner = (
        "cd /temp || exit 1; "
        f"nohup /temp/run_attack_wrapper.sh {cmd_in_guest} > {log_path} 2>&1 & "
        "sleep 0.05; "
        # attempt to print pidfile (non-fatal)
        f"cat {pidfile} 2>/dev/null || true"
    )

    escaped_inner = inner.replace('"', '\\"')
    final_args = f'-lc "{escaped_inner}"'
    spec = vim.vm.guest.ProcessManager.ProgramSpec(programPath="/bin/bash", arguments=final_args)
    pm = si.content.guestOperationsManager.processManager

    try:
        launcher_pid = pm.StartProgramInGuest(vm, auth, spec)
        info(f"[{vm.name}] background launcher started (launcher_pid={launcher_pid}, pidfile={pidfile})")
    except Exception as e:
        warn(f"[{vm.name}] guest_start_background falhou: {e}")
        return -1

    # Poll for pidfile presence by attempting guest_download (small timeout)
    start = time.time()
    local_tmp = os.path.join(".", "runs", f"pidcheck_{vm.name}_{now_ts()}.pid")
    while time.time() - start < pidfile_wait_sec:
        try:
            # try to download pidfile; guest_download returns True/False
            ok = guest_download(si, vm, auth, pidfile, local_tmp)
            if ok:
                try:
                    with open(local_tmp, "r") as f:
                        pcontent = [l.strip() for l in f if l.strip()]
                    info(f"[{vm.name}] pidfile found with {len(pcontent)} lines: {pcontent}")
                except Exception:
                    info(f"[{vm.name}] pidfile downloaded but failed to read locally")
                # keep the downloaded pidfile for debugging
                return int(launcher_pid)
        except Exception:
            pass
        time.sleep(0.25)

    warn(f"[{vm.name}] pidfile {pidfile} not seen after {pidfile_wait_sec}s (wrapper may be slower).")
    return int(launcher_pid)

def guest_stop_by_pidfile(si, vm, auth, pidfile: str = "/tmp/attack.pid",
                         script_path: str = None, timeout_sec: int = 30,
                         label: str = "attack_stop") -> Tuple[int, int]:

    # Prepare safe fallback patterns
    safe_pattern = ""
    basename = ""
    if script_path:
        safe_pattern = script_path.replace('"', '\\"')
        basename = os.path.basename(script_path)

    # Build the shell script we will write and run on the guest.
    # Keep it plain, with clear logging to /tmp/attack.stop.log
    guest_script = f"""#!/bin/bash
LOG=/tmp/attack.stop.log
echo "STOP SCRIPT START $(date '+%Y-%m-%d %H:%M:%S')" > "$LOG"
echo "pidfile: {pidfile}" >> "$LOG"
FOUND=0

# function to attempt stop of a pid
stop_pid() {{
  p="$1"
  echo "checking pid $p" >> "$LOG"
  if [ -d /proc/$p ]; then
    # optional safety: check cmdline contains basename if provided
    if [ -n "{basename}" ]; then
      cmd=$(tr '\\0' ' ' < /proc/$p/cmdline 2>/dev/null || true)
      echo "cmdline: $cmd" >> "$LOG"
      if ! echo \"$cmd\" | grep -F -- "{basename}" >/dev/null 2>&1; then
        echo "pid $p cmdline does not match basename {basename}, skipping" >> "$LOG"
        return 1
      fi
    fi
    echo "Attempting pkill -TERM -P $p (children)" >> "$LOG"
    pkill -TERM -P "$p" 2>/dev/null || true
    echo "Attempting kill -TERM $p" >> "$LOG"
    kill -TERM "$p" 2>/dev/null || true
    sleep 1
    if kill -0 "$p" 2>/dev/null; then
      echo "pid $p still alive, escalating to KILL and pkill -KILL -P" >> "$LOG"
      pkill -KILL -P "$p" 2>/dev/null || true
      kill -KILL "$p" 2>/dev/null || true
      sleep 0.1
    fi
    if kill -0 "$p" 2>/dev/null; then
      echo "pid $p still present after escalation" >> "$LOG"
      return 2
    else
      echo "pid $p terminated" >> "$LOG"
      FOUND=1
      return 0
    fi
  else
    echo "pid $p not present" >> "$LOG"
    return 1
  fi
}}

# If pidfile exists, try using it
if [ -f "{pidfile}" ]; then
  echo "Reading pidfile {pidfile}" >> "$LOG"
  while IFS= read -r p || [ -n "$p" ]; do
    p="$(echo $p | tr -d '\\r\\n')"
    if [ -n "$p" ]; then
      stop_pid "$p" || true
    fi
  done < "{pidfile}"
  # remove pidfile to avoid future confusion
  rm -f "{pidfile}" 2>/dev/null || true
else
  echo "pidfile {pidfile} not found" >> "$LOG"
fi

# fallback: pkill by full path and basename if provided
if [ -n "{safe_pattern}" ]; then
  echo "Fallback: pkill -TERM -f \"{safe_pattern}\"" >> "$LOG"
  pkill -TERM -f "{safe_pattern}" 2>/dev/null || true
  echo "Fallback: pkill -TERM -f \"{basename}\"" >> "$LOG"
  pkill -TERM -f "{basename}" 2>/dev/null || true
  sleep 1
  echo "Fallback escalate: KILL patterns" >> "$LOG"
  pkill -KILL -f "{safe_pattern}" 2>/dev/null || true
  pkill -KILL -f "{basename}" 2>/dev/null || true
else
  echo "No safe_pattern provided - generic fallback (wrapper & script names)" >> "$LOG"
  pkill -TERM -f "/temp/run_attack_wrapper.sh" 2>/dev/null || true
  pkill -TERM -f "run_scouting.sh" 2>/dev/null || true
  sleep 1
  pkill -KILL -f "/temp/run_attack_wrapper.sh" 2>/dev/null || true
  pkill -KILL -f "run_scouting.sh" 2>/dev/null || true
fi

# Final listing for debug
echo "Remaining pgrep -af {basename}:" >> "$LOG"
pgrep -af "{basename}" >> "$LOG" 2>/dev/null || echo "no process match" >> "$LOG"

echo "STOP SCRIPT END $(date '+%Y-%m-%d %H:%M:%S')" >> "$LOG"
# always exit 0 so the launcher indicates success (we log internal failures)
exit 0
"""

    # base64 encode the script to avoid any quoting issues when sending
    b64 = base64.b64encode(guest_script.encode("utf-8")).decode("ascii")
    # build the command: decode base64 -> /tmp/stop_attack.sh ; chmod +x ; run it
    cmd = f"printf '%s' '{b64}' | base64 -d > /tmp/stop_attack.sh && chmod +x /tmp/stop_attack.sh && /tmp/stop_attack.sh; rc=$?; rm -f /tmp/stop_attack.sh || true; exit $rc"

    # prepare ProgramSpec - use -lc so shell meta works
    escaped = cmd.replace('"', '\\"')
    args = f'-lc "{escaped}"'
    spec = vim.vm.guest.ProcessManager.ProgramSpec(programPath="/bin/bash", arguments=args)
    pm = si.content.guestOperationsManager.processManager

    try:
        stop_launcher_pid = pm.StartProgramInGuest(vm, auth, spec)
        info(f"[{vm.name}:{label}] stop launcher started (pid={stop_launcher_pid})")
    except Exception as e:
        warn(f"[{vm.name}:{label}] StartProgramInGuest falhou para stop_cmd: {e}")
        return (-1, 0)

    # poll the launcher process until it exits or timeout
    start_ts = time.time()
    poll = 1
    while True:
        try:
            procs = pm.ListProcessesInGuest(vm, auth, [stop_launcher_pid])
        except Exception as e:
            warn(f"[{vm.name}:{label}] ListProcessesInGuest erro (retry): {e}")
            time.sleep(poll)
            continue

        if not procs:
            dur = int(time.time() - start_ts)
            info(f"[{vm.name}:{label}] stop launcher not found (exited quickly) dur={dur}s")
            return (0, dur)

        p = procs[0]
        if getattr(p, "endTime", None) is not None:
            rc = int(getattr(p, "exitCode", 0) or 0)
            dur = int(time.time() - start_ts)
            info(f"[{vm.name}:{label}] finished pid={stop_launcher_pid} exit={rc} dur={dur}s")
            return (rc, dur)

        if timeout_sec and (time.time() - start_ts) > timeout_sec:
            warn(f"[{vm.name}:{label}] timeout after {timeout_sec}s (stop launcher may continue in guest)")
            return (-1, int(time.time() - start_ts))

        time.sleep(poll)

def guest_download(si, vm, auth, guest_path: str, local_path: str) -> bool:
    fm = si.content.guestOperationsManager.fileManager
    if vm.guest.toolsRunningStatus != 'guestToolsRunning':
        warn(f"[{vm.name}] VMware Tools not running -> guest_download skipped")
        return False

    try:
        info(f"[{vm.name}] Initiating transfer for: {guest_path}")
        info_obj = fm.InitiateFileTransferFromGuest(vm, auth, guest_path)
        raw_url = getattr(info_obj, "url", None)
        if not raw_url:
            warn(f"[{vm.name}] InitiateFileTransferFromGuest devolveu URL vazia")
            return False
        fixed = fix_esxi_url(raw_url)
        info(f"[{vm.name}] transfer URL fixed -> {fixed}")
        r = requests.get(fixed, verify=False, timeout=120)
        r.raise_for_status()
        os.makedirs(os.path.dirname(local_path), exist_ok=True)
        with open(local_path, "wb") as f:
            f.write(r.content)
        info(f"[{vm.name}] downloaded -> {local_path}")
        return True
    except Exception as e:
        warn(f"[{vm.name}] guest_download failed: {e}")
        return False

# ---------------- YAML parsing ---------------- #
def parse_yaml(path: str) -> Dict[str, Any]:
    if yaml is None:
        die("pyyaml required: pip install pyyaml")
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

# ---------------- UI helpers ---------------- #
def clear_line():
    sys.stdout.write("\r" + " " * 80 + "\r")
    sys.stdout.flush()

def countdown_minutes(minutes: int, label: str):
    total = int(minutes) * 60
    try:
        while total > 0:
            mins = total // 60
            secs = total % 60
            sys.stdout.write(f"\r{BOLD}{label}:{RESET} {mins:02d}:{secs:02d} remaining ")
            sys.stdout.flush()
            time.sleep(1)
            total -= 1
        clear_line()
        info(f"{label} complete")
    except KeyboardInterrupt:
        clear_line()
        raise

def print_header():
    print(BOLD + "="*72 + RESET)
    print(f"{BOLD}VMware Experiments — Orquestrador{RESET}")
    print(BOLD + "="*72 + RESET)

def show_vms_status(content, cfg_vms: List[Dict[str,Any]]):
    print("\n" + BOLD + "VM status:" + RESET)
    for v in cfg_vms:
        try:
            vm = find_vm_by_name(content, v["name"])
            ps = vm.runtime.powerState
            tools = vm.guest.toolsRunningStatus or "unknown"
            print(f"  - {v['name']:<30} power={ps:<12} tools={tools}")
        except Exception as e:
            print(f"  - {v['name']:<30} {RED}ERROR: {e}{RESET}")

# ---------------- Orquestração mínima por experiência ---------------- #
def revert_to_snapshot_all(content, vm_entries: List[Dict[str,Any]]):
    for v in vm_entries:
        vm = find_vm_by_name(content, v["name"])
        if not vm.snapshot or not vm.snapshot.rootSnapshotList:
            raise RuntimeError(f"{vm.name} não tem snapshots")
        snap = _find_snapshot(vm.snapshot.rootSnapshotList, v["base_snapshot"])
        if not snap:
            raise RuntimeError(f"Snapshot '{v['base_snapshot']}' não encontrado em {vm.name}")
        info(f"Revert → {vm.name} @ {v['base_snapshot']}")
        wait_for_task(snap.RevertToSnapshot_Task(), label=f"Revert {vm.name}")
        if vm.runtime.powerState != vim.VirtualMachinePowerState.poweredOn:
            info(f"PowerOn → {vm.name}")
            wait_for_task(vm.PowerOn(), label=f"PowerOn {vm.name}")
        time.sleep(1)

def ensure_tools_for_vm(vm: vim.VirtualMachine, timeout_sec: int = 120) -> bool:
    info(f"A aguardar VMware Tools em {vm.name} (timeout {timeout_sec}s)...")
    start = time.time()
    while time.time() - start < timeout_sec:
        status = getattr(vm.guest, "toolsRunningStatus", None)
        if status == "guestToolsRunning":
            info(f"VMware Tools running em {vm.name}")
            return True
        time.sleep(2)
        # refresh vm runtime/guest info
        try:
            # re-obter objeto VM para atualizar estados
            # (este passo depende da API; se 'vm' já for dinâmico pode nem ser necessário)
            pass
        except Exception:
            pass
    warn(f"VMware Tools NÃO ficou running em {vm.name} após {timeout_sec}s")
    return False

def ensure_tools_for_all(content, vm_entries: List[Dict[str, Any]]):
    for v in vm_entries:
        try:
            vm = find_vm_by_name(content, v["name"])
        except Exception as e:
            warn(f"ensure_tools_for_all: VM {v['name']} não encontrada: {e}")
            continue
        timeout = int(v.get("tools_wait_sec", 120))
        # se já estiver running, rápido skip
        if getattr(vm.guest, "toolsRunningStatus", None) == "guestToolsRunning":
            info(f"{vm.name}: VMware Tools já running")
            continue
        ok = ensure_tools_for_vm(vm, timeout_sec=timeout)
        if not ok:
            warn(f"{vm.name}: prosseguindo apesar do VMware Tools não estar running")

# ---------------- GUI alert box (terminal) ---------------- #

def gui_alert(title: str, msg: str, width: Optional[int] = None):
    lines = msg.splitlines() or [""]
    max_line = max(len(l) for l in lines)
    min_width = max(len(title) + 4, max_line + 4, 40)
    w = width if (width and width > min_width) else min_width

    print()
    print(YELLOW + BOLD + "+" + "-" * (w - 2) + "+" + RESET)
    title_text = f" {title} "
    print(YELLOW + "|" + title_text.center(w - 2) + "|" + RESET)
    print(YELLOW + "+" + "-" * (w - 2) + "+" + RESET)

    for l in lines:
        if len(l) > w - 4:
            l = l[:w - 7] + "..."
        print(YELLOW + "| " + l.ljust(w - 4) + " |" + RESET)

    print(YELLOW + "+" + "-" * (w - 2) + "+" + RESET)
    print()

def run_experiment(si, content, cfg: Dict[str,Any], exp: Dict[str,Any]):
    vms = cfg.get("vms", [])
    vm_map = {v["name"]: find_vm_by_name(content, v["name"]) for v in vms}
    kali_entry = next((v for v in vms if v["name"].lower().startswith("kali")), None)
    if not kali_entry:
        die("Kali VM not found in YAML (name must start with 'kali')")
    kali_vm = vm_map[kali_entry["name"]]
    kali_auth = guest_auth(kali_entry["guest_user"], kali_entry["guest_pass"])

    # 1) revert and status
    info("Reverting all VMs to base snapshots...")
    revert_to_snapshot_all(content, vms)

    # 1a) garantir VMware Tools nas VMs (ESSENCIAL)
        # 1a) garantir VMware Tools nas VMs (ESSENCIAL)
    ensure_tools_for_all(content, vms)
    show_vms_status(content, vms)

    # se alguma VM ainda não tiver Tools, reforçar aviso aqui também
    bad_vms = [v["name"] for v in vms
               if getattr(find_vm_by_name(content, v["name"]).guest, "toolsRunningStatus", None) != "guestToolsRunning"]
    if bad_vms:
        warn(f"As seguintes VMs continuam sem VMware Tools: {', '.join(bad_vms)}. "
             "\nProsseguindo, mas operações in-guest podem falhar.")
        gui_alert(
            title="POSSÍVEL VM FROZEN",
            msg=(
                f"As VMs {', '.join(bad_vms)} não têm VMware Tools running.\n\n"
                "As experiências vão prosseguir, mas comandos in-guest e transferências "
                "podem falhar nessas VMs.\n"
                "Verifique-as manualmente se necessário ou aguarde."
            )
        )

    # confirm
    note(f"About to run experiment '{exp['name']}'")
    note(f"pre_time={exp.get('pre_time',5)}m attack_time={exp.get('attack_time',20)}m post_time={exp.get('post_time',10)}m")
    ok = input("Proceed? (y/N): ").strip().lower()
    if ok != "y":
        info("Aborted by user")
        return

    # 2) start Mod-Sentinel (use /Mod-Sentinel exactly)
    info("Starting Mod-Sentinel on Kali (start command)...")
    SENTINEL_DIR = "/Mod-Sentinel"
    start_cmd_text = f"cd {SENTINEL_DIR} && python3 main.py start"
    # pass as /bin/bash -c '<cmd>' so -c receives one argument
    rc, _ = guest_run(si, kali_vm, kali_auth, ["/bin/bash", start_cmd_text], timeout_sec=60, label="sentinel_start")
    if rc != 0:
        warn("Sentinel start command retornou não-zero. Verifica logs do sentinel no guest para diagnóstico.")
        # try to download /tmp/sentinel.out for debug (may not exist)
        try:
            dbg_dir = os.path.join(".", "runs", f"debug_sentinel_{now_ts()}")
            os.makedirs(dbg_dir, exist_ok=True)
            okdl = guest_download(si, kali_vm, kali_auth, "/tmp/sentinel.out", os.path.join(dbg_dir, "sentinel.out"))
            if okdl:
                info(f"Downloaded /tmp/sentinel.out -> {os.path.join(dbg_dir, 'sentinel.out')}")
        except Exception:
            pass
    else:
        info("Sentinel start command issued (verifica logs do sentinel).")

    # 3) pre_time
    pre = int(exp.get("pre_time", 5))
    try:
        countdown_minutes(pre, "PRE")
    except KeyboardInterrupt:
        info("Interrupt received — aborting experiment early")

     # 4) attack: background from /temp
    attack_cmd = exp.get("kali_attack")
    attack_min = int(exp.get("attack_time", 20))
    runs_dir = os.path.join(".", "runs", f"{exp['name']}_{now_ts()}")
    os.makedirs(runs_dir, exist_ok=True)

    if not attack_cmd:
        warn("No kali_attack defined; skipping attack phase")
    else:
        info(f"Starting attack (background) from /temp: {attack_cmd} ({attack_min} minutes)")

        # normalizar path: se relativo, assumir /temp/<attack_cmd>
        if attack_cmd.startswith("~/"):
            attack_cmd_expanded = attack_cmd.replace("~/", "/")
        elif not attack_cmd.startswith("/"):
            attack_cmd_expanded = f"/temp/{attack_cmd}"
        else:
            attack_cmd_expanded = attack_cmd

        pidfile = "/tmp/attack.pid"
        logfile = "/tmp/attack.out"

        # iniciar ataque em background via wrapper; aguarda um pouco pelo pidfile
        launcher_pid = guest_start_background(
            si,
            kali_vm,
            kali_auth,
            attack_cmd_expanded,
            log_path=logfile,
            pidfile=pidfile
        )
        if launcher_pid == -1:
            warn("guest_start_background falhou a lançar o wrapper (prosseguindo, mas poderá não correr).")

        try:
            countdown_minutes(attack_min, "ATTACK")
        except KeyboardInterrupt:
            info("Interrupt during attack wait; proceeding to stop attack")

        info("Stopping attack process using robust stop (pidfile + fallback pkill)...")

        # parar ataque com função robusta (usa pidfile se existir, senão fallback por nome)
        rc_stop, dur = guest_stop_by_pidfile(
            si,
            kali_vm,
            kali_auth,
            pidfile=pidfile,
            script_path=attack_cmd_expanded,
            timeout_sec=30,
            label="attack_stop"
        )

        # sempre tentar obter o log de stop para diagnóstico
        try:
            guest_download(si, kali_vm, kali_auth, "/tmp/attack.stop.log",
                           os.path.join(runs_dir, "attack.stop.log"))
            info(f"Downloaded stop log -> {os.path.join(runs_dir, 'attack.stop.log')}")
        except Exception as e:
            warn(f"Could not download /tmp/attack.stop.log: {e}")

        if rc_stop != 0:
            warn(f"Stop launcher devolveu código {rc_stop} (dur={dur}s). Verifica o estado no guest.")

            # 2ª tentativa: forçar fallback (sem pidfile) — útil se pidfile desapareceu ou PIDs mudaram
            warn("Attempting fallback stop (no pidfile) ...")
            rc_fb, dur_fb = guest_stop_by_pidfile(
                si,
                kali_vm,
                kali_auth,
                pidfile=None,
                script_path=attack_cmd_expanded,
                timeout_sec=45,
                label="attack_stop_fallback"
            )

            if rc_fb != 0:
                warn(f"Fallback stop também devolveu código {rc_fb} (dur={dur_fb}s). Verifica /tmp/attack.stop.log no guest.")
            else:
                info(f"Fallback stop completed successfully (dur={dur_fb}s)")
        else:
            info(f"Stop launcher completed successfully (dur={dur}s)")

                # sempre tentar obter o log de stop para diagnóstico
        try:
            guest_download(si, kali_vm, kali_auth, "/tmp/attack.stop.log",
                           os.path.join(runs_dir, "attack.stop.log"))
            info(f"Downloaded stop log -> {os.path.join(runs_dir, 'attack.stop.log')}")
        except Exception as e:
            warn(f"Could not download /tmp/attack.stop.log: {e}")

        try:
            ok_attack_log = guest_download(si, kali_vm, kali_auth, logfile,
                                           os.path.join(runs_dir, "attack.out"))
            if ok_attack_log:
                info(f"Downloaded attack log -> {os.path.join(runs_dir, 'attack.out')}")
            else:
                warn(f"attack log {logfile} not found or download failed")
        except Exception as e:
            warn(f"Could not download {logfile}: {e}")

    # 5) post_time
    post = int(exp.get("post_time", 10))
    try:
        countdown_minutes(post, "POST")
    except KeyboardInterrupt:
        info("Interrupt received during post_time")

    # 6) stop sentinel and collect logs (all files under /Mod-Sentinel/logs/)
    info("Stopping Mod-Sentinel and collecting logs...")
    try:
        guest_run(si, kali_vm, kali_auth, ["/bin/bash", f"cd {SENTINEL_DIR} && python3 main.py stop"], timeout_sec=120, label="sentinel_stop")
    except Exception as e:
        warn(f"Stopping sentinel failed: {e}")

    remote_tgz = f"/tmp/modsentinel_{exp['name']}_{now_ts()}.tgz"
    try:
        guest_run(si, kali_vm, kali_auth, ["/bin/bash", f"cd {SENTINEL_DIR} && tar -czf {remote_tgz} logs"], timeout_sec=120, label="tar_logs")
        local_tgz = os.path.join(runs_dir, os.path.basename(remote_tgz))
        ok = guest_download(si, kali_vm, kali_auth, remote_tgz, local_tgz)
        if ok:
            try:
                shutil.unpack_archive(local_tgz, runs_dir)
                info(f"Logs extracted to {runs_dir}")
            except Exception:
                info(f"Saved logs tar -> {local_tgz}")
        else:
            warn("Failed to download sentinel logs")
        # cleanup remote tar
        try:
            guest_run(si, kali_vm, kali_auth, ["/bin/bash", f"rm -f {remote_tgz}"], timeout_sec=10, label="rm_tgz")
        except Exception:
            pass
    except Exception as e:
        warn(f"Could not create/download sentinel logs: {e}")

    info(f"Experiment '{exp['name']}' finished. Results in: {os.path.abspath(runs_dir)}")

def run_experiment_no_attack(si, content, cfg: Dict[str,Any], exp: Dict[str,Any], duration_min: int = 30):
    vms = cfg.get("vms", [])
    vm_map = {v["name"]: find_vm_by_name(content, v["name"]) for v in vms}
    kali_entry = next((v for v in vms if v["name"].lower().startswith("kali")), None)
    if not kali_entry:
        die("Kali VM not found in YAML (name must start with 'kali')")
    kali_vm = vm_map[kali_entry["name"]]
    kali_auth = guest_auth(kali_entry["guest_user"], kali_entry["guest_pass"])

    # 1) revert and status
    info("Reverting all VMs to base snapshots...")
    revert_to_snapshot_all(content, vms)

    ensure_tools_for_all(content, vms)
    show_vms_status(content, vms)

    bad_vms = [v["name"] for v in vms
               if getattr(find_vm_by_name(content, v["name"]).guest, "toolsRunningStatus", None) != "guestToolsRunning"]
    if bad_vms:
        warn(f"As seguintes VMs continuam sem VMware Tools: {', '.join(bad_vms)}. "
             "\nProsseguindo, mas operações in-guest podem falhar.")
        gui_alert(
            title="POSSÍVEL VM FROZEN",
            msg=(f"As VMs {', '.join(bad_vms)} não têm VMware Tools running.\n\n"
                 "As experiências vão prosseguir, mas comandos in-guest e transferências "
                 "podem falhar nessas VMs.\n"
                 "Verifique-as manualmente se necessário ou aguarde.")
        )

    note(f"About to run NO-ATTACK experiment '{exp['name']}' for {duration_min} minutes")
    ok = input("Proceed? (y/N): ").strip().lower()
    if ok != "y":
        info("Aborted by user")
        return

    # Start sentinel
    info("Starting Mod-Sentinel on Kali (start command)...")
    SENTINEL_DIR = "/Mod-Sentinel"
    start_cmd_text = f"cd {SENTINEL_DIR} && python3 main.py start"
    rc, _ = guest_run(si, kali_vm, kali_auth, ["/bin/bash", start_cmd_text], timeout_sec=60, label="sentinel_start")
    if rc != 0:
        warn("Sentinel start command retornou não-zero. Verifica logs do sentinel no guest para diagnóstico.")
    else:
        info("Sentinel start command issued (verifica logs do sentinel).")

    # create run dir early so logs have place to go
    runs_dir = os.path.join(".", "runs", f"{exp['name']}_{now_ts()}")
    os.makedirs(runs_dir, exist_ok=True)

    # Wait the desired duration
    try:
        countdown_minutes(duration_min, "NO-ATTACK")
    except KeyboardInterrupt:
        info("Interrupt received — proceeding to stop sentinel")

    # Stop sentinel and collect logs (same as existing logic)
    info("Stopping Mod-Sentinel and collecting logs...")
    try:
        guest_run(si, kali_vm, kali_auth, ["/bin/bash", f"cd {SENTINEL_DIR} && python3 main.py stop"], timeout_sec=120, label="sentinel_stop")
    except Exception as e:
        warn(f"Stopping sentinel failed: {e}")

    remote_tgz = f"/tmp/modsentinel_{exp['name']}_{now_ts()}.tgz"
    try:
        guest_run(si, kali_vm, kali_auth, ["/bin/bash", f"cd {SENTINEL_DIR} && tar -czf {remote_tgz} logs"], timeout_sec=120, label="tar_logs")
        local_tgz = os.path.join(runs_dir, os.path.basename(remote_tgz))
        ok = guest_download(si, kali_vm, kali_auth, remote_tgz, local_tgz)
        if ok:
            try:
                shutil.unpack_archive(local_tgz, runs_dir)
                info(f"Logs extracted to {runs_dir}")
            except Exception:
                info(f"Saved logs tar -> {local_tgz}")
        else:
            warn("Failed to download sentinel logs")
        # cleanup remote tar
        try:
            guest_run(si, kali_vm, kali_auth, ["/bin/bash", f"rm -f {remote_tgz}"], timeout_sec=10, label="rm_tgz")
        except Exception:
            pass
    except Exception as e:
        warn(f"Could not create/download sentinel logs: {e}")

    info(f"NO-ATTACK experiment '{exp['name']}' finished. Results in: {os.path.abspath(runs_dir)}")

# ---------------- CLI / Menu / Signal ---------------- #
def main():
    ap = argparse.ArgumentParser(description="Orquestrador simplificado para ESXi (experiências)")
    ap.add_argument("--esxi", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("--config", required=True)
    args = ap.parse_args()

    si = None
    try:
        print_header()
        si = esxi_connect(args.esxi, args.user, args.password, args.insecure)
        content = si.RetrieveContent()
        cfg = parse_yaml(args.config)
        experiments = cfg.get("experiments", [])
        if not experiments:
            die("No experiments in YAML")

        vms = cfg.get("vms", [])
        show_vms_status(content, vms)

        # menu loop
        while True:
            print("\n" + BOLD + "Experiments available:" + RESET)
            for i, e in enumerate(experiments, start=1):
                desc = e.get("description", "")
                print(f"  {i}) {e['name']:<30} - {desc}")
            print("  A) Run ALL experiments")
            print("  N) Run experiment WITHOUT attack")
            print("  S) Show VM status")
            print("  0) Quit")

            sel = input("\nChoose experiment number, name, or option: ").strip()
            if sel.lower() in ("0", "q", "quit", "exit"):
                info("Exit")
                break
            elif sel.lower() in ("a", "all"):
                info("Running ALL experiments sequentially...")
                for exp in experiments:
                    info(f"\n--- Running: {exp['name']} ---")
                    run_experiment(si, content, cfg, exp)
                info("All experiments finished.")
            elif sel.lower() in ("s", "status"):
                show_vms_status(content, vms)
            elif sel.lower() in ("n", "noattack", "no-attack"):
                # Perguntar duração em minutos (default 30)
                dur_in = input("Duração em minutos (default 30): ").strip()
                if dur_in == "":
                    duration = 30
                else:
                    try:
                        duration = int(dur_in)
                        if duration <= 0:
                            warn("Duração inválida. Usando 30 minutos.")
                            duration = 30
                    except Exception:
                        warn("Entrada inválida. Usando 30 minutos.")
                        duration = 30

                # Criar "experiência" fake só para nome e organização
                timestamp = now_ts()
                fake_exp = {
                    "name": f"no_attack_{timestamp}",
                    "description": f"Run sem ataque por {duration} minutos",
                    "pre_time": 0,
                    "attack_time": 0,
                    "post_time": duration  # usamos post_time para esperar a duração
                }

                info(f"Running NO-ATTACK: {fake_exp['name']} — {fake_exp['description']}")
                run_experiment_no_attack(si, content, cfg, fake_exp, duration_min=duration)

            else:
                chosen = None
                if sel.isdigit():
                    idx = int(sel) - 1
                    if 0 <= idx < len(experiments):
                        chosen = experiments[idx]
                else:
                    for e in experiments:
                        if e['name'].lower() == sel.lower():
                            chosen = e
                            break
                if not chosen:
                    warn("Invalid selection, try again.")
                    continue

                info(f"Running: {chosen['name']} — {chosen.get('description','')}")
                run_experiment(si, content, cfg, chosen)

    except Exception as e:
        die(str(e))
    finally:
        if si:
            Disconnect(si)

if __name__ == "__main__":
    main()