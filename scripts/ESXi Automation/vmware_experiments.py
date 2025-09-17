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

import requests
from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim
from sympy import content

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

def guest_start_background(si, vm, auth, shell_cmd: str, log_path: str = "/tmp/attack.out") -> int:
    if vm.guest.toolsRunningStatus != 'guestToolsRunning':
        warn(f"[{vm.name}] VMware Tools not running -> start_background skipped")
        return -1

    pidfile = "/tmp/attack.pid"
    # escape single quotes in shell_cmd
    esc = _escape_single_quotes_for_bash(shell_cmd)
    # launcher: nohup bash -lc '<shell_cmd>' > log 2>&1 & echo $! > pidfile
    # we pass the whole launcher as bash -c "...", so we must ensure proper quoting
    launcher_cmd_text = f"nohup bash -c '{esc}' > {log_path} 2>&1 & echo $! > {pidfile}"
    # Now pass launcher_cmd_text as a single argument to /bin/bash -c (again escape)
    launcher_text_esc = _escape_single_quotes_for_bash(launcher_cmd_text)
    final_args = f"-c '{launcher_text_esc}'"
    spec = vim.vm.guest.ProcessManager.ProgramSpec(programPath="/bin/bash", arguments=final_args)
    pm = si.content.guestOperationsManager.processManager
    try:
        launcher_pid = pm.StartProgramInGuest(vm, auth, spec)
        info(f"[{vm.name}] background launcher started (launcher_pid={launcher_pid}, pidfile={pidfile})")
        return launcher_pid
    except Exception as e:
        warn(f"[{vm.name}] guest_start_background falhou: {e}")
        return -1

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
    print(f"{BOLD}VMware Experiments — Orquestrador (UI melhorada){RESET}")
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

def ensure_tools_for_vm(content, vm_name: str, timeout_sec: int = 120) -> bool:
    info(f"A aguardar VMware Tools em {vm_name} (timeout {timeout_sec}s)...")
    start = time.time()
    while time.time() - start < timeout_sec:
        try:
            vm = find_vm_by_name(content, vm_name)   # re-obtem a VM
            status = getattr(vm.guest, "toolsRunningStatus", None)
            if status == "guestToolsRunning":
                info(f"VMware Tools running em {vm_name}")
                return True
        except Exception as e:
            warn(f"Erro ao obter estado Tools de {vm_name}: {e}")
        time.sleep(2)
    warn(f"VMware Tools NÃO ficou running em {vm_name} após {timeout_sec}s")
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
            warn(f"{vm.name}: prosseguindo apesar do VMware Tools não estar running (poderá falhar operações in-guest)")


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
    ensure_tools_for_all(content, vms)

    show_vms_status(content, vms)

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

    if attack_cmd:
        info(f"Starting attack (background) from /temp: {attack_cmd} ({attack_min} minutes)")
        # normalize: if relative, assume /temp/<attack_cmd>
        attack_cmd_expanded = attack_cmd
        if attack_cmd_expanded.startswith("~/"):
            attack_cmd_expanded = attack_cmd_expanded.replace("~/", "/")
        if not attack_cmd_expanded.startswith("/"):
            attack_cmd_expanded = f"/temp/{attack_cmd_expanded}"
        # start attack in background (pid -> /tmp/attack.pid, log -> /tmp/attack.out)
        guest_start_background(si, kali_vm, kali_auth, f"cd /temp && {attack_cmd_expanded}", log_path="/tmp/attack.out")
        try:
            countdown_minutes(attack_min, "ATTACK")
        except KeyboardInterrupt:
            info("Interrupt during attack wait; proceeding to stop attack")

        info("Stopping attack process (PID kill + fallback pkill)...")
        safe_pattern = attack_cmd_expanded.replace('"', '\\"')
        stop_cmd = (
            "pid=$(cat /tmp/attack.pid 2>/dev/null || echo ''); "
            "if [ -n \"$pid\" ]; then kill \"$pid\" 2>/dev/null || true; sleep 2; kill -0 \"$pid\" 2>/dev/null && pkill -f \"{p}\" || true; "
            "else pkill -f \"{p}\" || true; fi"
        ).format(p=safe_pattern)
        guest_run(si, kali_vm, kali_auth, ["/bin/bash", stop_cmd], timeout_sec=30, label="attack_stop")
        # retrieve attack log
        guest_download(si, kali_vm, kali_auth, "/tmp/attack.out", os.path.join(runs_dir, "attack.out"))
    else:
        warn("No kali_attack defined; skipping attack phase")

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
        print_header = lambda: (print(BOLD + "="*72 + RESET), print(f"{BOLD}VMware Experiments — Orquestrador{RESET}"), print(BOLD + "="*72 + RESET))
        print_header()
        si = esxi_connect(args.esxi, args.user, args.password, args.insecure)
        content = si.RetrieveContent()
        cfg = parse_yaml(args.config)
        experiments = cfg.get("experiments", [])
        if not experiments:
            die("No experiments in YAML")

        vms = cfg.get("vms", [])
        show_vms_status(content, vms)

        print("\n" + BOLD + "Experiments available:" + RESET)
        for i, e in enumerate(experiments, start=1):
            desc = e.get("description", "")
            print(f"  {i}) {e['name']:<30} - {desc}")
        print("  0) quit")
        sel = input("\nChoose experiment number or name: ").strip()
        if sel == "0":
            info("Exit"); return
        chosen = None
        if sel.isdigit():
            idx = int(sel) - 1
            if idx < 0 or idx >= len(experiments):
                die("Invalid selection")
            chosen = experiments[idx]
        else:
            for e in experiments:
                if e['name'] == sel:
                    chosen = e
                    break
            if not chosen:
                die("Invalid selection")

        info(f"Running: {chosen['name']} — {chosen.get('description','')}")
        run_experiment(si, content, cfg, chosen)

    except Exception as e:
        die(str(e))
    finally:
        if si:
            Disconnect(si)

if __name__ == "__main__":
    main()