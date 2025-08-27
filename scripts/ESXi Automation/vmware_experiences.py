#!/usr/bin/env python3
"""
vmware_experiments.py — Orquestração multi‑VM (ESXi standalone) com snapshots

Requisitos
- Python 3.9+
- `pip install pyvmomi pyyaml requests`
- VMware Tools a correr (obrigatório na Kali; recomendado nas restantes).
- Credenciais do guest OS.

Configuração (YAML) — exemplo `experiments.yaml`
-------------------------------------------------
# VMs geridas
vms:
  - name: KaliST01
    base_snapshot: clean
    guest_user: <kali_user>
    guest_pass: <kali_pass>
    power_on: true
    tools_wait_sec: 120
  - name: OpenPLC-PRV
    base_snapshot: clean
    guest_user: <user>
    guest_pass: <pass>
    power_on: true
    tools_wait_sec: 60
  - name: OpenPLC-PRV-RTU
    base_snapshot: clean
    guest_user: <user>
    guest_pass: <pass>
    power_on: true
    tools_wait_sec: 60
  - name: HMI-RSC-PRV
    base_snapshot: clean
    guest_user: <user>
    guest_pass: <pass>
    power_on: true
    tools_wait_sec: 60

# parâmetros globais de temporização (minutos)
timing:
  normal_pre: 10   # T0–T1 (sentinel a correr)
  attack: 20       # T1–T2 (script de ataque)
  normal_post: 10  # T2–T3 (cool‑down)

Execução (exemplo):
  python vmware_experiments.py \
    --esxi 192.168.1.10 --user root --password 'ESXI_PASS' --insecure \
    --config ./experiments.yaml --snapshot-memory --snapshot-quiesce

Como configurar o YAML
- Adiciona no topo (opcional):
run:
  iterations: 0             # 0 = correr até interrupção; por omissão 1
  pause_between_runs_sec: 30 # segundos entre execuções completas

- Mantém `dataset.command` para start do sentinel: ["cd /Mod-Sentinel && python3 main.py start"]
  e `dataset.collect` para indicar que queres copiar /Mod-Sentinel/logs/ (o orquestrador usa tar e transfere tudo).

Funcionamento (resumo do ciclo por experiência)
1) Revert a snapshots base nas 4 VMs e power-on / wait tools.
2) Upload de ficheiros para a Kali.
3) Inicia Mod‑Sentinel (start) em background.
4) Espera `timing.normal_pre` minutos.
5) Lança o ataque com `timeout timing.attack` (forçado) na Kali.
6) Espera `timing.normal_post` minutos.
7) Para Mod‑Sentinel (`cd /Mod-Sentinel && python3 main.py stop`) e gera tar de `/Mod-Sentinel/logs/` em `/tmp` do guest.
8) Descarrega logs do sentinel (tar), logs de ataque e quaisquer `collect_others` definidos.
9) Cria snapshot em todas as VMs.
10) Repete para próxima experiência e, depois do conjunto, repete o conjunto inteiro conforme `run.iterations`.

Detalhes técnicos da implementação
- Para o Mod‑Sentinel o orquestrador usa StartProgramInGuest (com nohup) para arrancar o processo em background e `StartProgramInGuest` para o comando stop que devolve quando terminado.
- Para recolher `/Mod-Sentinel/logs/` o orquestrador executa `tar -C /Mod-Sentinel -czf /tmp/modsentinel_<run>_<exp>.tgz logs` e depois descarrega o `/tmp`.
- Ficheiros recolhidos são colocados em: `./runs/<base_ts>/runNN_<ts>/<experiment>/...`.

"""

import argparse
import ssl
import sys
import time
import os
import csv
import json
from dataclasses import dataclass
from typing import List, Optional, Dict, Any, Tuple

import requests
from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim

try:
    import yaml  # type: ignore
except Exception:
    yaml = None

# ------------------------------- Utilitários ------------------------------- #

def die(msg: str, code: int = 1):
    print(f"[ERRO] {msg}", file=sys.stderr)
    sys.exit(code)

def info(msg: str):
    print(f"[INFO] {msg}")

def warn(msg: str):
    print(f"[AVISO] {msg}")

def now_ts() -> str:
    return time.strftime('%Y%m%d-%H%M%S')

def wait_for_task(task: vim.Task, label: str = "Tarefa"):
    while True:
        state = task.info.state
        if state == 'success':
            return task.info.result
        if state == 'error':
            details = task.info.error.msg if task.info.error else 'erro desconhecido'
            raise RuntimeError(f"{label} falhou: {details}")
        time.sleep(1)

# ----------------------------- Ligação ao ESXi ----------------------------- #

def esxi_connect(host: str, user: str, password: str, insecure: bool):
    if insecure:
        ctx = ssl._create_unverified_context()
        return SmartConnect(host=host, user=user, pwd=password, sslContext=ctx)
    return SmartConnect(host=host, user=user, pwd=password)

def find_vm_by_name(content, name: str) -> vim.VirtualMachine:
    view = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)
    try:
        for vm in view.view:
            if vm.name == name:
                return vm
    finally:
        view.Destroy()
    raise ValueError(f"VM '{name}' não encontrada")

# -------------------------------- Snapshots -------------------------------- #

def _find_snapshot(snapshot_tree, name: str) -> Optional[vim.vm.Snapshot]:
    if snapshot_tree is None:
        return None
    for n in snapshot_tree:
        if n.name == name:
            return n.snapshot
        c = _find_snapshot(n.childSnapshotList, name)
        if c:
            return c
    return None

# --------------------------- Guest Operations API -------------------------- #

def guest_auth(user: str, password: str) -> vim.NamePasswordAuthentication:
    return vim.NamePasswordAuthentication(username=user, password=password, interactiveSession=False)

def guest_upload(si, vm: vim.VirtualMachine, auth, local_path: str, guest_path: str, chmod_x: bool = False):
    fm = si.content.guestOperationsManager.fileManager
    with open(local_path, 'rb') as f:
        data = f.read()
    url = fm.InitiateFileTransferToGuest(vm=vm, auth=auth, guestFilePath=guest_path,
                                         fileAttributes=vim.vm.guest.FileManager.FileAttributes(),
                                         fileSize=len(data), overwrite=True)
    res = requests.put(url, data=data, verify=False)
    if not (200 <= res.status_code < 300):
        raise RuntimeError(f"Upload falhou ({guest_path}): HTTP {res.status_code}")
    if chmod_x:
        attrs = vim.vm.guest.FileManager.PosixFileAttributes()
        attrs.permissions = 0o755
        fm.ChangeFileAttributesInGuest(vm, auth, guest_path, attrs)

def guest_start_background(si, vm: vim.VirtualMachine, auth, shell_cmd: str) -> int:
    """Inicia um comando em background via /bin/bash -lc '<cmd> &' e devolve o PID (ou -1 se falhar)."""
    pm = si.content.guestOperationsManager.processManager
    spec = vim.vm.guest.ProcessManager.ProgramSpec(programPath="/bin/bash", arguments=f"-lc \"nohup {shell_cmd} >/tmp/orch_bg_$(date +%s).out 2>&1 &\"")
    try:
        pid = pm.StartProgramInGuest(vm, auth, spec)
        return pid
    except Exception as e:
        warn(f"guest_start_background falhou: {e}")
        return -1

def guest_run(si, vm: vim.VirtualMachine, auth, command: List[str], timeout_sec: int, label: str = "guest_run") -> Tuple[int, int]:
    pm = si.content.guestOperationsManager.processManager
    spec = vim.vm.guest.ProcessManager.ProgramSpec(programPath=command[0], arguments=" ".join(command[1:]) or None)
    info(f"[{vm.name}:{label}] → {' '.join(command)}")
    pid = pm.StartProgramInGuest(vm, auth, spec)
    start = time.time()
    while True:
        procs = pm.ListProcessesInGuest(vm, auth, [pid])
        if not procs:
            return (0, int(time.time() - start))
        p = procs[0]
        if p.endTime is not None:
            rc = p.exitCode or 0
            info(f"[{vm.name}:{label}] terminado (exit={rc}, dur={int(time.time()-start)}s)")
            return (rc, int(time.time() - start))
        if timeout_sec and (time.time() - start) > timeout_sec:
            warn(f"[{vm.name}:{label}] timeout — processo continua em background")
            return (-1, int(time.time() - start))
        time.sleep(2)

def guest_download(si, vm: vim.VirtualMachine, auth, guest_path: str, local_path: str):
    fm = si.content.guestOperationsManager.fileManager
    info(f"A descarregar '{guest_path}' para '{local_path}'")
    info_obj = fm.InitiateFileTransferFromGuest(vm, auth, guest_path)
    res = requests.get(info_obj.url, verify=False)
    if res.status_code != 200:
        raise RuntimeError(f"Download falhou ({guest_path}): HTTP {res.status_code}")
    os.makedirs(os.path.dirname(local_path), exist_ok=True)
    with open(local_path, 'wb') as f:
        f.write(res.content)

# --------------------------------- Tipos ---------------------------------- #
@dataclass
class VMEntry:
    name: str
    base_snapshot: str
    guest_user: str
    guest_pass: str
    power_on: bool
    tools_wait_sec: int

@dataclass
class Upload:
    local: str
    guest: str
    chmod_x: bool

@dataclass
class KaliBlock:
    uploads: List[Upload]
    dataset_cmd: List[str]
    dataset_timeout: int
    dataset_stop: str
    dataset_collect: List[Tuple[str, str]]
    attack_cmd: List[str]
    attack_timeout: int
    attack_collect: List[Tuple[str, str]]

@dataclass
class Experiment:
    name: str
    kali: KaliBlock
    collect_others: Dict[str, List[Tuple[str, str]]]

# ------------------------------ Parse YAML -------------------------------- #

def parse_yaml(path: str) -> Tuple[List[VMEntry], List[Experiment], Dict[str, Any], Dict[str, Any]]:
    if yaml is None:
        die("Instale pyyaml: pip install pyyaml")
    with open(path, 'r', encoding='utf-8') as f:
        raw = yaml.safe_load(f)

    vms: List[VMEntry] = []
    for v in raw.get('vms', []):
        vms.append(VMEntry(
            name=v['name'], base_snapshot=v['base_snapshot'],
            guest_user=v['guest_user'], guest_pass=v['guest_pass'],
            power_on=bool(v.get('power_on', True)), tools_wait_sec=int(v.get('tools_wait_sec', 60))
        ))

    exps: List[Experiment] = []
    for e in raw.get('experiments', []):
        uploads = [Upload(u['local'], u['guest'], bool(u.get('chmod_x', False))) for u in e['kali'].get('uploads', [])]
        kali = KaliBlock(
            uploads=uploads,
            dataset_cmd=e['kali'].get('dataset', {}).get('command', []),
            dataset_timeout=int(e['kali'].get('dataset', {}).get('timeout_sec', 0)),
            dataset_stop=e['kali'].get('dataset', {}).get('stop_signal', 'TERM'),
            dataset_collect=[(c['guest'], c['local']) for c in e['kali'].get('dataset', {}).get('collect', [])],
            attack_cmd=e['kali']['attack']['command'],
            attack_timeout=int(e['kali']['attack'].get('timeout_sec', 0)),
            attack_collect=[(c['guest'], c['local']) for c in e['kali']['attack'].get('collect', [])]
        )
        collect_others = {}
        for vm_name, items in (e.get('collect_others') or {}).items():
            collect_others[vm_name] = [(c['guest'], c['local']) for c in items]
        exps.append(Experiment(name=e['name'], kali=kali, collect_others=collect_others))

    timing = raw.get('timing', {})
    run_conf = raw.get('run', {})
    return vms, exps, timing, run_conf

# ------------------------------ Orquestração ------------------------------- #

def ensure_power_and_tools(vm: vim.VirtualMachine, power_on: bool, tools_wait: int):
    if power_on and vm.runtime.powerState != vim.VirtualMachinePowerState.poweredOn:
        info(f"PowerOn → {vm.name}")
        wait_for_task(vm.PowerOn(), label=f"PowerOn {vm.name}")
    if tools_wait:
        start = time.time()
        while time.time() - start < tools_wait:
            if vm.guest.toolsRunningStatus == 'guestToolsRunning':
                return
            time.sleep(2)
        warn(f"VMware Tools não ficou Running em {vm.name}")

def revert_all(si, content, vm_entries: List[VMEntry], vm_map: Dict[str, vim.VirtualMachine]):
    for v in vm_entries:
        vm = vm_map[v.name]
        if not vm.snapshot or not vm.snapshot.rootSnapshotList:
            raise RuntimeError(f"{vm.name} não tem snapshots")
        snap = _find_snapshot(vm.snapshot.rootSnapshotList, v.base_snapshot)
        if not snap:
            raise RuntimeError(f"Snapshot '{v.base_snapshot}' não encontrado em {vm.name}")
        info(f"Revert → {vm.name} @ {v.base_snapshot}")
        wait_for_task(snap.RevertToSnapshot_Task(), label=f"Revert {vm.name}")

def create_snapshot_all(vm_entries: List[VMEntry], vm_map: Dict[str, vim.VirtualMachine], name: str, desc: str, memory=False, quiesce=False):
    for v in vm_entries:
        vm = vm_map[v.name]
        info(f"Snapshot → {vm.name} :: {name}")
        wait_for_task(vm.CreateSnapshot_Task(name=name, description=desc, memory=memory, quiesce=quiesce), label=f"Snapshot {vm.name}")

# ------------------------------ Helpers de paths -------------------------- #

def compute_local_target(run_dir: str, exp_name: str, local_path: str) -> str:
    # Preserve relative path under run_dir/<exp_name>/...
    rel = local_path
    if rel.startswith('./'):
        rel = rel[2:]
    rel = rel.lstrip('/')
    target_dir = os.path.join(run_dir, exp_name, os.path.dirname(rel))
    os.makedirs(target_dir, exist_ok=True)
    return os.path.join(target_dir, os.path.basename(local_path))

# ------------------------------ Timeline Log ------------------------------- #
class Timeline:
    def __init__(self, run_dir: str):
        self.events: List[Dict[str, Any]] = []
        self.t0 = time.time()
        self.run_dir = run_dir
        os.makedirs(run_dir, exist_ok=True)

    def mark(self, tag: str, meta: Dict[str, Any] = None):
        t = time.time()
        self.events.append({"tag": tag, "ts": t, "t_rel": round(t - self.t0, 3), **(meta or {})})

    def sleep_mark(self, seconds: int, tag: str):
        info(f"A aguardar {seconds}s → {tag}")
        time.sleep(seconds)
        self.mark(tag)

    def dump(self):
        csv_path = os.path.join(self.run_dir, 'timeline.csv')
        json_path = os.path.join(self.run_dir, 'timeline.json')
        with open(csv_path, 'w', newline='') as f:
            fields = sorted({k for e in self.events for k in e.keys()})
            w = csv.DictWriter(f, fieldnames=fields); w.writeheader(); w.writerows(self.events)
        with open(json_path, 'w') as f:
            json.dump(self.events, f, indent=2)
        info(f"Timeline: {csv_path} | {json_path}")

# ------------------------- Sequência de Fases (Kali) ----------------------- #

def sentinel_start_background(si, kvm, kauth, tl: Timeline, run_idx: int, exp_name: str) -> int:
    cmd = "cd /Mod-Sentinel && python3 main.py start"
    pid = guest_start_background(si, kvm, kauth, cmd)
    tl.mark("sentinel_started", {"pid": pid})
    return pid


def sentinel_stop_and_collect(si, kvm, kauth, tl: Timeline, run_dir: str, run_idx: int, exp_name: str):
    # Stop sentinel
    rc, dur = guest_run(si, kvm, kauth, ["/bin/bash", "-lc", "cd /Mod-Sentinel && python3 main.py stop"], timeout_sec=120)
    tl.mark("sentinel_stopped", {"rc": rc, "dur_s": dur})
    # Tar the logs directory and download
    tar_guest = f"/tmp/modsentinel_run{run_idx}_{exp_name}.tgz"
    tar_cmd = f"cd /Mod-Sentinel && tar -czf {tar_guest} logs"
    rc2, d2 = guest_run(si, kvm, kauth, ["/bin/bash", "-lc", tar_cmd], timeout_sec=120)
    tl.mark("sentinel_tar_created", {"rc": rc2})
    # local target
    local_target = compute_local_target(run_dir, exp_name, os.path.basename(tar_guest))
    try:
        guest_download(si, kvm, kauth, tar_guest, local_target)
        tl.mark("sentinel_tar_downloaded", {"local": local_target})
    except Exception as e:
        warn(f"Falha a descarregar sentinel tar: {e}")
    # cleanup guest tar
    try:
        guest_run(si, kvm, kauth, ["/bin/bash", "-lc", f"rm -f {tar_guest}"], timeout_sec=30)
    except Exception:
        pass


def run_attack_with_timeout(si, kvm, kauth, attack_cmd: List[str], minutes: int, tl: Timeline, run_dir: str, exp_name: str):
    # usa timeout a nível de shell
    total_sec = minutes * 60
    quoted = " ".join([f'"{a}"' if ' ' in a else a for a in attack_cmd])
    shell_cmd = f"timeout {total_sec}s {quoted}"
    rc, dur = guest_run(si, kvm, kauth, ["/bin/bash", "-lc", shell_cmd], timeout_sec=total_sec + 60)
    tl.mark("attack_finished", {"rc": rc, "dur_s": dur})
    return rc, dur

# ---------------------------------- Main ---------------------------------- #

def main():
    ap = argparse.ArgumentParser(description="Orquestra experiências multi‑VM com pyVmomi (ESXi) — ciclos repetidos")
    ap.add_argument('--esxi', required=True)
    ap.add_argument('--user', required=True)
    ap.add_argument('--password', required=True)
    ap.add_argument('--insecure', action='store_true')
    ap.add_argument('--config', required=True)
    ap.add_argument('--snapshot-memory', action='store_true')
    ap.add_argument('--snapshot-quiesce', action='store_true')
    args = ap.parse_args()

    si = None
    try:
        si = esxi_connect(args.esxi, args.user, args.password, args.insecure)
        content = si.RetrieveContent()

        vm_entries, experiments, timing, run_conf = parse_yaml(args.config)
        if not vm_entries:
            die("Nenhuma VM definida no YAML")
        if not experiments:
            die("Nenhuma experiência definida no YAML")

        t_normal_pre = int(timing.get('normal_pre', 10))
        t_attack = int(timing.get('attack', 20))
        t_normal_post = int(timing.get('normal_post', 10))

        iterations = int(run_conf.get('iterations', 1))
        pause_between_runs = int(run_conf.get('pause_between_runs_sec', 0))
        infinite = iterations == 0

        # mapear VMs e autenticações
        vm_map: Dict[str, vim.VirtualMachine] = {}
        guest_auths: Dict[str, vim.NamePasswordAuthentication] = {}
        for v in vm_entries:
            vm_map[v.name] = find_vm_by_name(content, v.name)
            guest_auths[v.name] = guest_auth(v.guest_user, v.guest_pass)
        kali_name = next(v.name for v in vm_entries if v.name.lower().startswith('kali'))
        kvm = vm_map[kali_name]
        kauth = guest_auths[kali_name]

        base_run_dir = os.path.join('./runs', now_ts())
        run_idx = 0
        while infinite or run_idx < iterations:
            run_idx += 1
            run_subdir = os.path.join(base_run_dir, f"run{run_idx:02d}_{now_ts()}")
            tl = Timeline(run_subdir)
            tl.mark("run_start", {"run": run_idx})

            for exp in experiments:
                exp_name = exp.name
                tl.mark(f"{exp_name}:start")

                # 1) Reverter todas as VMs e garantir power/tools
                revert_all(si, content, vm_entries, vm_map)
                for v in vm_entries:
                    ensure_power_and_tools(vm_map[v.name], v.power_on, v.tools_wait_sec)
                tl.mark(f"{exp_name}:after_revert_power")

                # 2) Uploads para Kali
                for u in exp.kali.uploads:
                    if not os.path.exists(u.local):
                        die(f"Falta: {u.local}")
                    guest_upload(si, kvm, kauth, u.local, u.guest, chmod_x=u.chmod_x)
                tl.mark(f"{exp_name}:kali_prepared")

                # 3) Start Mod‑Sentinel em background (se definido)
                if exp.kali.dataset_cmd:
                    sentinel_start_background(si, kvm, kauth, tl, run_idx, exp_name)
                else:
                    tl.mark("sentinel_skipped")

                # 4) Normal pre
                tl.sleep_mark(t_normal_pre * 60, f"{exp_name}:normal_pre_done")

                # 5) Attack (with timeout)
                run_attack_with_timeout(si, kvm, kauth, exp.kali.attack_cmd, t_attack, tl, run_subdir, exp_name)

                # 6) Normal post
                tl.sleep_mark(t_normal_post * 60, f"{exp_name}:normal_post_done")

                # 7) Stop sentinel & collect logs
                if exp.kali.dataset_cmd:
                    sentinel_stop_and_collect(si, kvm, kauth, tl, run_subdir, run_idx, exp_name)

                # 8) Collect attack logs (kali)
                for (g, l) in exp.kali.attack_collect:
                    try:
                        local_target = compute_local_target(run_subdir, exp_name, l)
                        guest_download(si, kvm, kauth, g, local_target)
                        tl.mark("collect_kali", {"guest": g, "local": local_target})
                    except Exception as e:
                        warn(f"Collect Kali:{g} → falhou ({e})")

                # 9) Collect others
                for vm_name, items in exp.collect_others.items():
                    if vm_name not in vm_map:
                        warn(f"VM desconhecida em collect_others: {vm_name}")
                        continue
                    vma = guest_auths[vm_name]; vmx = vm_map[vm_name]
                    for (g, l) in items:
                        try:
                            local_target = compute_local_target(run_subdir, exp_name, l)
                            guest_download(si, vmx, vma, g, local_target)
                            tl.mark("collect_other", {"vm": vm_name, "guest": g, "local": local_target})
                        except Exception as e:
                            warn(f"Collect {vm_name}:{g} → falhou ({e})")

                # 10) Snapshot em todas as VMs
                snap_name = f"exp-{exp_name}-{now_ts()}"
                create_snapshot_all(vm_entries, vm_map, snap_name, f"Snapshot pós {exp_name}",
                                    memory=args.snapshot_memory, quiesce=args.snapshot_quiesce)
                tl.mark(f"{exp_name}:snapshots_done", {"snapshot": snap_name})

            tl.mark("run_end", {"run": run_idx})
            tl.dump()

            if not infinite and run_idx >= iterations:
                info("Número de iterações atingido — a terminar")
                break

            if pause_between_runs:
                info(f"A aguardar {pause_between_runs}s antes da próxima execução")
                time.sleep(pause_between_runs)

        info("Todas as execuções concluídas.")

    except Exception as e:
        die(str(e))
    finally:
        if si:
            Disconnect(si)

if __name__ == '__main__':
    main()
