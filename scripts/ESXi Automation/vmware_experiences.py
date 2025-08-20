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

# experiências — cada uma escolhe o script do ataque na Kali
experiments:
  - name: mitm
    kali:
      uploads:
        - local: ./attacks/mitm_attack.sh
          guest: /tmp/mitm_attack.sh
          chmod_x: true
      dataset:
        command: []          # opcional (outro recorder)
        timeout_sec: 0
        stop_signal: TERM
        collect: []
      attack:
        command: ["/bin/bash", "/tmp/mitm_attack.sh"]
        timeout_sec: 0       # ignorado; usamos timing.attack
        collect: []
    collect_others: {}

  - name: dos_syn
    kali:
      uploads:
        - local: ./attacks/dos_attack.sh
          guest: /tmp/dos_attack.sh
          chmod_x: true
      dataset:
        command: []
        timeout_sec: 0
        stop_signal: TERM
        collect: []
      attack:
        command: ["/bin/bash", "/tmp/dos_attack.sh", "hping3_synflood", "172.27.224.250", "eth0"]
        timeout_sec: 0
        collect: []
    collect_others: {}

  - name: scouting
    kali:
      uploads:
        - local: ./attacks/run_scouting.sh
          guest: /tmp/run_scouting.sh
          chmod_x: true
      dataset:
        command: []
        timeout_sec: 0
        stop_signal: TERM
        collect: []
      attack:
        command: ["/bin/bash", "/tmp/run_scouting.sh"]
        timeout_sec: 0
        collect: []
    collect_others: {}

Execução (exemplo):
  python vmware_experiments.py \
    --esxi 192.168.1.10 --user root --password 'ESXI_PASS' --insecure \
    --config ./experiments.yaml --snapshot-memory --snapshot-quiesce

Saída
- `./runs/<timestamp>/timeline.csv|json` com marcas das fases.
- Artefactos recolhidos conforme YAML.
- Snapshots por experiência: `exp-<nome>-<YYYYmmdd-HHMMSS>` em todas as VMs.
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

def guest_run(si, vm: vim.VirtualMachine, auth, command: List[str], timeout_sec: int) -> Tuple[int, int]:
    pm = si.content.guestOperationsManager.processManager
    spec = vim.vm.guest.ProcessManager.ProgramSpec(programPath=command[0], arguments=" ".join(command[1:]) or None)
    pid = pm.StartProgramInGuest(vm, auth, spec)
    start = time.time()
    while True:
        p = pm.ListProcessesInGuest(vm, auth, [pid])[0]
        if p.endTime is not None:
            return (p.exitCode or 0, int(time.time() - start))
        if timeout_sec and (time.time() - start) > timeout_sec:
            warn("Timeout a aguardar o processo (continua em background)")
            return (-1, int(time.time() - start))
        time.sleep(2)

def guest_download(si, vm: vim.VirtualMachine, auth, guest_path: str, local_path: str):
    fm = si.content.guestOperationsManager.fileManager
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
    dataset_timeout: int  # 0 = infinito
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

def parse_yaml(path: str) -> Tuple[List[VMEntry], List[Experiment], Dict[str, Any]]:
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

    return vms, exps, raw.get('timing', {})

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

def sentinel_start(si, kvm, kauth, tl: Timeline):
    rc, dur = guest_run(si, kvm, kauth, ["/bin/bash", "-lc", "~/mod-sentinel/python3 main.py start"], timeout_sec=120)
    tl.mark("sentinel_started", {"rc": rc, "dur_s": dur})

def sentinel_stop(si, kvm, kauth, tl: Timeline):
    rc, dur = guest_run(si, kvm, kauth, ["/bin/bash", "-lc", "~/mod-sentinel/python3 main.py stop"], timeout_sec=120)
    tl.mark("sentinel_stopped", {"rc": rc, "dur_s": dur})

def run_attack_with_timeout(si, kvm, kauth, attack_cmd: List[str], minutes: int, tl: Timeline):
    total_sec = minutes * 60
    quoted = " ".join([f'"{a}"' if ' ' in a else a for a in attack_cmd])
    shell_cmd = f"timeout {total_sec}s {quoted}"
    rc, dur = guest_run(si, kvm, kauth, ["/bin/bash", "-lc", shell_cmd], timeout_sec=total_sec + 60)
    tl.mark("attack_finished", {"rc": rc, "dur_s": dur})

# ---------------------------------- Main ---------------------------------- #

def main():
    ap = argparse.ArgumentParser(description="Orquestra experiências multi‑VM com pyVmomi (ESXi)")
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

        vm_entries, experiments, timing = parse_yaml(args.config)
        if not vm_entries:
            die("Nenhuma VM definida no YAML")
        if not experiments:
            die("Nenhuma experiência definida no YAML")

        t_normal_pre = int(timing.get('normal_pre', 10))
        t_attack = int(timing.get('attack', 20))
        t_normal_post = int(timing.get('normal_post', 10))

        # mapear VMs e autenticações
        vm_map: Dict[str, vim.VirtualMachine] = {}
        guest_auths: Dict[str, vim.NamePasswordAuthentication] = {}
        for v in vm_entries:
            vm_map[v.name] = find_vm_by_name(content, v.name)
            guest_auths[v.name] = guest_auth(v.guest_user, v.guest_pass)
        kali_name = next(v.name for v in vm_entries if v.name.lower().startswith('kali'))
        kvm = vm_map[kali_name]
        kauth = guest_auths[kali_name]

        run_dir = os.path.join('./runs', now_ts())
        tl = Timeline(run_dir)

        for exp in experiments:
            exp_name = exp.name
            tl.mark(f"{exp_name}:start")

            # 1) Revert + power-on + tools para todas as VMs
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

            # 3) 10 min normal com sentinel a correr
            sentinel_start(si, kvm, kauth, tl)
            tl.sleep_mark(t_normal_pre*60, f"{exp_name}:normal_pre_done")

            # 4) 20 min de ataque (timeout força paragem)
            run_attack_with_timeout(si, kvm, kauth, exp.kali.attack_cmd, t_attack, tl)

            # 5) 10 min normal pós-ataque
            tl.sleep_mark(t_normal_post*60, f"{exp_name}:normal_post_done")
            sentinel_stop(si, kvm, kauth, tl)

            # 6) Recolhas (se definidas)
            for vm_name, items in exp.collect_others.items():
                if vm_name not in vm_map:
                    warn(f"VM desconhecida em collect_others: {vm_name}")
                    continue
                vma = guest_auths[vm_name]; vmx = vm_map[vm_name]
                for (g, l) in items:
                    try:
                        guest_download(si, vmx, vma, g, l)
                    except Exception as e:
                        warn(f"Collect {vm_name}:{g} → falhou ({e})")
            for (g, l) in exp.kali.attack_collect:
                try:
                    guest_download(si, kvm, kauth, g, l)
                except Exception as e:
                    warn(f"Collect Kali:{g} → falhou ({e})")

            # 7) Snapshot em todas as VMs
            snap_name = f"exp-{exp_name}-{now_ts()}"
            create_snapshot_all(vm_entries, vm_map, snap_name, f"Snapshot pós {exp_name}",
                                memory=args.snapshot_memory, quiesce=args.snapshot_quiesce)
            tl.mark(f"{exp_name}:snapshots_done", {"snapshot": snap_name})

        tl.dump()
        info("Todas as experiências concluídas.")

    except Exception as e:
        die(str(e))
    finally:
        if si:
            Disconnect(si)

if __name__ == '__main__':
    main()
