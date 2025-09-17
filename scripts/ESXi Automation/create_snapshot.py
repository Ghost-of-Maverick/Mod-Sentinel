from pyVim import connect
from pyVmomi import vim
import ssl
import threading
import sys
import time

# --- Configurações ---
VCENTER_HOST = "192.168.136.149"
VCENTER_USER = "root"
VCENTER_PASSWORD = "password"
VM_NAMES = [
    "KaliST01",
    "OpenPLC-RTU-PRV",
    "OpenPLC-PRV",
    "HMI-RSC-PRV"
]
SNAPSHOT_NAME = "clean"
SNAPSHOT_DESC = "snapshot inicial - experiencias estado 0"
MEMORY = True          
QUIESCE = False        

# --- Funções auxiliares ---
def get_obj(content, vimtype, name):
    container = content.viewManager.CreateContainerView(content.rootFolder, vimtype, True)
    try:
        for obj in container.view:
            if obj.name == name:
                return obj
    finally:
        container.Destroy()
    return None

def wait_for_task(task, actionName='tarefa', hideResult=False):
    while task.info.state == vim.TaskInfo.State.running:
        time.sleep(1)
    if task.info.state == vim.TaskInfo.State.success:
        if task.info.result is not None and not hideResult:
            print(f"[INFO] {actionName} concluída com resultado: {task.info.result}")
        else:
            print(f"[INFO] {actionName} concluída com sucesso.")
        return task.info.result
    else:
        print(f"[ERRO] {actionName} falhou: {task.info.error}")
        raise task.info.error

def create_snapshot(vm, name, desc, memory, quiesce):
    try:
        print(f"[INFO] A criar snapshot '{name}' em {vm.name}...")
        task = vm.CreateSnapshot_Task(name=name, description=desc,
                                      memory=memory, quiesce=quiesce)
        wait_for_task(task, actionName=f"Snapshot {name} em {vm.name}")
    except Exception as e:
        print(f"[ERRO] VM {vm.name}: {e}")

def main():
    # Desativar verificação SSL (se certificado não for válido)
    context = ssl._create_unverified_context()

    # Conectar ao ESXi standalone
    si = connect.SmartConnect(host=VCENTER_HOST,
                              user=VCENTER_USER,
                              pwd=VCENTER_PASSWORD,
                              sslContext=context)
    content = si.RetrieveContent()

    # Obter VMs da lista
    vms = []
    for vm_name in VM_NAMES:
        vm = get_obj(content, [vim.VirtualMachine], vm_name)
        if vm:
            vms.append(vm)
        else:
            print(f"[AVISO] VM {vm_name} não encontrada")

    # Criar snapshots em paralelo (threads)
    threads = []
    for vm in vms:
        t = threading.Thread(target=create_snapshot, args=(vm, SNAPSHOT_NAME, SNAPSHOT_DESC, MEMORY, QUIESCE))
        t.start()
        threads.append(t)

    # Esperar que todas as threads terminem
    for t in threads:
        t.join()

    print("[INFO] snapshots finalizados.")

if __name__ == "__main__":
    main()
