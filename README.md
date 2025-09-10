# SCADA Data Collection & Mod-Sentinel

Este repositório reúne o trabalho desenvolvido no âmbito da recolha de dados **SCADA** e da aplicação **Mod-Sentinel**, focada na deteção de ataques em redes industriais Modbus/TCP.

📄 Relatório completo: [`./notas/job_report_v1.1.pdf`](./notas/job_report_v1.1.pdf)

## Estrutura

- `./notas/` → Relatório e notas do projeto
- `./scripts/` → Scripts de simulação, automação das experiências e ataques
- `./logs/` → Diretoria para armazenar logs do Mod-Sentinel como os CSV que guardam os dados devidamente marcados do tráfego

## Principais componentes

- **Ambiente virtualizado** no VMWare ESXi com máquinas Debian que simulam PLCs (OpenPLC), HMI e Kali Linux
- **Mod-Sentinel** (Python) para analisar, marcar e guardar tráfego para as experiências
- **Experiências**: ataques DoS, MitM e scouting
- **Resultados** guardados em [`./resultados/`](./resultados/)

---

🔗 Mais detalhes no relatório: [`./notas/job_report_v1.1.pdf`](./notas/job_report_v1.1.pdf)
