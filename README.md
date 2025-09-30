# SCADA Data Collection & Mod-Sentinel

Este repositório reúne o trabalho desenvolvido no âmbito da recolha de dados **SCADA** e da aplicação **Mod-Sentinel**, focada na deteção de ataques em redes industriais Modbus/TCP.

## Estrutura

- [`./notas/`](./notas/) → Relatório e notas do projeto
- [`./scripts/`](./scripts/) → Scripts de simulação, automação das experiências e ataques
- [`./logs/`](./logs/) → Diretoria para armazenar logs do Mod-Sentinel como os CSV que guardam os dados devidamente marcados do tráfego
- [`./resultados/`](./resultados/) → resultados das experiências efetuadas (ficheiros CSV)

## Principais componentes

- **Ambiente virtualizado no VMWare ESXi**: máquinas Debian que simulam PLCs (OpenPLC), Windows Server (HMI) e Kali Linux
- **Mod-Sentinel**: aplicação Python para analisar, marcar e guardar tráfego para as experiências
- **Experiências**: ataques DoS, MitM e scouting

---

🔗 Mais detalhes no relatório: [`./notas/job_report_v1.3.pdf`](./notas/job_report_v1.3.pdf)
