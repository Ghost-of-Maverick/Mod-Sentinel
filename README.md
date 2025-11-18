<p align="center">
  <img src="./notas/logo_modsentinel.png" alt="Mod-Sentinel Logo" width="200"/>
</p>
<h3 align="center">Prova de Conceito de um Sistema de Deteção de Intrusões para ICS baseado em ML</h3>

---

A proteção de sistemas industriais tornou-se central na segurança de infraestruturas críticas. A aproximação entre OT e IT trouxe novas superfícies de ataque, agravadas pelo uso contínuo de protocolos como Modbus/TCP, que carecem de autenticação, encriptação e validação de integridade.

Este projeto apresenta o **Mod-Sentinel**, uma prova de conceito de um sistema de deteção de intrusões baseado em Machine Learning, validado
num ambiente SCADA virtualizado que replica um cenário industrial realista. O ambiente inclui PLCs virtuais, HMI, attacker node e
monitorização passiva através de uma interface em modo promíscuo no ESXi.

A simulação do processo físico, nomeadamente da temperatura do óleo controlada pelos PLCs, foi criada com o intuito de refletir um dinamismo real, integrando ruído, curvas assintóticas e dependência do estado do motor. Com este ambiente, foram gerados datasets completos com tráfego legítimo e malicioso: DoS, MitM com manipulação de pacotes Modbus e operações de scouting.

Foi criado código que processa estes dados e treina um classificador Random Forest capaz de prever comportamentos anómalos. O Mod-Sentinel cria um relatório HTML, bem como ficheiros CSV com os resultados de treino do modelo.

---

## 📂 Estrutura do Repositório

- [`./notas/`](./notas/) — Relatório principal e documentação adicional
- [`./scripts/`](./scripts/) — Scripts de simulação, automação e ataques
- [`./logs/`](./logs/) — Logs do Mod-Sentinel e datasets exportados
- [`./resultados/`](./resultados/) — Outputs das experiências
- [`./modelo-ml/`](./modelo-ml/) — Código do modelo de ML e resultados do treino

---

## 📄 Documentação

🔗 Relatório detalhado: [`./notas/job_report_v1.5.pdf`](./notas/job_report_v1.5.pdf)  
🔗 Arquitetura base do sistema: [`./notas/Infrastructure_report_v1.1.pdf`](./notas/Infrastructure_report_v1.1.pdf)

---

<p align="center"><b>Mod-Sentinel — Security through visibility.</b></p>
