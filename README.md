<img src="./notas/logo_modsentinel.png" alt="Mod-Sentinel Logo" width="180"/>
# Prova de Conceito de um Sistema de Deteção de Intrusões para Sistemas de Controlo Industriais baseado em Machine Learning

A segurança de sistemas industriais tornou-se um vetor crítico na proteção de infraestruturas essenciais. A convergência entre tecnologia operacional (OT) e tecnologia de informação (IT) expôs redes industriais a novos riscos, especialmente em ambientes baseados em protocolos como o Modbus/TCP, que continuam a ser amplamente utilizados mas carecem de mecanismos nativos de autenticação e encriptação. Este trabalho apresenta o desenvolvimento e validação de um protótipo funcional de um sistema de deteção de intrusões baseado em Machine Learning, aplicado a um cenário SCADA virtualizado que replica o comportamento de um sistema real de controlo de processos.<br>

O estudo integra três componentes essenciais: simulação fiel de processos industriais, geração sistemática de tráfego malicioso e legítimo, e construção de modelos capazes de distinguir ambos com precisão. Para isso, foi criado um ambiente isolado em VMware ESXi que inclui PLCs virtuais, uma HMI e uma máquina atacante, suportado por mecanismos de monitorização passiva através de interfaces configuradas em modo promiscuo. A dinâmica dos sensores, particularmente a simulação da temperatura do óleo, que foi pensada para representar com maior realismo o comportamento físico de um sistema industrial, incorporando modelos assintóticos, ruído e dependência do estado do motor.<br>

Com este ambiente estabelecido, foram realizados vários tipos de ataques, desde DoS (físicos e lógicos), técnicas de Man-in-the-Middle com manipulação seletiva de pacotes Modbus, até operações de reconhecimento baseadas na leitura não autorizada de registos. A recolha do tráfego resultante permitiu criar datasets devidamente marcados, essenciais para treinar um modelo de ML.

---

## Estrutura

- [`./notas/`](./notas/) → Relatório e notas do projeto.
- [`./scripts/`](./scripts/) → Scripts de simulação, automação das experiências e ataques
- [`./logs/`](./logs/) → Diretoria para armazenar logs do Mod-Sentinel como os CSV que guardam os dados devidamente marcados do tráfego.
- [`./resultados/`](./resultados/) → Resultados das experiências efetuadas.
- [`./modelo-ml/`](./modelo-ml/) → Código do script de treino do modelo de ML e resultados obtidos.

---

## Documentação

🔗 Mais detalhes no relatório: [`./notas/job_report_v1.4.pdf`](./notas/job_report_v1.5.pdf)<br>
🔗 Ver também o relatório da arquitetura base do sistema: [`./notas/Infrastructure_report_v1.1.pdf`](./notas/Infrastructure_report_v1.1.pdf)
