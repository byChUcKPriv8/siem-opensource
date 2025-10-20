# Projeto SIEM – Fortinet + Wazuh (FaithTech)

## 🧠 Visão Geral
Este projeto implementa uma arquitetura **SIEM completa** integrando **FortiGate**, **rsyslog** e **Wazuh 4.9.2 (OpenSearch)** para centralizar logs, detectar ameaças e gerar visibilidade em tempo real sobre a infraestrutura. O ambiente foi projetado para ser **reprodutível, escalável e didático**, servindo como **portfólio profissional e base de estudos em segurança da informação**.

---

## ⚙️ Tecnologias Utilizadas
- **FortiGate (100F / 60F)** – Firewall perimetral e VPN IPsec
- **rsyslog (Ubuntu Server)** – Coletor e agregador de logs
- **Wazuh 4.9.2 + OpenSearch** – SIEM, análise, dashboard e correlação
- **Linux & Windows Agents** – Monitoramento de servidores e FIM (File Integrity Monitoring)
- **Bash / Python** – Scripts de automação e enriquecimento de IOC

---

## 🎯 Objetivo do Projeto
- Centralizar e normalizar logs de segurança em múltiplos sites.
- Criar detecções personalizadas para eventos FortiGate (DDoS, brute force, etc.).
- Integrar monitoramento de servidores Linux e Windows.
- Documentar arquitetura e práticas SOC aplicáveis a PMEs.

---

## 🧩 Estrutura do Ambiente
```
Filiais (FG-60F) --IPsec--> Matriz (FG-100F) --Syslog--> srv-syslog --Filebeat/rsyslog--> srv-wazuh
                                                  |                                    | 
                                                  └---> Wazuh Agents (Linux/Windows) --┘
```

- **srv-syslog:** Recebe logs FortiGate via UDP/TCP 514, roteia e organiza via `rsyslog`.
- **srv-wazuh:** Analisa, correlaciona e visualiza via OpenSearch Dashboards.
- **Agentes:** Coletam eventos e FIM de estações e servidores.

---

## 🧰 Componentes e Funções
### 🔸 FortiGate
- Envio remoto de logs em formato **key=value** via UDP/TCP 514.
- Categorias ativas: `traffic`, `event`, `utm`.
- Padronização de `devname`, `vd`, `interface` e `tz`.

### 🔸 Servidor Syslog
- Listener rsyslog configurado:
```conf
module(load="imudp")
input(type="imudp" port="514")
module(load="imtcp")
input(type="imtcp" port="514")
$template FortiFmt,"/var/log/fortigate-%fromhost-ip%.log"
if ($fromhost-ip startswith '192.168.') then {
  action(type="omfile" DynaFile="FortiFmt")
  stop
}
```
- Logrotate configurado com compressão, rotação e permissões corretas (`syslog:adm`).

### 🔸 Servidor Wazuh (SIEM)
- Stack Wazuh + Indexer + OpenSearch Dashboards.
- Política ISM de retenção 14 dias:
```json
{
  "policy": {
    "description": "Delete Wazuh indices older than 14d",
    "default_state": "hot",
    "states": [
      { "name": "hot", "actions": [], "transitions": [
        { "state_name": "delete", "conditions": { "min_index_age": "14d" } }
      ]},
      { "name": "delete", "actions": [ { "delete": {} } ] }
    ],
    "ism_template": [ { "index_patterns": ["wazuh-*"], "priority": 100 } ]
  }
}
```

---

## 🧠 Decoders e Regras Customizadas
### local_decoder.xml
- Regexs otimizadas para campos: `type`, `subtype`, `srcip`, `dstip`, `action`, `vd`, etc.

### local_rules.xml
```xml
<group name="fortigate,bruteforce">
  <rule id="88010" level="8">
    <if_decoder name="fortigate-traffic"/>
    <match>action=deny|event=failed|auth</match>
    <description>FortiGate brute force / múltiplas falhas em janela curta</description>
    <frequency>6</frequency>
    <timeframe>60</timeframe>
    <same_srcip />
  </rule>
</group>
```

---

## 🔄 Automação de Bloqueios (PoC)
- **publish_blocklist.sh** — Atualizado para manter histórico de IPs:
```bash
echo "$IP" >> /opt/blocklist/blocklist.txt
sort -u /opt/blocklist/blocklist.txt -o /opt/blocklist/blocklist.txt
```
- **enrich_and_decide.py** — Script opcional para enriquecer e validar IOC antes do bloqueio.
- Integração sugerida com **FortiGate Dynamic Address Group** via HTTP/FTP.

---

## 📊 Dashboards (OpenSearch)
- Painéis otimizados para versão 4.9.2 (sem Kibana).
- Views principais:
  - **Threat Overview** – top IPs, eventos críticos e tendências.
  - **FortiGate Traffic** – sessões, políticas e portas anômalas.
  - **Auth & Brute Force** – falhas por IP, usuário e tempo.
  - **File Integrity (FIM)** – alterações em shares e hotspots de usuários.

---

## 📘 Boas Práticas
- Padronizar nomes de políticas e interfaces FortiGate.
- Versionar decoders, regras e dashboards.
- Validar logs e rotação semanalmente.
- Backups de configs (FortiGate, rsyslog, Wazuh).
- Notificações de eventos críticos via webhook (futuro).

---

## 🚀 Melhorias Futuras
- TLS no syslog para transmissão segura.
- Enriquecimento GeoIP e reputação em decoders.
- Integração com automação FortiGate API.
- Expansão de dashboards e relatórios executivos.

---

## 👨‍💻 Autor
**Lucas Eziquiel – FaithTech Soluções em TI**  
Infraestrutura, Segurança da Informação e Automação de Redes  
📍 Projeto de portfólio e estudo – 2025

📫 Contato: [LinkedIn](https://www.linkedin.com/in/lucaseziquiel)  
🛠️ Licença: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)

---

## 🧩 Hashtags sugeridas para post:
`#wazuh #opensearch #fortinet #siem #cybersecurity #infosec #rsyslog #soc #portfolio #bluesecurity`

