# Wazuh SOC Lab

Laboratório local de monitoramento de segurança com Wazuh, Sysmon e VirtualBox. Código e documentação: [wazuh-soc-lab](https://github.com/hgardel/wazuh-soc-lab).

## Arquitetura
- Servidor Wazuh 4.14.7 em Ubuntu Server
- Endpoint Linux (Ubuntu Server) com agente Wazuh
- Endpoint Windows 11 com agente Wazuh e Sysmon
- Rede host-only isolada, sem exposição à internet

## Detecção: tentativa de autenticação SSH inválida

Simulei uma tentativa de login SSH usando um usuário inexistente no endpoint, repetida 4 vezes numa janela de cerca de 20 segundos.

O Wazuh disparou a regra **5710** ("sshd: Attempt to login using a non-existent user") nas 4 tentativas, nível de severidade 5.

Na investigação, cheguei a:

- Log bruto e evento em formato JSON
- IP de origem, usuário utilizado e horário exato de cada tentativa
- Agente de origem (ubuntu-endpoint, agent.id 001)
- Consulta DQL (`agent.id:"001" AND rule.groups:"sshd"`) pra isolar os 4 eventos entre as dezenas de outros logs do período

## Endpoint Windows com Sysmon

- Sysmon v15.22 com a configuração SwiftOnSecurity
- Coleta do canal `Microsoft-Windows-Sysmon/Operational` via `eventchannel`
- Problemas encontrados e correções: [docs/sysmon-windows.md](https://github.com/hgardel/wazuh-soc-lab/blob/main/docs/sysmon-windows.md)
- Baseline CIS Windows 11: 24%

## Investigação: alerta de nível 9 que era falso positivo

- Regra 92205 (nível 9), mapeada para T1105 (Ingress Tool Transfer)
- Processo filho de `wazuh-agent.exe`, com assinatura digital válida
- Conclusão: falso positivo, causado pela própria varredura do agente
- Ajuste futuro com supressão restrita ao `ParentImage`

Detalhes e evidências: [investigação completa](https://github.com/hgardel/wazuh-soc-lab/blob/main/investigations/01-falso-positivo-sca.md).

## Configuration Assessment (CIS Benchmark)

Além da detecção de log, rodei o módulo de Security Configuration Assessment do Wazuh contra o CIS Ubuntu Linux 24.04 LTS Benchmark no endpoint.

Resultado: pontuação 43/100 (102 checks aprovados, 135 reprovados, de 279 no total).

Entre os itens reprovados que investiguei:

- `sshd UsePAM` desabilitado
- `sshd PermitEmptyPasswords` permitido
- `sshd GSSAPIAuthentication` habilitado (superfície de ataque desnecessária)
- `sshd HostbasedAuthentication` habilitado
- `sshd LogLevel` abaixo do recomendado (perda de visibilidade de auditoria)

Cada achado já vem mapeado pra MITRE ATT&CK (táticas como TA0001 e TA0008, técnicas como T1078 e T1021), PCI DSS, HIPAA e NIST SP 800-53, com a remediação sugerida.

## Dashboard geral

Com os agentes rodando, o painel Overview consolidou, em 24h: 92 alertas de severidade média (nível 7 a 11) e 41 de severidade baixa, cruzando eventos de SCA, autenticação e log de sistema.

## O que isso demonstra

- Arquitetura cliente-servidor de SIEM open source
- Deploy de agente via assistente oficial
- Coleta e centralização de logs de Linux e Windows
- Investigação de alerta com consulta DQL e com Sysmon (ParentImage, assinatura)
- Configuration assessment contra benchmark CIS, com leitura de score e priorização
- Conexão entre log técnico, configuração insegura e contexto de ameaça

[Voltar](./index.md)
