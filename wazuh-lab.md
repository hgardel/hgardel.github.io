# Wazuh SOC Lab

Laboratório de monitoramento de segurança construído do zero pra praticar coleta de log, detecção, configuration assessment e investigação em ambiente controlado.

## Arquitetura

- VirtualBox, duas VMs Ubuntu Server 24.04 LTS:
  - **wazuh-server**: servidor Wazuh (manager)
  - **ubuntu-endpoint**: endpoint com o agente Wazuh instalado
- Rede combinando NAT (acesso à internet) e rede interna host-only (comunicação isolada entre as VMs)
- Agente instalado via assistente de deploy do próprio Wazuh (pacote DEB, endereço do servidor apontado manualmente)
- Administração via SSH

## Detecção: tentativa de autenticação SSH inválida

Simulei uma tentativa de login SSH usando um usuário inexistente no endpoint, repetida 4 vezes numa janela de cerca de 20 segundos.

O Wazuh disparou a regra **5710** ("sshd: Attempt to login using a non-existent user") nas 4 tentativas, nível de severidade 5.

Na investigação, cheguei a:

- Log bruto e evento em formato JSON
- IP de origem, usuário utilizado e horário exato de cada tentativa
- Agente de origem (ubuntu-endpoint, agent.id 001)
- Consulta DQL (`agent.id:"001" AND rule.groups:"sshd"`) pra isolar os 4 eventos entre as dezenas de outros logs do período

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

- Configuração de arquitetura cliente-servidor de SIEM open source
- Deploy de agente via assistente oficial
- Coleta e centralização de log
- Investigação de alerta usando consulta DQL
- Configuration assessment contra benchmark reconhecido (CIS), com leitura de score e priorização de achados
- Conexão entre log técnico, configuração insegura e contexto de ameaça

[Voltar](./index.md)
