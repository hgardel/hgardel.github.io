# Wazuh SOC Lab

Laboratório de monitoramento de segurança construído do zero pra praticar coleta de log, detecção e investigação em ambiente controlado.

## Arquitetura

- Duas VMs Ubuntu Server no VirtualBox
- Uma rodando o servidor Wazuh (manager)
- Outra como endpoint, com o agente Wazuh instalado
- Rede combinando NAT (acesso à internet) e host-only (comunicação isolada entre as VMs)
- Administração das duas VMs via SSH

## Teste controlado

Simulei uma tentativa de autenticação SSH com um usuário inexistente no endpoint, pra observar como o Wazuh detecta e classifica esse tipo de evento.

## Detecção

O teste disparou a regra 5710 do Wazuh, referente a tentativa de login SSH com usuário inválido.

## Análise

A partir do alerta, investiguei:

- Log bruto e evento em formato JSON
- IP de origem da tentativa
- Usuário utilizado na tentativa
- Horário do evento
- Severidade atribuída pelo Wazuh
- Mapeamento da técnica correspondente no MITRE ATT&CK

Também usei consultas DQL diretamente na interface do Wazuh pra filtrar e cruzar eventos.

## O que isso demonstra

- Configuração de arquitetura cliente-servidor de SIEM open source
- Coleta e centralização de log via agente
- Leitura e interpretação de alerta de segurança
- Investigação de evento suspeito, ligando log técnico a contexto de ameaça (MITRE ATT&CK)

[Voltar](./index.md)
