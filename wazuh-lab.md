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

## Detecção: falhas de logon no Windows (T1110)

Simulei tentativas de logon inválidas no endpoint Windows, com a auditoria de logon habilitada. Foram 12 tentativas manuais (uma bem-sucedida) e 10 eventos 4625 registrados.

| Item | Valor |
|---|---|
| Falha de logon | evento 4625, regra 60122, nível 5 |
| Múltiplas falhas | regra 60204, nível 10, disparou na 8ª falha (frequência 8), T1110 |
| Bloqueio de conta | evento 4740, regra 60115, nível 9, cerca de 2 segundos depois |

Limitação: o bloqueio da conta interrompe novos eventos 4625, então a contagem no SIEM fica abaixo do número real de tentativas.

Detalhes: [fase2-cenarios.md](https://github.com/hgardel/wazuh-soc-lab/blob/main/docs/fase2-cenarios.md).

## Detecção: PowerShell com comando codificado (T1059.001)

**Objetivo:** verificar se o Wazuh detecta a execução de PowerShell com `-EncodedCommand`, usando o evento 1 do Sysmon.

**Técnica MITRE ATT&CK:** T1059.001 (Command and Scripting Interpreter: PowerShell). Tática: Execution.

**Ambiente:** `windows-endpoint` (Windows 11, Sysmon, agente 002) e `wazuh-server` 4.14.7, em rede host-only isolada. Teste local e controlado.

**Procedimento:** em um PowerShell elevado no endpoint, executei duas vezes:

```
powershell -NoProfile -EncodedCommand aABvAHMAdABuAGEAbQBlAA==
```

O payload é Base64 em UTF-16LE. Decodificado no host, resulta em `hostname`, um comando inofensivo:

```
echo 'aABvAHMAdABuAGEAbQBlAA==' | base64 -d | iconv -f UTF-16LE -t UTF-8
```

**Consulta DQL usada (Threat Hunting):**

```
data.win.system.eventID:"1" and data.win.eventdata.commandLine:*EncodedCommand*
```

### Resultados

| Item | Valor |
|---|---|
| Evento de origem | Sysmon evento 1 (Process Create) |
| Alertas gerados | 2, um por execução (31/10/2026, cerca de 16:56 e 16:59, horário local) |
| Regra | 92057, arquivo 0800-sysmon_id_1.xml |
| Descrição | Powershell.exe spawned a powershell process which executed a base64 encoded command |
| Nível | 12 |
| Grupos | sysmon, sysmon_eid1_detections, windows |
| Tática e técnica | Execution, PowerShell (T1059.001) |
| Latência | cerca de 2 segundos, do evento no Sysmon ao alerta no Wazuh |

### Campos do evento 1 (primeiro alerta)

| Campo | Valor |
|---|---|
| Image | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| OriginalFileName | PowerShell.EXE (igual ao nome do binário, sem renomeação) |
| ParentImage | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| ParentCommandLine | `powershell.exe` (shell interativo, sem argumentos) |
| CommandLine | `powershell.exe -NoProfile -EncodedCommand aABvAHMAdABuAGEAbQBlAA=` |
| IntegrityLevel | High (shell elevado) |
| TerminalSessionId | 1 (sessão interativa) |
| CurrentDirectory | `C:\WINDOWS\system32\` |
| SHA256 | 60C9B29843624DD8AF6B6A7B26147753BE6AEEF65098B9A503CC50850AFE410F |

Usuário e hostname foram omitidos por privacidade. O segundo alerta (cerca de 16:59) não foi aberto individualmente.

### Enriquecimento (VirusTotal)

- Consultei o SHA256 do `powershell.exe` por busca (somente o hash, sem enviar o arquivo).
- Resultado: 0 de 71 fornecedores marcaram como malicioso. Nome do arquivo: PowerShell.EXE, 484 KB.
- Conclusão: o binário é o PowerShell legítimo do Windows, sem reputação maliciosa.
- Os relatórios de sandbox exibem sinais como tags de ofuscação e regras Sigma. Eles refletem o comportamento da própria ferramenta em sandbox (e, provavelmente, o ambiente do teste), não indicam que o binário seja malicioso.
- O PowerShell é um LOLBin. A reputação do hash não detecta o abuso, que aparece só na linha de comando e no processo pai. Por isso a regra 92057 analisa `commandLine` e `parentImage`, e não o hash.

### Análise

- A regra 92057 exige duas condições: o processo pai é `powershell.exe` e a CommandLine contém `powershell.exe` seguido de `-EncodedCommand` ou de uma abreviação (`-e`, `-ec`, `-enc` e variantes). Os dois campos acima atendem a regra.
- Triagem: **verdadeiro positivo de comportamento, atividade benigna e esperada** (teste do lab).
- Um payload inofensivo gerou alerta de nível 12. A regra detecta a técnica, não a intenção. Em produção, o analista decodificaria o comando e checaria processo pai, usuário, nível de integridade, horário e frequência antes de escalar.
- Sinais que aumentariam a suspeita em produção: pai inesperado (Office, navegador), usuário fora do padrão, execução fora do horário e payload que baixa ou executa código remoto.
- O CommandLine registrado termina com um único `=`, diferente do comando planejado (`==`), provável erro de digitação. A regra disparou mesmo assim. O Sysmon registra a criação do processo, não o resultado da execução.

### Limitações

- A regra depende do processo pai ser PowerShell. Não testei a execução a partir de outro pai (por exemplo, o CMD). É uma hipótese a validar.
- Não testei ofuscações além do `-EncodedCommand` padrão.
- O evento 1 não mostra a saída do comando. Ver o conteúdo decodificado exigiria o PowerShell Script Block Logging (evento 4104), que não estava habilitado.
- Foi um único payload, inofensivo e de teste.

## O que isso demonstra

- Arquitetura cliente-servidor de SIEM open source
- Deploy de agente via assistente oficial
- Coleta e centralização de logs de Linux e Windows
- Investigação de alerta com consulta DQL e com Sysmon (ParentImage, assinatura)
- Configuration assessment contra benchmark CIS, com leitura de score e priorização
- Conexão entre log técnico, configuração insegura e contexto de ameaça
- Detecção de força bruta no Windows (T1110) e de PowerShell codificado (T1059.001), com triagem por processo pai, integridade e hash

[Voltar](./index.md)
