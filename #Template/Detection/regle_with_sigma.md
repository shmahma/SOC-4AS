
# Titre
Potentially Suspicious Self Extraction Directive File Created 

# Description

Cette règle sera levée en cas de création de fichiers avec l'extension .sed qui sont des fichiers de type Self Extraction Directive (directive d'auto-extraction).Cette règle a été choisi du git de sigma : https://github.com/SigmaHQ/sigma/tree/master/rules 

# Criticité : **Medium**


# Règle SPL

```
index="connectix" EventCode=11 TargetFilename="*.sed"

```

# Règle SIGMA

```
title: Potentially Suspicious Self Extraction Directive File Created
id: ab90dab8-c7da-4010-9193-563528cfa347
related:
    - id: 760e75d8-c3b5-409b-a9bf-6130b4c4603f
      type: derived
status: experimental
description: |
    Detects the creation of a binary file with the ".sed" extension. The ".sed" extension stand for Self Extraction Directive files.
    These files are used by the "iexpress.exe" utility in order to create self extracting packages.
    Attackers were seen abusing this utility and creating PE files with embedded ".sed" entries.
    Usually ".sed" files are simple ini files and not PE binaries.
references:
    - https://strontic.github.io/xcyclopedia/library/iexpress.exe-D594B2A33EFAFD0EABF09E3FDC05FCEA.html
    - https://en.wikipedia.org/wiki/IExpress
    - https://www.virustotal.com/gui/file/602f4ae507fa8de57ada079adff25a6c2a899bd25cd092d0af7e62cdb619c93c/behavior
author: Joseliyo Sanchez, @Joseliyo_Jstnk
date: 2024-02-05
tags:
    - attack.defense-evasion
    - attack.t1218
logsource:
    product: windows
    category: file_executable_detected
detection:
    selection:
        TargetFilename|endswith: '.sed'
    condition: selection
falsepositives:
    - Unknown
level: medium
```

# Explication

Cette règle permet de détecter la création de fichiers avec l'extension .sed
Ces fichiers .sed sont normalement de simples fichiers de configuration, mais les attaquants peuvent les abuser pour emballer des fichiers malveillants dans des paquets d'auto-extraction.




# Titre
Potential Malicious activity 

# Description

Cette règle détecte des comportements associés à Mustang Panda puisqu'ils utilisent les outils d'administration comme PowerShell, WMIC et CMD pour mener des attaques sophistiquées. Les signes d'alerte incluent des processus exécutés de manière inhabituelle par des utilisateurs non admins. 

# Criticité : **Medium**


# Règle SPL

```
index="connectix" sourcetype="WinEventLog" 
(EventCode=4688 OR EventCode=4672) 
(New_Process_Name="*powershell.exe" OR New_Process_Name="*wmic.exe" OR New_Process_Name="*cmd.exe") 
| eval suspicious_process=case(
    like(New_Process_Name, "%powershell.exe%"), "PowerShell",
    like(New_Process_Name, "%wmic.exe%"), "WMIC",
    like(New_Process_Name, "%cmd.exe%"), "Command Prompt",
    true(), "Other"
) 
| search NOT Account_Name IN ("frank", "olivia", "alice", "yara", "david", "katherine", "uma", "SRV-PRD-DC$", "SRV-PRD-WEB$", "SRV-PRD-DB$", "SRV-PRD-SHARE$")
| stats count by host, Account_Name, New_Process_Name, suspicious_process, ComputerName, _time, EventCode
| where count > 5


```

# Règle SIGMA

```
title: Détection des activités de Mustang Panda
id: 43b3cbe9-ffd0-4607-98ed-c1114f3ccf01
status: experimental
description: Détecte des comportements associés aux techniques d'attaque de Mustang Panda, comme l'utilisation de PowerShell ou WMIC par des comptes suspects.
author: Hadil M .
date: 2024-11-10
tags:
    - attack.t1078
    - attack.t1086
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 4688
            - 4672
        NewProcessName|contains:
            - "powershell.exe"
            - "wmic.exe"
            - "cmd.exe"
    filter:
        AccountName:
            - frank
            - olivia
            - alice
            - yara
            - david
            - katherine
            - uma
            - SRV-PRD-DC$
            - SRV-PRD-WEB$
            - SRV-PRD-DB$
            - SRV-PRD-SHARE$
    condition: selection and not filter
falsepositives:
    - Utilisation légitime de PowerShell, WMIC ou CMD par des administrateurs 
level: medium

```

# Explication

Cette règle identifie des activités inhabituelles par des comptes qui n’ont normalement pas de privilèges d'administration, en se concentrant sur l'utilisation de processus liés à l’administration comme PowerShell et l'invite de commande.  Cela permet de repérer d'éventuelles attaques ciblées comme celles du groupe Mustang Panda.
