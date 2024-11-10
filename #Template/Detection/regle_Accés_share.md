# Description

Cette règle sera levée en cas de tentative d'accès à un partage réseau par un utilisateur non authorisé à partir de l'événement EventCode=5140 dans les journaux Windows.

# Criticité : **LOW**

# Outils

Windows Event Logs

# Règle SPL

```
index="connectix" sourcetype="WinEventLog" EventCode=5140
| search NOT (Account_Name IN ("Zane", "Yara", "Ethan", "Scott", "David", "Noah", "Samuel", "Wila", "Alice", "Katherine", "Victor", "Lee", "Taylor", "Frank", "Olivia", "Uma", "SRV-PRD-WEB$", "SRV-PRD-DB$", "SRV-PRD-SHARE$", "SRV-PRD-DC$"))

```

# Règle SIGMA

```
title: Détection d'une tentative d'accès à un partage réseau par un utilisateur exclu
status: experimental
description: |
    Cette règle détecte les tentatives d'accès à un partage réseau via l'événement `EventCode=5140` où l'utilisateur tentant d'accéder au partage réseau n'est pas dans la liste d'utilisateurs spécifiée.
    Cela permet d'identifier des accès réseau non autorisés par des utilisateurs autres que ceux autorisés.
author: Inès OUESALTI
date: 2024-11-10
tags:
    - attack.t1071.001
    - attack.discovery
    - attack.exfiltration
logsource:
    product: windows
    category: file
    service: security
detection:
    selection:
        EventCode: 5140
        Account_Name|not_in:
            - "Zane"
            - "Yara"
            - "Ethan"
            - "Scott"
            - "David"
            - "Noah"
            - "Samuel"
            - "Wila"
            - "Alice"
            - "Katherine"
            - "Victor"
            - "Lee"
            - "Taylor"
            - "Frank"
            - "Olivia"
            - "Uma"
            - "SRV-PRD-WEB$"
            - "SRV-PRD-DB$"
            - "SRV-PRD-SHARE$"
            - "SRV-PRD-DC$"
    condition: selection
falsepositives:
    - Connexion légitime effectuée par des administrateurs ou utilisateurs ayant des horaires spéciaux
    - Connexion d'un utilisateur ayant un besoin ponctuel d'accès à un partage réseau spécifique
level: low


```

# Explication
Cette règle détecte les événements EventCode=5140, qui correspondent à une tentative d'accès à un partage réseau. La règle filtre les connexions en excluant un certain nombre d'utilisateurs spécifiés dans la liste, ce qui permet de se concentrer sur les tentatives d'accès provenant d'utilisateurs qui ne font pas partie de ces comptes.