# Description

Cette règle sera levée si les journaux de sécurité de Windows sont supprimés (chose qui n'est pas censé arriver), signe qu'un attaquant essaie de masquer son passage.

# Criticité : **LOW**

# Règle SPL

```
index="connectix" EventCode=1102
```

# Règle SIGMA

```
title: Audit Log Cleared (EventID 1102)
id: 8c7b41d4-1c92-4904-b1a7-29045b11566f
description: Detects the clearing of audit logs (EventID 1102) which may indicate an attempt to cover tracks or erase traces of malicious activity.
author: Léo JAILLET
date: 2024-11-10
logsource:
  category: system
  product: windows
detection:
  selection:
    EventID: 1102
  condition: selection
falsepositives:
  - Routine log maintenance or administrative actions
level: high


```

# Explication

On récupère tous les événements de ce type, c'est un event qui n'est pas censé se produire normalement donc c'est nécessairement une intervention manuelle qui nécessite de regarder en détail.