# Description

Cette règle sera levée lorsque quelqu'un énumère les groupes d'un utilisateur, une action qui peut être effectuée par un attaquant en pleine reconnaissance.

# Criticité : **LOW**

# Outils

Sysmon

# Règle SPL

```
index="connectix" EventCode=4798
```

# Règle SIGMA

```
title: User Group Membership Enumeration (EventID 4798)
id: 2d4b73b9-75a4-4f4e-9f9a-4d745f9e15d7
description: Detects enumeration of user group memberships (EventID 4798), which could indicate reconnaissance activities by an attacker.
author: Léo JAILLET
date: 2024-11-10
logsource:
  category: authentication
  product: windows
detection:
  selection:
    EventID: 4798
  condition: selection
falsepositives:
  - Legitimate administrative actions or auditing tools
level: low


```

# Explication

On regarde tous les événementes de ce type, ce n'est pas une action qui est faite par un utilisateur standard et doit donc être regardé.