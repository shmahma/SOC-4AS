# Description

Cette règle sera levée lorsqu'une connection avec un compte explicite est faite, en excluant les opération de maintenance de routine. C'est une action fréquente lors d'un pivot quand une machine a été infectée.

# Criticité : **MEDIUM**


# Règle SPL

```
index="connectix" EventCode=4648
NOT (Account_Name="frank" OR Account_Name="olivia")
NOT Process_Name="C:\Windows\System32\lsass.exe"

```

# Règle SIGMA

```
title: Suspicious Logon Attempt Excluding Specific Accounts and Process
id: a1c7a5b2-e9a2-4d34-92b2-dbd9d227c3fb
description: Detects logon attempts where the account name is neither "frank" nor "olivia" and the process is not lsass.exe.
author: Léo JAILLET
date: 2024-11-10
logsource:
  category: authentication
  product: windows
detection:
  event_id:
    EventID: 4648
  account_name:
    Account_Name:
      - frank
      - olivia
  process:
    Process_Name:
      - 'C:\Windows\System32\lsass.exe'
  condition: event_id and (not account_name and not process)
falsepositives:
  - Unusual user accounts performing logins
level: medium

```

# Explication

On vérifie que le compte ne vient pas d'un des deux administrateurs et que le processus n'est pas lsass.exe car c'est un fonctionnement légitime dans l'entreprise.