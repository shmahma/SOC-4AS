# Description

Cette règle sera levée lors d'un nombre d'échec de connection de 5 ou plus sur 1 heure.

# Criticité : **MEDIUM**


# Règle SPL

```
index="connectix" (EventCode=4625 OR EventCode=4771) earliest_time=-60m@m latest_time=now
| stats count by Account_Name
| where count > 5
```

# Règle SIGMA

```
title: Failed logon attemps
id: 3b1c0e7f-d59b-4a9d-bf84-8759dbbaf687
description: Detects a failed login attemps (EventID 4625 or 4771)
author: Léo JAILLET
date: 2024-11-10
name: failed_login
logsource:
  category: authentication
  product: windows
detection:
  event_id:
    EventID:
      - 4625
      - 4771
  condition: event_id
level: medium

--- 

title: Multiple failed logon attemps
description: Detects accounts with more than 5 failed logon attempts (EventID 4625 or 4771) in the last hour.
correlation: 
  type: event_count
  rules: 
    - failed_login
  timespan: 1h
  group-by: Account_Name
  condition:
    gt: 5
falsepositives:
  - Users who repeatedly fail to log in due to incorrect credentials
level: medium

```

# Explication

La règle est divisée en 2:
- la 1e partie récupère tous les échecs de connection (compte classique et Kerberos)
- la 2e partie regarde s'il y a eu plus de 5 échecs durant la dernière heure sur un même compte utilisateur. 