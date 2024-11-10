# Description

Cette règle sera levée en cas de requête sur Kerberos venant de l'extérieur ou d'un port privilégié, ce qui serait un signe assez évident d'une tentative d'attaqur sur Kerberos. 
Note: cette règle Sigma ne peut pas être compilée à cause du plugin Splunk de Sigma qui ne supporte pas les regex.

# Criticité : **HIGH**


# Règle SPL

```
index="connectix" EventCode=4768
(where NOT match(Client_Address, "(::ffff:)?192\.168\.\d{1,3}\.\d{1,3}")
OR (Client_Port > 0 AND Client_Port < 1024))
```

# Règle SIGMA

```
title: Suspicious Kerberos Authentication (EventID 4768) from Unusual IP or Port
id: 5f3c1b67-77ea-4c93-bb6e-bcb489adf91b
description: Detects Kerberos authentication (EventID 4768) with client addresses outside the internal subnet or using ports below 1024.
author: Léo JAILLET
date: 2024-11-10
logsource:
  category: authentication
  product: windows
detection:s
  event_id:
    EventID: 4768
  local_address:
    Client_Address|re: '(::ffff:)?192\.168\.\d{1,3}\.\d{1,3}'
  low_port:
    Client_Port|gt: 0
    Client_Port|lte: 1024
  condition: event_id and ((not local_address) or low_port)
falsepositives:
  - Legitimate external access to Kerberos services
level: high


```

# Explication

Dans les requêtes faites à Kerberos, on regarde si:
- le port est <= 1024 (ports réservés)
- si l'IP n'appartient pas au réseau local de l'entreprise. Il faut aussi s'assurer que l'IP n'est pas une IPv4 mappé en IPv6. 
