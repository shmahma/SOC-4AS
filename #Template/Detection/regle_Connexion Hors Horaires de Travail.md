# Description

Cette règle sera levée en cas de connexion d'un utilisateur en dehors des heures de travail définies (6 AM à 8 PM).

# Criticité : **LOW**

# Outils

Windows Event Logs

# Règle SPL

```
index="connectix"  sourcetype="WinEventLog" EventCode=4624 
| eval hour=strftime(_time, "%H") 
| where hour < 6 OR hour >=20
```

# Règle SIGMA

```
title: Détection de la connexion d'un utilisateur en dehors des heures normales de travail
id: 7dac54cc-7d75-4e01-a755-0995e5505f69
status: experimental
description: Cette règle détecte les connexions d'utilisateurs en dehors des heures normales de travail (6h00 à 20h00).
author: Inès OUESALTI
date: 2024-11-10
tags:
    - attack.t1071.001
    - attack.persistence
    - attack.execution
logsource:
    product: windows
    category: authentication
detection:
    selection:
        EventID: 4624  
    condition: selection
    timeframe:
        start: 00:00
        end: 06:00  # Heures non autorisées avant 6h00
        or:
        start: 20:00  # Après 20h00
        end: 23:59
falsepositives:
    - Connexion légitime effectuée après les heures normales de travail par des administrateurs ou utilisateurs ayant des horaires spéciaux.
level: low

```

# Explication
Cette règle détecte les événements de connexion (EventCode 4624) survenant en dehors des heures normales de travail, c'est-à-dire avant 6h00 et après 20h00. Les horaires de connexion anormale peuvent indiquer une activité suspecte ou non autorisée. L'heure est calculée à partir du timestamp du log, et une évaluation est effectuée pour vérifier si elle tombe dans les plages horaires spécifiées.
