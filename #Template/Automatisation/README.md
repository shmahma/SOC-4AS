
# Extraction d'Alertes Critiques ou Élevées de Splunk

  

## Description

  

Ce script en Python se connecte à un serveur Splunk et extrait les alertes ayant un impact "critique" ou "élevé" au cours des dernières 24 heures. Les résultats sont récupérés en format JSON et un modèle de notification en Markdown est généré pour afficher chaque alerte, avec son titre, sa description et son horodatage.

  

## Prérequis

  

Avant d'exécuter ce script, assurez-vous que les bibliothèques suivantes sont installées :

  

-  `splunk-sdk`

-  `splunklib`

-  `jinja2`

  

Ou utilisé le fichier requirements.txt:

```bash
pip install -r requirements.txt
``` 

  

## Utilisation

  

### Connexion au serveur Splunk

  

Le script utilise les informations de connexion suivantes pour se connecter au serveur Splunk :

  

-  `host` : adresse IP ou nom d'hôte du serveur Splunk

-  `port` : port par défaut de l'API Splunk (8089)

-  `username` : nom d'utilisateur de votre compte Splunk

-  `password` : mot de passe de votre compte Splunk

  

Assurez-vous de modifier ces valeurs directement dans le script si nécessaire.

  

### Requête Splunk

  

Le script exécute une requête de recherche pour récupérer les alertes ayant un impact "critique" ou "élevé" au cours des dernières 24 heures. La requête est la suivante :

  

```bash 
search_query = 'search index=alerts event.event_title="*" (event.impact="high" OR event.urgency="high") earliest=-24h'
```

  

### Extraction des informations

  

Pour chaque alerte, le script :

  

- Convertit le champ `_raw` de chaque résultat en JSON afin de récupérer des informations supplémentaires, notamment la description.

- Utilise le champ `event.originQuery.description` pour extraire la description de chaque alerte.

  

### Affichage des résultats

  

Un modèle Jinja2 est utilisé pour formater les résultats en Markdown. Les informations suivantes sont affichées pour chaque alerte :

  

- Le titre de l'alerte et son niveau d'impact

- La description de l'alerte

- L'horodatage de l'alerte

  

### Déconnexion de Splunk

  

Une fois les données récupérées, le script se déconnecte du serveur Splunk.
