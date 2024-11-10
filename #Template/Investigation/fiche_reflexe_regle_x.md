1. Alerte : Détection d’Injections de Code
Requête Splunk :
index=windows EventCode=10
| stats count, values(User) AS Users, values(ProcessName) AS ProcessNames BY Host
| table Host, count, Users, ProcessNames

Pivot d’investigation :
Vérifier si l'exécution des processus a été réalisée par un administrateur en dehors des horaires de travail habituels.
Croiser l'origine de la connexion avec les adresses IP connues de l'utilisateur.
Vérifier s'il y a des tentatives d'accès échouées qui pourraient suggérer une activité suspecte.
Identifier des processus inhabituels qui ne sont pas typiques pour le contexte système.

2. Alerte : Détection de Changements dans les Clés de Registre de Persistance
Requête Splunk :
index=windows EventCode=13 TargetObject="*\Software\Microsoft\Windows\CurrentVersion\Run*"
| stats count, values(User) AS Users, values(RegistryKey) AS RegistryKeys BY Computer
| table Computer, count, Users, RegistryKeys

Pivot d’investigation :
Vérifier si les modifications de la clé de registre ont été réalisées en dehors des heures habituelles par des comptes privilégiés.
Déterminer si la modification provient d'une connexion habituelle.
Rechercher des traces de persistance d'une possible attaque sur le système.

3. Alerte : Accès Anormal aux Fichiers Système
Requête Splunk :
index=windows EventCode=7 (TargetFilename="*\Windows\System32\*" OR TargetFilename="*\Windows\SysWOW64\*")
| stats count, values(User) AS Users, values(FileName) AS FileNames BY Host
| table Host, count, Users, FileNames

Pivot d’investigation :
Vérifier si l'accès a été réalisé par des utilisateurs standards ou des comptes administratifs.
Analyser si ces fichiers ont été accédés à partir de connexions légitimes ou non.
Rechercher une énumération système potentielle qui pourrait révéler des reconnaissances préliminaires.

4. Alerte : Surveillance des Utilisations Anormales de CertUtil
Requête Splunk :
index=windows EventCode=1 Image="*\certutil.exe" (CommandLine="* -urlcache*" OR CommandLine="* -split*")
| stats count, values(User) AS Users, values(CommandLine) AS CommandLines BY Host
| table Host, count, Users, CommandLines

Pivot d’investigation :
Examiner l'origine des commandes exécutées, notamment les connexions provenant de serveurs inhabituels.
Vérifier s'il existe des tentatives de C&C (command & control) associées à ces commandes.
Vérifier les échecs de connexion et les activités anormales de comptes non privilégiés.

5. Alerte : Détection de l'Exécution de Fichiers depuis des Répertoires Temp
Requête Splunk :
index=test EventCode=4688 New_Process_Name="*\\Temp\\*.exe"
| stats count, values(Creator_Process_Name) AS Creator_Process_Name BY New_Process_Name
| table New_Process_Name, count, Creator_Process_Name

Pivot d’investigation :
Déterminer si les fichiers exécutés proviennent de comptes administratifs ou standards.
Identifier si ces fichiers sont connus ou s'ils représentent une nouvelle menace.
Vérifier s'ils ont été exécutés suite à une connexion anormale ou en dehors des horaires habituels.
