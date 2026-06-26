# LogSonar

**LogSonar** est un outil de surveillance de sécurité léger, stylé et intelligent, conçu pour analyser les logs de vos conteneurs Docker en temps réel. 

C'est l'alternative parfaite aux monstres de la sécurité comme Wazuh ou ELK stack lorsque vous avez des ressources limitées. LogSonar se concentre sur l'essentiel : détecter les intrusions, vous alerter immédiatement, et générer des rapports explicatifs compréhensibles par tous, sans jamais envoyer vos données à une IA externe.

## Fonctionnalités

- **Temps réel (WebSocket) :** Flux de logs style "terminal" ultra-rapide, avec défilement fluide et bouton Pause/Reprendre.
- **Détection d'attaques :** Reconnaissance instantanée de 7 types de menaces (SQL Injection, XSS, Path Traversal, Scanners...).
- **Interface Web Moderne :** Design épuré noir et blanc, avec mode Sombre/Clair configurable par l'utilisateur.
- **Alertes Email :** Notification immédiate dans votre boîte mail dès qu'une attaque critique est repérée.
- **Rapports Pédagogiques :** Génération quotidienne (à 00h00) de rapports HTML détaillés qui expliquent l'attaque, son risque et comment la corriger.
- **100% Dockerisé :** Déploiement en une seule commande.
- **Multi-plateforme :** Fonctionne automatiquement sur Windows (Docker Desktop) pour le développement, et sur Linux (VPS/Ubuntu) pour la production.
- **Sécurité isolée :** LogSonar s'exécute en dehors de vos projets, il ne peut pas être compromis par une faille de votre application web.

---

## Installation et Démarrage

### Prérequis
- [Docker](https://docs.docker.com/get-docker/)
- [Docker Compose](https://docs.docker.com/compose/install/)

### 1. Cloner le projet
```bash
git clone https://votre-repo-git.com/votre-user/logsonar.git
cd logsonar
```

### 2. Lancer l'application
```bash
docker-compose up -d --build
```

### 3. Accéder à l'interface
Ouvrez votre navigateur et rendez-vous sur : **http://localhost:8081**

*(Note : Si vous êtes sur un serveur distant, remplacez `localhost` par l'adresse IP de votre serveur).*

---

## Comment ça marche sous le capot ?

LogSonar utilise une architecture asynchrone moderne pour rester extrêmement léger :

1. **Lecture (Docker SDK) :** Au démarrage, LogSonar se connecte au démon Docker de l'hôte (via un socket Unix sur Linux, ou via TCP sur Windows). Il liste les conteneurs actifs (en s'excluant lui-même pour éviter une boucle infinie) et écoute leurs flux de logs en temps réel.
2. **Analyse (Moteur Regex) :** Chaque ligne de log est décodée, nettoyée des caractères de couleur ANSI, puis passée dans un moteur de regex. Il extrait l'IP, la méthode HTTP, le chemin, le code retour, et cherche des signatures d'attaques connues.
3. **Temps réel (FastAPI & WebSockets) :** Si l'événement est une attaque, il est sauvégardé en base de données et une alerte mail est préparée en arrière-plan. Le log est ensuite poussé instantanément au navigateur via un canal WebSocket ouvert.
4. **Persistance (SQLite) :** Toutes les métriques et les attaques sont stockées dans une base SQLite locale, liée au système de fichiers hôte pour survivre aux redémarrages de conteneurs.
5. **Rapports (Moteur de Templates) :** Un planificateur interne vérifie l'heure toutes les 30 secondes. À minuit pile, il interroge la base de données, récupère les attaques de la journée, et génère un fichier HTML formaté avec des explications techniques vulgarisées.

---

## Structure du Projet

```text
logsonar/
│
├── docker-compose.yml       # Configuration Docker (Ports, Volumes, Environnement)
├── Dockerfile               # Image Python légère (Alpine)
├── requirements.txt         # Dépendances Python (FastAPI, aiosqlite, docker)
├── README.md                # Ce fichier
│
├── app/                     # Dossier applicatif (Backend Python)
│   ├── main.py              # Point d'entrée : API REST, WebSocket, Routeur, Moteur d'analyse
│   ├── db.py                # Gestionnaire de base de données SQLite (Création, Lecture, Écriture)
│   ├── mailer.py            # Moteur d'envoi d'emails (SMTP asynchrone)
│   └── reporter.py          # Générateur de rapports HTML pédagogiques
│
├── static/                  # Dossier public (Frontend)
│   └── index.html           # Interface utilisateur complète (HTML, TailwindCSS, JS WebSocket)
│
└── data/                    # Généré automatiquement au premier lancement (Volume Docker)
    ├── logsonar.db          # Base de données SQLite
    └── reports/             # Dossier contenant les rapports HTML quotidiens
        └── rapport_2023-10-27.html
```

---

## Signatures de Détection

LogSonar analyse les requêtes **peu importe le code de retour** (200, 404, 500...) car une attaque réussie (200 OK) est plus critique qu'une attaque bloquée (403 Forbidden).

Il détecte actuellement :
1. **Tentative d'Injection SQL :** `UNION SELECT`, `OR 1=1`, `DROP TABLE`...
2. **Tentative de Cross-Site Scripting (XSS) :** `<script>`, `javascript:`, `onerror=`...
3. **Tentative de Path Traversal :** `../../../etc/passwd`...
4. **Scan de vulnérabilités (Bots) :** Détection des User-Agents de `Sqlmap`, `Nmap`, `Nikto`...
5. **Recherche de fichiers sensibles :** Accès à `/.env`, `/wp-admin`, `/.git`...
6. **Alertes internes (Django/Python) :** Détection des `SuspiciousOperation` (nécessite le middleware côté app).
7. **Tentatives de falsification (CSRF) :** Échecs de validation de token CSRF.

---

## Configuration via l'interface

Une fois connecté à `http://localhost:8081`, cliquez sur **Paramètres** dans le menu latéral :

1. **Email destinataire :** L'adresse qui recevra les alertes critiques instantanées.
2. **Configuration SMTP :** Les identifiants de votre serveur d'envoi (ex: Gmail, OVH, Sendgrid).
   * *Note pour Gmail :* Vous devez générer un "Mot de passe d'application" dans votre compte Google (ne pas utiliser votre mot de passe classique).
3. Cliquez sur **Sauvegarder** puis sur **Envoyer un test** pour vérifier que la connexion fonctionne.

---

## Notes Spécifiques & Bonnes Pratiques

### Les requêtes POST (Le point aveugle des logs)
Par défaut, les serveurs web (Nginx/Apache) ne日志ent pas le corps (body) des requêtes POST pour des raisons de performance et de confidentialité. LogSonar ne verra donc pas une injection SQL faite depuis un formulaire de connexion classique. 
*Solution :* Pour surveiller les POST, il est recommandé d'ajouter un petit Middleware dans votre application (ex: TikiPay) qui écrit un log spécifique `LOGSONAR_POST_ATTACK` si un payload dangereux est détecté dans la requête. LogSonar interceptera ce signal.

### Développement sur Windows (Docker Desktop)
Pour que la détection automatique de Docker fonctionne sur Windows, assurez-vous que l'option **"Expose daemon on tcp://localhost:2375 without TLS"** est cochée dans les paramètres de Docker Desktop. LogSonar gérera la bascule tout seul.

### Environnement de Production (Linux)
Sur un serveur Ubuntu classique, aucune configuration supplémentaire n'est nécessaire. Le socket Docker standard (`/var/run/docker.sock`) sera utilisé automatiquement.

---

## Améliorations Futures (Roadmap)

- [ ] Rendre les filtres de dates fonctionnels dans le terminal Live.
- [ ] Système de "Buffer" : Empiler les logs en mémoire lors de la Pause et les rejouer au moment de Reprendre.
- [ ] Tableau de bord avec des graphiques (Top 5 des IP attaquantes, répartition des types d'attaques).
- [ ] Gestion avancée des requêtes POST via intégration directe d'un agent léger.

---

## Licence

Ce projet est open-source et libre d'utilisation. 
Créé avec patience et beaucoup de café.