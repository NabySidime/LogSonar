# LogSonar

**LogSonar** est un outil de surveillance de sécurité léger, stylé et intelligent, conçu pour analyser les logs de vos conteneurs Docker en temps réel.

C'est l'alternative parfaite aux monstres de la sécurité comme Wazuh ou ELK stack lorsque vous avez des ressources limitées. LogSonar se concentre sur l'essentiel : détecter les intrusions, vous alerter immédiatement, et générer des rapports explicatifs compréhensibles par tous, sans jamais envoyer vos données à une IA externe.

## Fonctionnalités

- **Authentification sécurisée** : Système à 2 facteurs (2FA) avec OTP par email, rôles utilisateur (superuser/user).
- **Contrôle d'accès (RBAC)** : 2 utilisateurs max, 1 superuser. L'utilisateur standard ne peut que consulter le dashboard, le live et les rapports.
- **Temps réel (WebSocket)** : Flux de logs style "terminal" ultra-rapide, avec défilement fluide et bouton Pause/Reprendre.
- **Détection d'attaques** : Reconnaissance instantanée de **17 types de menaces** (15 signatures regex + 2 détections comportementales).
- **Interface Web Moderne** : Design épuré noir et blanc, responsive, avec mode Sombre/Clair configurable.
- **Dashboard analytique** : Graphiques temps réel (tendance 7j, volume horaire, répartition par type, top IPs attaquantes, feed récent).
- **Alertes Email** : Notification immédiate dans votre boîte mail dès qu'une attaque critique réussie est repérée (code 2xx).
- **Rapports Pédagogiques** : Génération quotidienne (à 00h00) de rapports HTML détaillés qui expliquent l'attaque, son risque et comment la corriger.
- **Scan de dépendances** : Analyse des paquets Python prioritaires dans vos conteneurs, avec comparaison des versions via PyPI.
- **100% Dockerisé** : Déploiement en une seule commande.
- **Multi-plateforme** : Fonctionne automatiquement sur Windows (Docker Desktop) pour le développement, et sur Linux (VPS/Ubuntu) pour la production.
- **Sécurité isolée** : LogSonar s'exécute en dehors de vos projets, il ne peut pas être compromis par une faille de votre application web.
- **Purge automatique** : Les événements de plus de 60 jours sont supprimés automatiquement.

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
Ouvrez votre navigateur et rendez-vous sur : **http://localhost**

*(Note : Si vous êtes sur un serveur distant, remplacez `localhost` par l'adresse IP de votre serveur).*

### 4. Configuration initiale (premier lancement)

Lors du premier lancement, LogSonar vous présente un formulaire de création de compte superuser. Si vous skippez cette étape, un compte par défaut est créé automatiquement :

- **Username** : `admin`
- **Password** : `admin123`
- **Email** : `admin@localhost`

> **⚠️ Important** : Changez immédiatement ce mot de passe via la page **Utilisateurs** après votre première connexion. Si le SMTP n'est pas encore configuré, le code OTP s'affichera dans les logs Docker. Consultez la section [Configuration SMTP](#configuration-smtp) ci-dessous.

---

## Authentification et Sécurité

### Système de connexion

LogSonar utilise une authentification à 2 facteurs (2FA) :

1. **Étape 1** : Nom d'utilisateur + mot de passe
2. **Étape 2** : Code OTP à 6 chiffres envoyé par email (ou affiché dans les logs si SMTP non configuré)

Le token JWT est stocké côté client (`localStorage`) et transmis via le header `Authorization: Bearer`. La clé JWT est persistée dans `data/.jwt_secret` pour survivre aux redémarrages de conteneur.

### Gestion des utilisateurs

| Rôle | Permissions | Limite |
|------|-------------|--------|
| **Superuser** | Tout (dashboard, live, rapports, paramètres, gestion users, scan deps) | **1 max** |
| **User** | Lecture uniquement (dashboard, live, rapports en lecture seule) | **1 max** |

**Contraintes système :**
- Maximum **2 utilisateurs actifs** au total
- Maximum **1 superuser** (impossible d'en créer un second)
- La suppression d'un utilisateur le désactive (`is_active = 0`), libérant sa place
- L'utilisateur standard **ne peut pas** télécharger ni supprimer les rapports
- Seul le superuser peut configurer le SMTP, générer des rapports manuellement, scanner les dépendances et gérer les utilisateurs

### Créer un utilisateur standard

Deux méthodes :

**Via l'interface** : Connectez-vous en superuser → **Utilisateurs** → bouton **Ajouter**

**Via l'API** :
```bash
# 1. Récupérer le token JWT (remplacez par vos identifiants)
TOKEN="votre_token_jwt"

# 2. Créer l'utilisateur
curl -X POST http://localhost/api/auth/create-user \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=viewer" \
  -d "password=monMotDePasse" \
  -d "email=viewer@domaine.com" \
  -d "role=user"
```

---

## Configuration SMTP

Pour activer l'envoi des OTP par email et les alertes de sécurité, configurez le SMTP :

1. Connectez-vous en tant que **superuser**
2. Allez dans **Paramètres** → **Configuration SMTP**
3. Renseignez :
   - **Email destinataire** : l'adresse qui recevra les alertes d'attaques
   - **Hôte SMTP** : ex. `smtp.gmail.com`
   - **Port** : ex. `587`
   - **Utilisateur SMTP** : votre adresse email
   - **Mot de passe SMTP** : mot de passe d'application (pas votre mot de passe principal)

4. Cliquez sur **"Envoyer un test"** pour vérifier
5. Cliquez sur **"Sauvegarder"**

> **Note Gmail** : Vous devez générer un "Mot de passe d'application" dans votre compte Google (Sécurité → Vérification en 2 étapes → Mots de passe d'application).
> 
> **Sécurité** : Le mot de passe SMTP est chiffré en AES-128 (Fernet) avant d'être stocké en base de données. Il n'est jamais renvoyé en clair par l'API (masqué par `********`).

---

## Déploiement en Production

### 1. Variables d'environnement

Créez un fichier `.env` à la racine du projet :

```env
# Sécurité (fortement recommandé en production)
LOGSONAR_JWT_SECRET=votre-cle-super-secrete-32-caracteres-min
```

> **⚠️ CRITIQUE** : Si `LOGSONAR_JWT_SECRET` n'est pas défini, LogSonar génère une clé et la persiste dans `data/.jwt_secret`. Cela fonctionne, mais une clé définie via variable d'environnement est plus sûre (pas de clé sur le disque). Générez-en une avec : `openssl rand -base64 32`

### 2. `docker-compose.yml` — Exposer uniquement sur localhost

```yaml
version: "3.8"
services:
  logsonar:
    build: .
    container_name: logsonar-app
    restart: unless-stopped
    ports:
      - "127.0.0.1:80:80"  # ← LOCALHOST UNIQUEMENT (reverse proxy devant)
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./data:/app/data
    environment:
      - LOGSONAR_JWT_SECRET=${LOGSONAR_JWT_SECRET}
```

> **Jamais** d'exposition directe sur `0.0.0.0:80` en production. Utilisez toujours un reverse proxy (Nginx, Traefik, Caddy).

### 3. Reverse Proxy (Nginx)

Exemple de configuration Nginx :

```nginx
server {
    listen 443 ssl http2;
    server_name logsonar.votre-domaine.com;

    ssl_certificate /etc/letsencrypt/live/votre-domaine.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/votre-domaine.com/privkey.pem;

    client_max_body_size 10M;

    location / {
        proxy_pass http://127.0.0.1:80;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeouts pour WebSocket (les logs sont push en continu)
        proxy_read_timeout 86400;
        proxy_send_timeout 86400;
    }
}

# Redirection HTTP → HTTPS
server {
    listen 80;
    server_name logsonar.votre-domaine.com;
    return 301 https://$server_name$request_uri;
}
```

### 4. Sécurité Docker

#### Dockerfile (vérifier les permissions)

```dockerfile
FROM python:3.11-alpine

WORKDIR /app

# Créer un utilisateur non-root
RUN adduser -D -u 1000 logsonar

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py db.py mailer.py reporter.py ./
COPY static/ ./static/

# Permissions restrictives sur les fichiers sensibles
RUN mkdir -p /app/data/reports && chown -R logsonar:logsonar /app/data
RUN chmod 600 /app/data/.secret_key 2>/dev/null || true
RUN chmod 600 /app/data/.jwt_secret 2>/dev/null || true

USER logsonar

EXPOSE 80

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "80"]
```

### 5. Checklist de sécurité production

- [ ] `LOGSONAR_JWT_SECRET` défini dans `.env` (pas de clé auto-générée sur disque)
- [ ] Port exposé uniquement sur `127.0.0.1` (pas `0.0.0.0`)
- [ ] Reverse proxy HTTPS (Nginx/Traefik/Caddy) configuré
- [ ] Certificat SSL valide (Let's Encrypt)
- [ ] Firewall : port 80 bloqué depuis l'extérieur
- [ ] Docker socket en lecture seule (`:ro`)
- [ ] Conteneur tourne avec un utilisateur non-root
- [ ] Clé Fernet (`data/.secret_key`) avec permissions `600`
- [ ] Clé JWT (`data/.jwt_secret`) avec permissions `600` (si pas de var d'env)
- [ ] Mot de passe admin par défaut changé
- [ ] SMTP configuré (OTP par email, pas dans les logs)
- [ ] Logs Docker monitorés (`docker logs -f logsonar-app`)
- [ ] Backup régulier de `data/logsonar.db`

### 6. Mise à jour en production

```bash
# Pull des changements
git pull origin main

# Rebuild et redémarrage (les données persistent dans ./data)
docker-compose down
docker-compose up -d --build

# Vérifier les logs
docker logs -f logsonar-app
```

---

## Comment ça marche sous le capot ?

LogSonar utilise une architecture asynchrone moderne pour rester extrêmement léger :

1. **Lecture (Docker SDK)** : Au démarrage, LogSonar se connecte au démon Docker de l'hôte (via un socket Unix sur Linux, ou via TCP sur Windows). Il liste les conteneurs actifs (en s'excluant lui-même pour éviter une boucle infinie) et écoute leurs flux de logs en temps réel. Un superviseur détecte automatiquement les nouveaux conteneurs et les arrêts.
2. **Analyse (Moteur Regex)** : Chaque ligne de log est décodée, nettoyée des caractères de couleur ANSI, puis passée dans un moteur de regex. Il extrait l'IP, la méthode HTTP, le chemin, le code retour, et cherche des signatures d'attaques connues. Les payloads subissent une double normalisation (décodage URL + NFKC) pour contrer les encodages multiples.
3. **Détection comportementale** : Détection de bruteforce (même IP + même path, >10 req/min) et flood (>30 req/30s par IP) via des fenêtres glissantes en mémoire.
4. **Authentification (JWT + OTP)** : Chaque session est sécurisée par un token JWT transmis via le header `Authorization: Bearer`. La connexion requiert un code OTP à usage unique envoyé par email (ou affiché en console en mode dev).
5. **Temps réel (FastAPI & WebSockets)** : Si l'événement est une attaque, il est sauvegardé en base de données et une alerte mail est préparée en arrière-plan (avec rate-limiting de 60s par IP/type). Le log est poussé instantanément au navigateur via un canal WebSocket authentifié par token.
6. **Persistance (SQLite)** : Toutes les métriques, attaques, utilisateurs et paramètres sont stockés dans une base SQLite locale (mode WAL pour les performances concurrentes), liée au système de fichiers hôte pour survivre aux redémarrages. Les événements de plus de 60 jours sont purgés automatiquement.
7. **Rapports (Moteur de Templates)** : Un planificateur interne vérifie l'heure toutes les 30 secondes. À minuit pile, il interroge la base de données, récupère les attaques de la journée, et génère un fichier HTML formaté avec des explications techniques vulgarisées.
8. **Scan de dépendances** : Exécute `pip list --format=json` dans chaque conteneur cible, filtre les paquets Python prioritaires, et interroge l'API PyPI pour comparer les versions installées avec les dernières disponibles.

---

## Structure du Projet

```text
logsonar/
│
├── docker-compose.yml       # Configuration Docker (Ports, Volumes, Environnement)
├── Dockerfile               # Image Python légère (Alpine)
├── requirements.txt         # Dépendances Python
├── .env                     # Variables d'environnement (LOGSONAR_JWT_SECRET)
│
├── main.py                  # Point d'entrée FastAPI + Auth JWT + Routes + Moteur d'analyse + Docker SDK
├── db.py                    # SQLite (WAL) + Users + OTP + Settings + Chiffrement Fernet
├── mailer.py                # SMTP asynchrone + Envoi OTP et alertes
├── reporter.py              # Générateur de rapports HTML pédagogiques
│
├── static/                  # Dossier public (Frontend)
│   ├── index.html           # Interface principale (SPA : Dashboard, Live, Rapports, Users, Settings)
│   └── login.html           # Page de connexion (Setup initial + 2FA OTP)
│
└── data/                    # Volume Docker persistant
    ├── logsonar.db          # Base de données SQLite
    ├── .secret_key          # Clé de chiffrement Fernet pour le mot de passe SMTP (perms 600)
    ├── .jwt_secret          # Clé de signature JWT auto-générée (perms 600)
    └── reports/             # Rapports HTML quotidiens
        └── rapport_2025-01-15.html
```

---

## Signatures de Détection

LogSonar analyse les requêtes **peu importe le code de retour** (200, 404, 500...) car une attaque réussie (200 OK) est plus critique qu'une attaque bloquée (403 Forbidden).

Il détecte actuellement **17 types de menaces** :

### Signatures Regex (15 types)
1. **Tentative d'Injection SQL** : `UNION SELECT`, `OR 1=1`, `DROP TABLE`, `xp_cmdshell`, `information_schema`, `pg_sleep`, `benchmark()`...
2. **Tentative de Cross-Site Scripting (XSS)** : `<script>`, `javascript:`, `onerror=`, `alert(`, `document.cookie`, `<svg onload>`, `data:text/html`...
3. **Tentative de Path Traversal** : `../../../etc/passwd`, `%2e%2e`, double encodage, `%c0%ae`...
4. **Tentative d'Injection de Commande** : `; ls`, `| cat /etc`, `$(whoami)`, `` `cmd` ``, `system()`, `__import__`...
5. **Tentative Log4Shell (Log4J)** : `${jndi:ldap://...}`, `${lower:jndi}`, `${::-j}`...
6. **Tentative de SSRF** : `url=http://169.254.169.254`, `redirect=http://127.0.0.1`, `file:///etc/`, `metadata.google.internal`...
7. **Tentative XXE (Injection d'Entité XML)** : `<!DOCTYPE`, `<!ENTITY`, `SYSTEM "file://"`...
8. **Tentative de Redirection Ouverte** : `redirect=https://evil.com`, `next=http://phishing.com`...
9. **Scan de vulnérabilités (Bots)** : `Sqlmap`, `Nmap`, `Nikto`, `Nuclei`, `BurpSuite`, `Metasploit`, `ZAP`, `Shodan`...
10. **Recherche de fichiers sensibles** : `/.env`, `/wp-admin`, `/.git/HEAD`, `.htaccess`, `backup.sql`, `/actuator/`, `/swagger-ui`...
11. **Alertes internes de l'application** : `SuspiciousOperation`, `LOGSONAR_POST_ATTACK`, `Invalid HTTP_HOST header`...
12. **Tentatives de falsification (CSRF)** : Échecs de validation de token CSRF.
13. **Tentative d'Injection de Template (SSTI)** : `{{7*7}}`, `${7*7}`, `<%= ... %>`, `{{config}}`...
14. **Tentative de Désérialisation Malveillante** : `rO0AB` (Java), `O:1:` (PHP), `__reduce__` (Python pickle)...
15. **Recherche d'informations** : `id_rsa`, `.aws/credentials`, `config.php`, `database.yml`, `phpmyadmin`...

### Détections Comportementales (2 types)
16. **Bruteforce** : Plus de 10 requêtes identiques (même IP + même path) en 60 secondes.
17. **Flood** : Plus de 30 requêtes toutes cibles confondues depuis une même IP en 30 secondes.

---

## Notes Spécifiques & Bonnes Pratiques

### Les requêtes POST (Le point aveugle des logs)
Par défaut, les serveurs web (Nginx/Apache) ne loguent pas le corps (body) des requêtes POST pour des raisons de performance et de confidentialité. LogSonar ne verra donc pas une injection SQL faite depuis un formulaire de connexion classique.
*Solution :* Pour surveiller les POST, il est recommandé d'ajouter un petit Middleware dans votre application qui écrit un log spécifique `LOGSONAR_POST_ATTACK` si un payload dangereux est détecté dans la requête. LogSonar interceptera ce signal.

### Scan de dépendances
Le scan nécessite que vos conteneurs aient **pip** d'installé et un accès **internet** (pour interroger PyPI). Seuls les 20 paquets les plus critiques sont vérifiés (Django, Flask, FastAPI, requests, cryptography, etc.). Les autres sont ignorés pour éviter de surcharger l'interface et l'API PyPI.

### Alertes Email (Rate-limiting)
Pour éviter de saturer votre boîte mail lors d'une attaque massive, LogSonar n'envoie une alerte que pour les attaques **réussies** (code HTTP 2xx) et applique un cooldown de 60 secondes par combinaison IP + type d'attaque.

### Développement sur Windows (Docker Desktop)
Pour que la détection automatique de Docker fonctionne sur Windows, assurez-vous que l'option **"Expose daemon on tcp://localhost:2375 without TLS"** est cochée dans les paramètres de Docker Desktop. LogSonar gérera la bascule tout seul.

### Environnement de Production (Linux)
Sur un serveur Ubuntu classique, aucune configuration supplémentaire n'est nécessaire. Le socket Docker standard (`/var/run/docker.sock`) sera utilisé automatiquement.

### OTP sans SMTP configuré
Si vous n'avez pas encore configuré le SMTP, le code OTP s'affiche dans les logs Docker :
```bash
docker logs -f logsonar-app
```
Recherchez la ligne :
```
LogSonar: SMTP non configuré — CODE OTP pour [username]
  Code: 482917
```

---

## API Endpoints

### Authentification
| Méthode | Endpoint | Description | Auth |
|---------|----------|-------------|------|
| POST | `/api/auth/check-setup` | Vérifie si le setup initial est nécessaire | ❌ |
| POST | `/api/auth/setup` | Crée le premier superuser | ❌ (si 0 user) |
| POST | `/api/auth/login` | Étape 1 : username/password → envoi OTP | ❌ |
| POST | `/api/auth/verify-otp` | Étape 2 : OTP → JWT token | ❌ |
| POST | `/api/auth/logout` | Déconnexion | ✅ |
| GET | `/api/auth/me` | Infos utilisateur connecté | ✅ |
| POST | `/api/auth/create-user` | Créer un user (superuser only) | ✅ superuser |

### Utilisateurs (superuser only)
| Méthode | Endpoint | Description | Auth |
|---------|----------|-------------|------|
| GET | `/api/users` | Liste les utilisateurs actifs | ✅ superuser |
| POST | `/api/users/update` | Met à jour un utilisateur (email, password) | ✅ superuser |
| DELETE | `/api/users/{user_id}` | Supprime (désactive) un utilisateur | ✅ superuser |

### Application
| Méthode | Endpoint | Description | Auth | Rôle |
|---------|----------|-------------|------|------|
| GET | `/api/settings` | Paramètres SMTP | ✅ | superuser |
| POST | `/api/settings` | Sauvegarder paramètres | ✅ | superuser |
| POST | `/api/settings/test` | Test email | ✅ | superuser |
| GET | `/api/reports` | Liste rapports | ✅ | all |
| GET | `/api/reports/view/{filename}` | Voir un rapport (HTML) | ✅ | all |
| GET | `/api/reports/generate` | Générer rapport manuellement | ✅ | superuser |
| DELETE | `/api/reports/{filename}` | Supprimer rapport | ✅ | superuser |
| GET | `/api/stats` | Stats du jour | ✅ | all |
| GET | `/api/dashboard` | Données dashboard (KPIs, graphiques) | ✅ | all |
| GET | `/api/ws-token` | Token pour WebSocket | ✅ | all |
| GET | `/api/containers/deps` | Scanner dépendances Python | ✅ | superuser |

### WebSocket
| Protocole | Endpoint | Description |
|-----------|----------|-------------|
| WS | `/ws/logs?token=XXX` | Flux de logs temps réel |

---

## Dépendances Python (`requirements.txt`)

```
fastapi
uvicorn[standard]
aiosqlite
docker
bcrypt
pyjwt
cryptography
```

---

## Améliorations Futures (Roadmap)

- [x] Système d'authentification avec 2FA OTP par email
- [x] Contrôle d'accès RBAC (superuser/user)
- [x] Dashboard analytique avec graphiques (Chart.js)
- [x] Détection comportementale (bruteforce, flood)
- [x] Scan des dépendances Python des conteneurs
- [x] Purge automatique des événements (60 jours)
- [x] Chiffrement du mot de passe SMTP (Fernet)
- [x] Persistance de la clé JWT entre les redémarrages
- [ ] Rendre les filtres de dates fonctionnels dans le terminal Live
- [ ] Système de "Buffer" : Empiler les logs en mémoire lors de la Pause et les rejouer
- [ ] Gestion avancée des requêtes POST via intégration directe d'un agent léger
- [ ] Export CSV/JSON des événements
- [ ] Blacklist IP automatique
- [ ] Notifications Slack/Discord/Webhook

---

## Licence

Ce projet est open-source et libre d'utilisation.
Créé avec patience, beaucoup de café, et un zeste de paranoïa sécuritaire.
