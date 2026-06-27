# LogSonar

**LogSonar** est un outil de surveillance de sécurité léger, stylé et intelligent, conçu pour analyser les logs de vos conteneurs Docker en temps réel. 

C'est l'alternative parfaite aux monstres de la sécurité comme Wazuh ou ELK stack lorsque vous avez des ressources limitées. LogSonar se concentre sur l'essentiel : détecter les intrusions, vous alerter immédiatement, et générer des rapports explicatifs compréhensibles par tous, sans jamais envoyer vos données à une IA externe.

## Fonctionnalités

- **Authentification sécurisée** : Système à 2 facteurs (2FA) avec OTP par email, rôles utilisateur (superuser/user).
- **Contrôle d'accès (RBAC)** : 2 utilisateurs max, 1 superuser. L'utilisateur standard ne peut que consulter les rapports.
- **Temps réel (WebSocket)** : Flux de logs style "terminal" ultra-rapide, avec défilement fluide et bouton Pause/Reprendre.
- **Détection d'attaques** : Reconnaissance instantanée de 7 types de menaces (SQL Injection, XSS, Path Traversal, Scanners, Bruteforce, Flood).
- **Interface Web Moderne** : Design épuré noir et blanc, responsive, avec mode Sombre/Clair configurable.
- **Dashboard analytique** : Graphiques temps réel (tendance 7j, volume horaire, répartition par type, top IPs attaquantes).
- **Alertes Email** : Notification immédiate dans votre boîte mail dès qu'une attaque critique est repérée.
- **Rapports Pédagogiques** : Génération quotidienne (à 00h00) de rapports HTML détaillés qui expliquent l'attaque, son risque et comment la corriger.
- **100% Dockerisé** : Déploiement en une seule commande.
- **Multi-plateforme** : Fonctionne automatiquement sur Windows (Docker Desktop) pour le développement, et sur Linux (VPS/Ubuntu) pour la production.
- **Sécurité isolée** : LogSonar s'exécute en dehors de vos projets, il ne peut pas être compromis par une faille de votre application web.

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

### 4. Configuration initiale (premier lancement)

Lors du premier démarrage, LogSonar détecte qu'aucun utilisateur n'existe et affiche un **écran de configuration initiale** :

1. Créez votre compte **superuser** (administrateur)
2. Renseignez un **email valide** (nécessaire pour recevoir les OTP)
3. Choisissez un **mot de passe fort** (min. 8 caractères)

> **⚠️ Important** : Si le SMTP n'est pas encore configuré, le code OTP s'affichera dans les logs Docker. Consultez la section [Configuration SMTP](#configuration-smtp) ci-dessous.

---

## Authentification et Sécurité

### Système de connexion

LogSonar utilise une authentification à 2 facteurs (2FA) :

1. **Étape 1** : Nom d'utilisateur + mot de passe
2. **Étape 2** : Code OTP à 6 chiffres envoyé par email (ou affiché dans les logs si SMTP non configuré)

### Gestion des utilisateurs

| Rôle | Permissions | Limite |
|------|-------------|--------|
| **Superuser** | Tout (dashboard, live, rapports, paramètres, gestion users) | **1 max** |
| **User** | Lecture uniquement (dashboard, live, rapports en lecture seule) | **1 max** |

**Contraintes système :**
- Maximum **2 utilisateurs** au total
- Maximum **1 superuser** (impossible d'en créer un second)
- L'utilisateur standard **ne peut pas** télécharger ni supprimer les rapports
- Seul le superuser peut configurer le SMTP et générer des rapports manuellement

### Créer un utilisateur standard

Connectez-vous en tant que superuser, puis envoyez une requête API :

```bash
curl -X POST http://localhost:8081/api/auth/create-user \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=viewer" \
  -d "password=monMotDePasse" \
  -d "email=viewer@domaine.com" \
  -d "role=user" \
  --cookie "access_token=VOTRE_JWT_TOKEN"
```

---

## Configuration SMTP

Pour activer l'envoi des OTP par email et les alertes de sécurité, configurez le SMTP :

1. Connectez-vous en tant que **superuser**
2. Allez dans **Paramètres** → **Configuration SMTP**
3. Renseignez :
   - **Email destinataire** : l'adresse qui recevra les alertes
   - **Hôte SMTP** : ex. `smtp.gmail.com`
   - **Port** : ex. `587`
   - **Utilisateur SMTP** : votre adresse email
   - **Mot de passe SMTP** : mot de passe d'application (pas votre mot de passe principal)

4. Cliquez sur **"Envoyer un test"** pour vérifier
5. Cliquez sur **"Sauvegarder"**

> **Note Gmail** : Vous devez générer un "Mot de passe d'application" dans votre compte Google (Sécurité → Vérification en 2 étapes → Mots de passe d'application).

---

## Déploiement en Production

### 1. Variables d'environnement

Créez un fichier `.env` à la racine du projet :

```env
# Sécurité (obligatoire en production)
LOGSONAR_JWT_SECRET=votre-cle-super-secrete-32-caracteres-min

# Optionnel : forcer HTTPS pour les cookies
# LOGSONAR_SECURE_COOKIES=true
```

> **⚠️ CRITIQUE** : Changez immédiatement `LOGSONAR_JWT_SECRET` ! Générez-en une avec : `openssl rand -base64 32`

### 2. Modifications obligatoires pour la production

#### A. `app/main.py` — Activer HTTPS/Secure Cookies

Trouvez cette ligne dans `main.py` :

```python
response.set_cookie(
    key="access_token",
    value=token,
    httponly=True,
    secure=False,  # ← CHANGER EN TRUE
    samesite="lax",
    max_age=86400,
    path="/"
)
```

Remplacez `secure=False` par `secure=True` :

```python
    secure=True,  # ← COOKIES UNIQUEMENT EN HTTPS
```

#### B. `app/main.py` — Désactiver le fallback OTP console

Trouvez cette section dans `api_login` :

```python
    if not result["sent"] and result["code"]:
        response_data["code"] = result["code"]  # ← RETIRER EN PROD
```

**Supprimez ou commentez** la ligne `response_data["code"] = result["code"]` pour ne jamais exposer le code OTP dans la réponse API.

#### C. `docker-compose.yml` — Exposer uniquement le port nécessaire

```yaml
version: "3.8"
services:
  logsonar:
    build: .
    container_name: logsonar
    restart: unless-stopped
    ports:
      - "127.0.0.1:8081:8081"  # ← LOCALHOST UNIQUEMENT (reverse proxy devant)
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./data:/app/data
    environment:
      - LOGSONAR_JWT_SECRET=${LOGSONAR_JWT_SECRET}
    # ...
```

> **Jamais** d'exposition directe sur `0.0.0.0:8081` en production. Utilisez toujours un reverse proxy (Nginx, Traefik, Caddy).

### 3. Reverse Proxy (Nginx)

Exemple de configuration Nginx :

```nginx
server {
    listen 443 ssl http2;
    server_name logsonar.votre-domaine.com;

    ssl_certificate /etc/letsencrypt/live/votre-domaine.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/votre-domaine.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8081;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeouts pour WebSocket
        proxy_read_timeout 86400;
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

COPY app/ ./app/
COPY static/ ./static/

# Permissions restrictives
RUN mkdir -p /app/data && chown -R logsonar:logsonar /app/data
RUN chmod 600 /app/data/.secret_key 2>/dev/null || true

USER logsonar

EXPOSE 8081

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8081"]
```

### 5. Checklist de sécurité production

- [ ] `LOGSONAR_JWT_SECRET` changé et stocké dans `.env`
- [ ] `secure=True` activé dans les cookies
- [ ] Fallback OTP console désactivé (`response_data["code"]` retiré)
- [ ] Port exposé uniquement sur `127.0.0.1` (pas `0.0.0.0`)
- [ ] Reverse proxy HTTPS (Nginx/Traefik/Caddy) configuré
- [ ] Certificat SSL valide (Let's Encrypt)
- [ ] Firewall : port 8081 bloqué depuis l'extérieur
- [ ] Docker socket en lecture seule (`:ro`)
- [ ] Conteneur tourne avec un utilisateur non-root
- [ ] Clé Fernet (`data/.secret_key`) avec permissions `600`
- [ ] Logs Docker monitorés (`docker logs -f logsonar`)
- [ ] Backup régulier de `data/logsonar.db`

### 6. Mise à jour en production

```bash
# Pull des changements
git pull origin main

# Rebuild et redémarrage
docker-compose down
docker-compose up -d --build

# Vérifier les logs
docker logs -f logsonar
```

---

## Comment ça marche sous le capot ?

LogSonar utilise une architecture asynchrone moderne pour rester extrêmement léger :

1. **Lecture (Docker SDK)** : Au démarrage, LogSonar se connecte au démon Docker de l'hôte (via un socket Unix sur Linux, ou via TCP sur Windows). Il liste les conteneurs actifs (en s'excluant lui-même pour éviter une boucle infinie) et écoute leurs flux de logs en temps réel.
2. **Analyse (Moteur Regex)** : Chaque ligne de log est décodée, nettoyée des caractères de couleur ANSI, puis passée dans un moteur de regex. Il extrait l'IP, la méthode HTTP, le chemin, le code retour, et cherche des signatures d'attaques connues.
3. **Détection comportementale** : Détection de bruteforce (même IP + même path, >10 req/min) et flood (>30 req/30s par IP).
4. **Authentification (JWT + OTP)** : Chaque session est sécurisée par token JWT stocké en cookie HTTP-only. La connexion requiert un code OTP à usage unique envoyé par email.
5. **Temps réel (FastAPI & WebSockets)** : Si l'événement est une attaque, il est sauvegardé en base de données et une alerte mail est préparée en arrière-plan. Le log est ensuite poussé instantanément au navigateur via un canal WebSocket authentifié.
6. **Persistance (SQLite)** : Toutes les métriques, attaques et utilisateurs sont stockés dans une base SQLite locale (mode WAL pour les performances), liée au système de fichiers hôte pour survivre aux redémarrages de conteneurs.
7. **Rapports (Moteur de Templates)** : Un planificateur interne vérifie l'heure toutes les 30 secondes. À minuit pile, il interroge la base de données, récupère les attaques de la journée, et génère un fichier HTML formaté avec des explications techniques vulgarisées.

---

## Structure du Projet

```text
logsonar/
│
├── docker-compose.yml       # Configuration Docker (Ports, Volumes, Environnement)
├── Dockerfile               # Image Python légère (Alpine)
├── requirements.txt         # Dépendances Python
├── .env                     # Variables d'environnement (JWT_SECRET)
│
├── app/                     # Dossier applicatif (Backend Python)
│   ├── main.py              # Point d'entrée FastAPI + Auth + Routes
│   ├── db.py                # SQLite + Gestion users + OTP
│   ├── auth.py              # JWT + bcrypt + RBAC
│   ├── mailer.py            # SMTP + Envoi OTP
│   └── reporter.py          # Générateur de rapports HTML pédagogiques
│
├── static/                  # Dossier public (Frontend)
│   ├── index.html           # Interface principale (Dashboard, Live, Rapports, Paramètres)
│   └── login.html           # Page de connexion (2FA OTP)
│
└── data/                    # Volume Docker (persistant)
    ├── logsonar.db          # Base de données SQLite
    ├── .secret_key          # Clé de chiffrement Fernet (permissions 600)
    └── reports/             # Rapports HTML quotidiens
        └── rapport_2026-06-27.html
```

---

## Signatures de Détection

LogSonar analyse les requêtes **peu importe le code de retour** (200, 404, 500...) car une attaque réussie (200 OK) est plus critique qu'une attaque bloquée (403 Forbidden).

Il détecte actuellement :
1. **Tentative d'Injection SQL** : `UNION SELECT`, `OR 1=1`, `DROP TABLE`, `xp_cmdshell`, `information_schema`...
2. **Tentative de Cross-Site Scripting (XSS)** : `<script>`, `javascript:`, `onerror=`, `alert(`, `document.cookie`...
3. **Tentative de Path Traversal** : `../../../etc/passwd`, `%2e%2e`, double encodage...
4. **Scan de vulnérabilités (Bots)** : `Sqlmap`, `Nmap`, `Nikto`, `Nuclei`, `BurpSuite`, `Metasploit`...
5. **Recherche de fichiers sensibles** : `/.env`, `/wp-admin`, `/.git/`, `.htaccess`, `backup.sql`...
6. **Alertes internes (Django/Python)** : `SuspiciousOperation`, `LOGSONAR_POST_ATTACK`...
7. **Tentatives de falsification (CSRF)** : Échecs de validation de token CSRF.
8. **Bruteforce** : Plus de 10 requêtes identiques (même IP + même path) en 60 secondes.
9. **Flood** : Plus de 30 requêtes toutes cibles confondues depuis une même IP en 30 secondes.

---

## Notes Spécifiques & Bonnes Pratiques

### Les requêtes POST (Le point aveugle des logs)
Par défaut, les serveurs web (Nginx/Apache) ne loguent pas le corps (body) des requêtes POST pour des raisons de performance et de confidentialité. LogSonar ne verra donc pas une injection SQL faite depuis un formulaire de connexion classique. 
*Solution :* Pour surveiller les POST, il est recommandé d'ajouter un petit Middleware dans votre application qui écrit un log spécifique `LOGSONAR_POST_ATTACK` si un payload dangereux est détecté dans la requête. LogSonar interceptera ce signal.

### Développement sur Windows (Docker Desktop)
Pour que la détection automatique de Docker fonctionne sur Windows, assurez-vous que l'option **"Expose daemon on tcp://localhost:2375 without TLS"** est cochée dans les paramètres de Docker Desktop. LogSonar gérera la bascule tout seul.

### Environnement de Production (Linux)
Sur un serveur Ubuntu classique, aucune configuration supplémentaire n'est nécessaire. Le socket Docker standard (`/var/run/docker.sock`) sera utilisé automatiquement.

### OTP sans SMTP configuré
Si vous n'avez pas encore configuré le SMTP, le code OTP s'affiche dans les logs Docker :
```bash
docker logs -f logsonar
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
| POST | `/api/auth/login` | Étape 1 : username/password → OTP | ❌ |
| POST | `/api/auth/verify-otp` | Étape 2 : OTP → JWT cookie | ❌ |
| POST | `/api/auth/logout` | Déconnexion | ✅ |
| GET | `/api/auth/me` | Infos utilisateur connecté | ✅ |
| POST | `/api/auth/create-user` | Créer un user (superuser only) | ✅ superuser |

### Application
| Méthode | Endpoint | Description | Auth | Rôle |
|---------|----------|-------------|------|------|
| GET | `/api/settings` | Paramètres SMTP | ✅ | superuser |
| POST | `/api/settings` | Sauvegarder paramètres | ✅ | superuser |
| POST | `/api/settings/test` | Test email | ✅ | superuser |
| GET | `/api/reports` | Liste rapports | ✅ | all |
| GET | `/api/reports/view/{filename}` | Voir un rapport | ✅ | all |
| GET | `/api/reports/generate` | Générer rapport | ✅ | superuser |
| DELETE | `/api/reports/{filename}` | Supprimer rapport | ✅ | superuser |
| GET | `/api/stats` | Stats du jour | ✅ | all |
| GET | `/api/dashboard` | Données dashboard | ✅ | all |
| GET | `/api/ws-token` | Token JWT pour WebSocket | ✅ | all |

---

## Améliorations Futures (Roadmap)

- [x] Système d'authentification avec 2FA OTP
- [x] Contrôle d'accès RBAC (superuser/user)
- [x] Dashboard analytique avec graphiques
- [x] Détection comportementale (bruteforce, flood)
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
