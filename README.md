# LogSonar

**LogSonar** est un outil de surveillance de sécurité léger, stylé et intelligent, conçu pour analyser les logs de vos conteneurs Docker en temps réel.

C’est l’alternative parfaite aux monstres de la sécurité comme Wazuh ou ELK stack lorsque vous avez des ressources limitées. LogSonar se concentre sur l’essentiel : détecter les intrusions, vous alerter immédiatement, et générer des rapports explicatifs compréhensibles par tous, sans jamais envoyer vos données à une IA externe.

---

## Fonctionnalités

- **Authentification sécurisée** : Système à 2 facteurs (2FA) avec OTP par email, rôles utilisateur (superuser/user).
- **Contrôle d’accès (RBAC)** : 2 utilisateurs max, 1 superuser. L’utilisateur standard ne peut que consulter le dashboard, le live et les rapports.
- **Temps réel (WebSocket)** : Flux de logs style "terminal" ultra-rapide, avec défilement fluide et bouton Pause/Reprendre.
- **Détection d’attaques** : Reconnaissance instantanée de **+20 types de menaces** (signatures regex + détections comportementales).
- **Interface Web Moderne** : Design épuré noir et blanc, responsive, avec mode Sombre/Clair configurable.
- **Dashboard analytique** : Graphiques temps réel (tendance 7j, volume horaire, répartition par type, top IPs attaquantes, feed récent).
- **Alertes Email** : Notification immédiate dans votre boîte mail dès qu’une attaque critique réussie est repérée (code 2xx). Utilise l’API **Brevo** (ex‑Sendinblue) pour un envoi fiable et sans serveur SMTP.
- **Rapports Pédagogiques** : Génération quotidienne (à 00h00) de rapports HTML détaillés qui expliquent l’attaque, son risque et comment la corriger.
- **Scan de dépendances Python** : Analyse des paquets prioritaires dans vos conteneurs, avec comparaison des versions via PyPI.
- **Scan des services système** : Vérification des versions critiques (Nginx, OpenSSL, PostgreSQL, Redis…) avec alerte si elles sont obsolètes.
- **Purge automatique** : Suppression des événements de plus de 60 jours (paramétrable) pour maîtriser la taille de la base de données.
- **Whitelist IP / CIDR** : Possibilité d’ignorer les scanners légitimes (Censys, Shodan…) et vos propres IP internes.
- **100% Dockerisé** : Déploiement en une seule commande.
- **Multi‑plateforme** : Fonctionne automatiquement sur Windows (Docker Desktop) pour le développement, et sur Linux (VPS/Ubuntu) pour la production.
- **Sécurité isolée** : LogSonar s’exécute en dehors de vos projets, il ne peut pas être compromis par une faille de votre application web.

---

## Installation et Démarrage (Local)

### Prérequis
- [Docker](https://docs.docker.com/get-docker/)
- [Docker Compose](https://docs.docker.com/compose/install/)

### 1. Cloner le projet
```bash
git clone https://github.com/NabySidime/LogSonar.git
cd LogSonar
```

### 2. Lancer l’application
```bash
docker compose up -d --build
```

### 3. Accéder à l’interface
Ouvrez votre navigateur et rendez‑vous sur : **http://localhost**

### 4. Configuration initiale
Lors du premier lancement, un formulaire vous permet de créer le compte superuser. Si vous skippez cette étape, un compte par défaut est créé (`admin` / `admin123`). 

> **Important** : Changez immédiatement ce mot de passe. Si Brevo n’est pas encore configuré, le code OTP s’affichera dans les logs Docker : `docker logs -f logsonar-app`.

---

## Déploiement en Production (Greffé sur un existant)

LogSonar est conçu pour se greffer sur un serveur possédant **déjà un Reverse Proxy (Nginx) et un certificat SSL (Let's Encrypt)** gérés par Docker (ex: un projet Django/Node existant).

### Principe d’architecture
Au lieu d’exposer des ports sur le serveur hôte, LogSonar rejoint le réseau Docker de votre application existante. Votre Nginx existant agit comme porte d’entrée unique.

```
Internet → SSL (Nginx Existant) → Réseau Docker → LogSonar
```

### 1. Préparer les fichiers sur le serveur
```bash
git clone https://github.com/NabySidime/LogSonar.git
cd LogSonar
mkdir -p data/reports
```

### 2. Configurer les variables d’environnement
```bash
echo "LOGSONAR_JWT_SECRET=$(openssl rand -base64 48)" > .env
chmod 600 .env
```

### 3. Adapter le réseau Docker
Ouvrez `docker-compose.prod.yml` et modifiez le nom du réseau externe pour qu’il corresponde au réseau de votre application principale (trouvez‑le avec `docker network ls`) :
```yaml
networks:
  tikipay:
    external: true
    name: tikipay_default  # ← REMPLACEZ PAR VOTRE RESEAU
```

### 4. Configurer le Reverse Proxy (Nginx) existant
Dans la configuration Nginx de votre application principale, ajoutez ce bloc à la fin du fichier :

```nginx
# -----------------------------------------------------------
# LogSonar — Surveillance de sécurité
# -----------------------------------------------------------
server {
    listen 80;
    server_name logsonar.votre-domaine.com; # ← REMPLACEZ

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
        return 301 https://logsonar.votre-domaine.com$request_uri; # ← REMPLACEZ
    }
}

server {
    listen 443 ssl;
    server_name logsonar.votre-domaine.com; # ← REMPLACEZ

    # Certificat (à générer à l’étape 6)
    ssl_certificate /etc/letsencrypt/live/logsonar.votre-domaine.com/fullchain.pem; # ← REMPLACEZ
    ssl_certificate_key /etc/letsencrypt/live/logsonar.votre-domaine.com/privkey.pem; # ← REMPLACEZ
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    location ~* /\.(env|git|htaccess) {
        return 444;
    }

    location / {
        # Communication directe via le réseau Docker interne
        proxy_pass http://logsonar-app:80;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeouts longs pour le WebSocket
        proxy_read_timeout 86400;
        proxy_send_timeout 86400;
    }
}
```

**ATTENTION :** Commentez temporairement les lignes `ssl_certificate` et `ssl_certificate_key` du bloc 443 avant de redémarrer Nginx, sinon Nginx refusera de démarrer.

### 5. DNS
Ajoutez un enregistrement DNS de type `A` chez votre registraire :
- **Host** : `logsonar`
- **Value** : `L’IP de votre serveur`

### 6. Démarrer LogSonar et générer le SSL
```bash
# 1. Démarrer LogSonar
docker compose -f docker-compose.prod.yml up -d --build

# 2. Redémarrer votre Nginx existant (pour prendre en compte la redirection port 80)
docker compose -f docker-compose.prod.yml de votre-app up -d

# 3. Générer le certificat SSL (exemple avec certbot en Docker)
docker compose -f docker-compose.prod.yml de votre-app run --rm --entrypoint "certbot" certbot certonly \
  --webroot -w /var/www/certbot \
  -d logsonar.votre-domaine.com \
  --email votre-email@gmail.com \
  --agree-tos --no-eff-email

# 4. Décommenter les lignes ssl_certificate dans Nginx

# 5. Forcer Nginx à relire la config
docker exec votre-nginx nginx -s reload
```

---

## Authentification et Sécurité

### Système de connexion
1. **Étape 1** : Nom d’utilisateur + mot de passe
2. **Étape 2** : Code OTP à 6 chiffres envoyé par email (ou affiché dans les logs si Brevo non configuré)

### Gestion des utilisateurs

| Rôle | Permissions | Limite |
|------|-------------|--------|
| **Superuser** | Tout (dashboard, live, rapports, paramètres, gestion users, scan deps, scan système) | **1 max** |
| **User** | Lecture uniquement (dashboard, live, rapports en lecture seule) | **1 max** |

**Contraintes système :**
- Maximum **2 utilisateurs actifs** au total
- La suppression d’un utilisateur le **supprime physiquement** de la base (libère sa place)
- Le mot de passe SMTP (Brevo) est chiffré en AES‑128 (Fernet) en base de données.

### Créer un utilisateur standard
Via l’interface : Connectez‑vous en superuser → **Utilisateurs** → bouton **Ajouter**

---

## Configuration des Emails (Brevo)

LogSonar utilise désormais **Brevo** (ex‑Sendinblue) pour l’envoi des emails. Plus besoin de serveur SMTP.

1. Connectez‑vous en superuser → **Paramètres**
2. Renseignez :
   - **Clé API Brevo** (générée depuis votre compte Brevo)
   - **Expéditeur** (adresse email vérifiée dans votre compte Brevo)
3. Cliquez sur **"Envoyer un test"** pour vérifier.
4. Cliquez sur **"Sauvegarder"**.

> **Note** : Si Brevo n’est pas configuré, les codes OTP s’affichent en console (`docker logs -f logsonar-app`).

---

## Structure du Projet

```text
logsonar/
│
├── docker-compose.yml           # Développement local (expose le port 80)
├── docker-compose.prod.yml      # Production (greffé sur un réseau Docker existant)
├── Dockerfile                   # Image Python (Alpine)
├── requirements.txt             # Dépendances Python
│
├── app/                         # Backend Python
│   ├── main.py                  # Point d’entrée FastAPI + Moteur d’analyse
│   ├── db.py                    # SQLite (WAL) + Users + OTP + Fernet + purge auto
│   ├── mailer.py                # Envoi via Brevo (API REST)
│   └── reporter.py              # Générateur de rapports HTML
│
├── static/                      # Frontend
│   ├── index.html               # Interface SPA principale
│   └── login.html               # Connexion (Setup + 2FA OTP)
│
└── data/                        # Volume persistant
    ├── logsonar.db              # Base de données
    ├── .secret_key              # Clé Fernet (perms 600)
    ├── .jwt_secret              # Clé JWT auto-générée (perms 600)
    └── reports/                 # Rapports quotidiens
```

---

## Signatures de Détection (23 types)

LogSonar analyse les requêtes **peu importe le code de retour** (200, 404, 500…).

### Signatures Regex (19 types)
1. **Injection SQL** : `UNION SELECT`, `OR 1=1`, `DROP TABLE`…
2. **XSS** : `<script>`, `javascript:`, `onerror=`…
3. **Path Traversal** : `../../../etc/passwd`…
4. **Injection de Commande** : `; ls`, `$(whoami)`…
5. **Log4Shell (Log4J)** : `${jndi:ldap://…}`…
6. **SSRF** : `url=http://169.254.169.254`…
7. **XXE** : `<!DOCTYPE`, `<!ENTITY`…
8. **Redirection Ouverte** : `redirect=https://evil.com`…
9. **Scan de vulnérabilités (Bots)** : `Sqlmap`, `Nmap`, `Nikto`, `User-Agent vide`…
10. **Scan de routeurs / IoT** : `/storage/apply.cgi`, `/JNAP/`, `/hndUnblock.cgi`… (détection des scanners d’équipements réseau)
11. **Fichiers sensibles** : `/.env`, `/wp-admin`, `/.git/`…
12. **Alertes internes** : `SuspiciousOperation`, `LOGSONAR_POST_ATTACK`…
13. **CSRF** : Échecs de validation de token.
14. **SSTI (Template)** : `{{7*7}}`, `${7*7}`…
15. **Désérialisation** : `rO0AB` (Java), `__reduce__` (Python)…
16. **Recherche d’infos** : `id_rsa`, `.aws/credentials`…

### Détections Comportementales (2 types)
17. **Bruteforce** : > 20 req/min (même IP + même path) – seuil paramétrable.
18. **Flood** : > 30 req/30s (même IP) – seuil paramétrable.

### Détections supplémentaires (Post / ciblées)
19. **Injection SQL (POST)** : détection sur les chemins POST suspects.
20. **Injection de Commande (POST)** : sur les POST contenant des métacaractères shell.
21. **Upload malveillant (POST)** : tentative d’upload de scripts PHP/ASP/JSP.

> **Note** : Pour une détection complète sur les requêtes POST (analyse du corps), configurez Nginx pour logger `$request_body` (voir section “Optimisations”).

---

## Scan des dépendances

### Paquets Python
- Liste prioritaire de ~50 paquets (Django, FastAPI, Celery, DRF, Pillow, PyJWT, etc.).
- Comparaison avec la dernière version disponible sur PyPI.
- Affichage des paquets obsolètes dans une modal dédiée.

### Services système
- Détection des versions de **Nginx**, **OpenSSL**, **PostgreSQL**, **Redis**, **Node.js**, **Python**…
- Comparaison avec la dernière version stable (via Docker Hub).
- Alerte si une mise à jour est nécessaire.

---

## Gestion des logs et purge automatique

- Les événements sont conservés dans `data/logsonar.db`.
- Une purge automatique supprime les événements de plus de **60 jours** (paramètre `_RETENTION_DAYS` dans `db.py`).
- Vous pouvez lancer manuellement une purge depuis l’interface (bouton dédié en développement) ou via l’API.

---

## Whitelist IP / CIDR

Pour éviter les faux positifs (scanners légitimes, IP internes), vous pouvez whitelister des IPs ou des plages CIDR :

```python
# Dans main.py
WHITELIST_IPS = {"172.18.0.5", "41.77.188.2", "66.132.172.186"}
WHITELIST_CIDRS = ["66.132.172.0/24", "66.132.176.0/24"]
```

Les requêtes provenant de ces adresses seront ignorées (ni alertes, ni logs d’attaque).

---

## Optimisations et Bonnes Pratiques

### 1. Augmenter les seuils comportementaux
Si vous recevez trop de faux positifs (ex: recharges de l’interface admin), ajustez dans `main.py` :

```python
_BRUTE_THRESHOLD = 100
_FLOOD_THRESHOLD = 150
_ALERT_COOLDOWN_SECONDS = 600   # 10 minutes entre deux emails
```

### 2. Logger le corps des requêtes POST (Nginx)
Ajoutez dans la configuration Nginx :

```nginx
log_format main '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" "$request_body"';
access_log /var/log/nginx/access.log main;
```

Cela peut augmenter la taille des logs et exposer des données sensibles. À utiliser avec précaution.

### 3. Activer la purge automatique
La purge est déjà configurée par défaut. Vous pouvez modifier la durée dans `db.py` :

```python
_RETENTION_DAYS = 180   # 6 mois
```

---

## Dépendances Python

```
fastapi
uvicorn[standard]
aiosqlite
docker
bcrypt
pyjwt
cryptography
aiohttp          # pour l’API Brevo
```

---

## Licence

Ce projet est open‑source et libre d’utilisation.  
Créé avec patience, beaucoup de café, et un zeste de paranoïa sécuritaire.