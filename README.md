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

## Installation et Démarrage (Local)

### Prérequis
- [Docker](https://docs.docker.com/get-docker/)
- [Docker Compose](https://docs.docker.com/compose/install/)

### 1. Cloner le projet
```bash
git clone https://github.com/NabySidime/LogSonar.git
cd LogSonar
```

### 2. Lancer l'application
```bash
docker compose up -d --build
```

### 3. Accéder à l'interface
Ouvrez votre navigateur et rendez-vous sur : **http://localhost**

### 4. Configuration initiale
Lors du premier lancement, un formulaire vous permet de créer le compte superuser. Si vous skippez cette étape, un compte par défaut est créé (`admin` / `admin123`). 

> **⚠️ Important** : Changez immédiatement ce mot de passe. Si le SMTP n'est pas encore configuré, le code OTP s'affichera dans les logs Docker : `docker logs -f logsonar-app`.

---

## Déploiement en Production (Greffé sur un existant)

LogSonar est conçu pour se greffer sur un serveur possédant **déjà un Reverse Proxy (Nginx) et un certificat SSL (Let's Encrypt)** gérés par Docker (ex: un projet Django/Node existant).

### Principe d'architecture
Au lieu d'exposer des ports sur le serveur hôte, LogSonar rejoint le réseau Docker de votre application existante. Votre Nginx existant agit comme porte d'entrée unique.

```
Internet → SSL (Nginx Existant) → Réseau Docker → LogSonar
```

### 1. Préparer les fichiers sur le serveur
```bash
git clone https://github.com/NabySidime/LogSonar.git
cd LogSonar
mkdir -p data/reports
```

### 2. Configurer les variables d'environnement
```bash
echo "LOGSONAR_JWT_SECRET=$(openssl rand -base64 48)" > .env
chmod 600 .env
```

### 3. Adapter le réseau Docker
Ouvrez `docker-compose.prod.yml` et modifiez le nom du réseau externe pour qu'il corresponde au réseau de votre application principale (trouvez-le avec `docker network ls`) :
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

    # Certificat (à générer à l'étape 6)
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
- **Value** : `L'IP de votre serveur`

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
1. **Étape 1** : Nom d'utilisateur + mot de passe
2. **Étape 2** : Code OTP à 6 chiffres envoyé par email (ou affiché dans les logs si SMTP non configuré)

### Gestion des utilisateurs

| Rôle | Permissions | Limite |
|------|-------------|--------|
| **Superuser** | Tout (dashboard, live, rapports, paramètres, gestion users, scan deps) | **1 max** |
| **User** | Lecture uniquement (dashboard, live, rapports en lecture seule) | **1 max** |

**Contraintes système :**
- Maximum **2 utilisateurs actifs** au total
- La suppression d'un utilisateur le désactive (`is_active = 0`), libérant sa place
- Le mot de passe SMTP est chiffré en AES-128 (Fernet) en base de données.

### Créer un utilisateur standard
Via l'interface : Connectez-vous en superuser → **Utilisateurs** → bouton **Ajouter**

---

## Configuration SMTP

1. Connectez-vous en superuser → **Paramètres**
2. Renseignez l'hôte (ex: `smtp.gmail.com`), le port (`587`), l'utilisateur et le mot de passe d'application.
3. Cliquez sur **"Envoyer un test"** pour vérifier.
4. Cliquez sur **"Sauvegarder"**.

> **Note Gmail** : Utilisez un "Mot de passe d'application" (Sécurité → Vérification en 2 étapes → Mots de passe d'application).

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
│   ├── main.py                  # Point d'entrée FastAPI + Moteur d'analyse
│   ├── db.py                    # SQLite (WAL) + Users + OTP + Fernet
│   ├── mailer.py                # SMTP asynchrone
│   └── reporter.py              # Générateur de rapports HTML
│
├── static/                      # Frontend
│   ├── index.html               # Interface SPA principale
│   └── login.html               # Connexion (Setup + 2FA OTP)
│
└── data/                        # Volume persistant
    ├── logsonar.db              # Base de données
    ├── .secret_key              # Clé Fernet SMTP (perms 600)
    ├── .jwt_secret              # Clé JWT auto-générée (perms 600)
    └── reports/                 # Rapports quotidiens
```

---

## Signatures de Détection (17 types)

LogSonar analyse les requêtes **peu importe le code de retour** (200, 404, 500...).

### Signatures Regex (15 types)
1. **Injection SQL** : `UNION SELECT`, `OR 1=1`, `DROP TABLE`...
2. **XSS** : `<script>`, `javascript:`, `onerror=`...
3. **Path Traversal** : `../../../etc/passwd`...
4. **Injection de Commande** : `; ls`, `$(whoami)`...
5. **Log4Shell (Log4J)** : `${jndi:ldap://...}`...
6. **SSRF** : `url=http://169.254.169.254`...
7. **XXE** : `<!DOCTYPE`, `<!ENTITY`...
8. **Redirection Ouverte** : `redirect=https://evil.com`...
9. **Scan de vulnérabilités (Bots)** : `Sqlmap`, `Nmap`, `Nikto`...
10. **Fichiers sensibles** : `/.env`, `/wp-admin`, `/.git/`...
11. **Alertes internes** : `SuspiciousOperation`, `LOGSONAR_POST_ATTACK`...
12. **CSRF** : Échecs de validation de token.
13. **SSTI (Template)** : `{{7*7}}`, `${7*7}`...
14. **Désérialisation** : `rO0AB` (Java), `__reduce__` (Python)...
15. **Recherche d'infos** : `id_rsa`, `.aws/credentials`...

### Détections Comportementales (2 types)
16. **Bruteforce** : >10 req/min (même IP + même path).
17. **Flood** : >30 req/30s (même IP).

---

## Notes Spécifiques

- **Requêtes POST** : Les serveurs web ne loguent pas le corps des POST. Ajoutez un middleware dans votre app pour loguer `LOGSONAR_POST_ATTACK` si un payload dangereux est détecté.
- **Alertes Email** : Rate-limitées (cooldown de 60s par IP/type) pour éviter la saturation. Seules les attaques réussies (2xx) déclenchent des alertes.
- **Scan Deps** : Nécessite `pip` et un accès internet dans les conteneurs scannés.

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
```

---

## Licence

Ce projet est open-source et libre d'utilisation.
Créé avec patience, beaucoup de café, et un zeste de paranoïa sécuritaire.