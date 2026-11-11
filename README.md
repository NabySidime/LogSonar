# LogSonar

**Surveillance légère et sécurité pour serveurs Docker.** Une alternative simple à Wazuh / ELK pour les VPS et petites infrastructures : un seul `docker compose up`, environ 100 Mo de RAM, aucune base externe.

LogSonar surveille **n'importe quel projet Docker** sur le serveur, sans modifier les applications :

| | |
|---|---|
| 🖥️ **Serveur** | CPU, mémoire, swap, disques, réseau, charge, processus les plus gourmands, espace occupé par Docker |
| 📦 **Conteneurs** | état, CPU/mémoire par conteneur, crash, mémoire saturée (OOM), healthcheck en échec, redémarrage en boucle |
| 🌐 **Trafic** | requêtes/min, pics anormaux (comparés à la normale), taux d'erreurs 5xx, IP et URL les plus actives |
| 🛡️ **Menaces** | injection SQL, XSS, path traversal, injection de commande, Log4Shell, SSRF, SSTI, scanners, fichiers sensibles, force brute, flood… dans les URL **et dans le corps des requêtes POST** (middleware optionnel) |
| 🐞 **Vulnérabilités** | paquets Debian/Ubuntu/Alpine, Python et npm de chaque conteneur **et du serveur**, comparés à la base [OSV.dev](https://osv.dev) (CVE, avis GitHub, Debian, Alpine…) |
| 🔧 **Audit de configuration** | base de données exposée sur Internet, conteneurs privilégiés, socket Docker monté, SSH root, pare-feu inactif, redémarrage requis… |
| 🔒 **Certificats TLS** | expiration et validité de vos domaines |
| 🔔 **Alertes** | dashboard + email (Brevo), Discord, Slack, Telegram, webhook JSON — avec déduplication et anti-rafale |
| 📄 **Rapports** | rapport quotidien : verdict, actions prioritaires, comparaison avec la veille, graphiques ; résumé envoyé sur vos canaux, rapport complet par email |

Chaque alerte et chaque faille est **expliquée en clair**, avec la correction à appliquer.

📘 **Documentation** : [Déployer sur un serveur](docs/DEPLOIEMENT.md) · [Utiliser au quotidien](docs/EXPLOITATION.md) · [Accès en lecture seule (Claude, scripts)](docs/ACCES-LECTURE.md) · [Historique des versions](CHANGELOG.md)

---

## Installation

```bash
git clone https://github.com/NabySidime/LogSonar.git && cd LogSonar
cp .env.example .env          # adaptez si besoin
docker compose up -d --build
docker compose logs logsonar  # affiche le code d'installation
```

L'interface écoute sur **http://127.0.0.1:8081** (uniquement en local). Au premier accès :
1. saisissez le **code d'installation** affiché dans les logs ;
2. créez le compte administrateur ;
3. scannez le QR code avec une application d'authentification (Google Authenticator, Authy, Bitwarden…) : la **double authentification est obligatoire**.

Pour y accéder depuis votre poste sans l'exposer : `ssh -L 8081:127.0.0.1:8081 votre-serveur`, puis http://localhost:8081.

### Derrière un reverse proxy (recommandé)

Pour l'exposer en HTTPS sur un sous-domaine, branchez LogSonar sur le réseau de votre reverse proxy :

```bash
# .env
PROXY_NETWORK=monprojet_default             # docker network ls
LOGSONAR_TRUSTED_PROXIES=172.16.0.0/12      # réseaux Docker : on fait confiance au proxy pour X-Forwarded-For
```
```bash
docker compose -f docker-compose.yml -f docker-compose.proxy.yml up -d --build
```

Exemple Nginx :
```nginx
location / {
    proxy_pass http://logsonar:8000;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_http_version 1.1;                     # WebSocket (temps réel)
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
}
```

### Pour de meilleurs résultats

- **Logs d'accès avec l'IP réelle** : si Nginx est dans Docker, gardez le format `combined` (ou ajoutez `"$http_x_forwarded_for"` en fin de ligne) ; LogSonar reconnaît Nginx, Apache, Traefik, Caddy (JSON), Uvicorn, Gunicorn et Django.
- **Exclure un conteneur** : ajoutez-lui le label `logsonar.enable=false`, ou mettez-le en sourdine dans Paramètres.
- **Domaines TLS** : renseignez-les dans Paramètres pour être prévenu avant expiration.

### Analyser le corps des requêtes POST

Les logs d'accès ne contiennent que l'URL : une injection SQL tapée dans un formulaire de connexion ou envoyée dans un appel API JSON y est **invisible**. Pour la détecter, ajoutez un petit middleware à votre application ; il transmet chaque requête POST/PUT/PATCH/DELETE à LogSonar, en arrière-plan.

1. **Paramètres → Analyse des requêtes POST → Activer** : copiez le jeton affiché (il ne sera plus montré).
2. **Django** : copiez `integrations/django/logsonar_middleware.py` dans votre projet et ajoutez-le à la fin de `MIDDLEWARE` (instructions en tête du fichier).
3. Variables d'environnement de l'application :
   ```bash
   LOGSONAR_URL=http://logsonar:8000
   LOGSONAR_TOKEN=lsi_...
   LOGSONAR_SOURCE=tikipay
   LOGSONAR_EXCLUDE_PATHS=/payments/callback/,/admin/   # facultatif : webhooks signés, admin avec HTML
   ```
4. L'application doit joindre LogSonar sur le réseau Docker : utilisez `docker-compose.proxy.yml` avec `PROXY_NETWORK` = le réseau de votre application.

Garanties :
- **Aucun impact sur l'application** : envoi asynchrone par lots ; si LogSonar est arrêté, rien ne change pour vos utilisateurs.
- **Données bancaires jamais transmises** (carte, CVV, IBAN… remplacés par `***` dans l'application même).
- **Rien n'est stocké** hormis un court extrait de l'attaque détectée, limité au champ attaqué ; la valeur d'un champ sensible (mot de passe, jeton…) n'est jamais conservée.

**Autres langages** : envoyez `POST /api/ingest` avec l'en-tête `Authorization: Bearer <jeton>` et ce JSON (200 requêtes max par lot) :
```json
{"source": "mon-api", "events": [{"method": "POST", "path": "/login?next=/", "status": 200,
  "ip": "172.18.0.5", "xff": "81.2.69.142", "ua": "Mozilla/5.0", "body": {"username": "..."}}]}
```
`body` peut être un objet JSON ou du texte brut.

---

## Sécurité de LogSonar lui-même

Un outil de sécurité ne doit pas devenir la porte d'entrée. LogSonar est conçu pour avoir le moins de pouvoir possible :

- **Accès Docker en lecture seule** via [docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy) (`POST=0`) : LogSonar ne peut ni créer, ni arrêter, ni exécuter quoi que ce soit. Le scan de vulnérabilités **lit** les fichiers des images, il n'exécute aucune commande dans vos conteneurs.
- Conteneur **sans root**, système de fichiers en lecture seule, toutes les capacités Linux retirées, `no-new-privileges`.
- Hôte monté en **lecture seule** (`/proc` et `/`) uniquement pour les métriques et l'audit.
- **3 comptes maximum** (administrateurs ou lecture seule) : l'accès reste limité à quelques personnes de confiance.
- **Jetons d'API en lecture seule** pour les outils externes : GET uniquement, liste fermée de pages, expiration, révocation immédiate, empreinte seule stockée.
- Mots de passe **bcrypt**, **2FA TOTP obligatoire** (codes non réutilisables), session en cookie `HttpOnly` + `SameSite=Strict`, révocation à la déconnexion.
- Limitation des tentatives par compte **et** par IP ; `X-Forwarded-For` lu seulement depuis vos proxys déclarés.
- Secrets (clés API, webhooks) **chiffrés** au repos et jamais renvoyés au navigateur.
- En-têtes de sécurité stricts (CSP sans script inline, anti-clickjacking, HSTS en HTTPS).

## Commandes de secours

```bash
docker exec -it logsonar python -m app.cli users                    # lister les comptes
docker exec -it logsonar python -m app.cli reset-2fa <utilisateur>  # téléphone perdu
docker exec -it logsonar python -m app.cli reset-password <utilisateur>
```

## Migration depuis la v1

Les événements d'attaque de la v1 sont importés automatiquement. Les comptes, eux, ne sont **pas** repris : la v1 stockait les mots de passe sans sel et sans 2FA, un nouvel administrateur est donc créé à l'installation.

```bash
docker compose up -d --build       # crée le volume logsonar-data
docker compose stop logsonar
docker run --rm -v logsonar_logsonar-data:/data -v "$PWD/data:/old:ro" alpine \
  sh -c "cp /old/logsonar.db /data/ && chown 10001:10001 /data/logsonar.db"
docker compose start logsonar
```

---

## Architecture

```
app/
├── main.py              Application FastAPI, en-têtes de sécurité, WebSocket
├── monitor.py           Orchestration : logs → détection → alertes, métriques, tâches planifiées
├── config.py            Configuration (variables d'environnement)
├── db.py                SQLite (WAL) + migration v1
├── security.py          bcrypt, sessions, TOTP, limitation des tentatives
├── settings_store.py    Paramètres modifiables (secrets chiffrés)
├── alerts.py            Alertes : déduplication, escalade, résolution automatique
├── notify.py            Email (Brevo), Discord, Slack, Telegram, webhook
├── traffic.py           Compteurs de trafic par conteneur
├── score.py             Score de sécurité global
├── reports.py           Rapport HTML quotidien
├── cli.py               Commandes de secours
├── api/ingest.py        Réception des requêtes envoyées par le middleware
├── api/tokens.py        Jetons d'accès en lecture seule
├── detection/
│   ├── signatures.py    Règles d'attaque (+ explications pédagogiques)
│   ├── parsers.py       Formats de logs HTTP
│   └── engine.py        Analyse d'une ligne, détection comportementale
├── collectors/
│   ├── docker_watch.py  Logs, événements, stats et occupation disque Docker
│   └── host.py          Métriques du serveur
├── vuln/
│   ├── inventory.py     Inventaire des paquets (dpkg, apk, Python, npm)
│   ├── osv.py           Client OSV.dev + calcul CVSS v3
│   ├── audit.py         Audit de configuration + TLS
│   └── scanner.py       Orchestration du scan
└── api/                 Routes HTTP
integrations/django/     Middleware Django (analyse des requêtes POST)
static/                  Interface (HTML/CSS/JS sans étape de build)
tests/                   Tests (pytest)
```

**Ajouter une règle de détection** : une entrée dans `RULES` (`app/detection/signatures.py`), une explication dans `EXPLANATIONS`, et un cas dans `tests/test_detection.py`.

```bash
pip install -r requirements.txt pytest && python -m pytest tests
```

## Limites connues

- Corps des requêtes POST : analysé seulement pour les applications équipées du middleware (fourni pour Django ; API simple pour les autres).
- Scan : les binaires Go/Rust/Java et les images Red Hat/Fedora (rpm) ne sont pas encore inventoriés.
- Un seul serveur par instance (le multi-serveurs est sur la feuille de route).

## Feuille de route

- Blocage automatique d'IP (intégration CrowdSec / Fail2Ban)
- Règles de détection personnalisables depuis l'interface
- Inventaire rpm, Go et Java ; scan des images avant déploiement
- Surveillance de disponibilité (ping HTTP de vos URLs)
- Multi-serveurs (agents légers + instance centrale)
- Cartographie MITRE ATT&CK des attaques détectées

## Auteur et licence

LogSonar est conçu et développé par **Naby Sidime** (https://github.com/NabySidime).

Distribué sous [licence MIT](LICENSE) : vous pouvez l'utiliser, le modifier et le redistribuer,
à condition de conserver la mention de copyright et la licence (voir aussi [NOTICE](NOTICE)).
Les commits de ce dépôt sont signés : un commit « Verified » sur GitHub provient bien de l'auteur.

Contributions bienvenues par pull request : voir [CONTRIBUTING.md](CONTRIBUTING.md).
