# Déployer LogSonar sur un serveur

Guide pas à pas pour installer LogSonar sur un serveur Linux qui fait tourner une application Docker (exemple : Tikipay).
Durée : environ 30 minutes.

---

## 0. Avant de commencer

### Révoquer les anciennes clés Brevo (obligatoire)
La v1 contenait un fichier `doc.txt` avec deux clés API Brevo. Il est supprimé, mais **il reste dans l'historique git publié sur GitHub** : n'importe qui peut encore les lire.

1. Brevo → *SMTP & API* → *Clés API* : supprimez les deux anciennes clés.
2. Créez-en une nouvelle ; vous la saisirez dans l'interface de LogSonar (elle y est chiffrée, jamais dans un fichier).

Facultatif — effacer le fichier de l'historique git (réécrit l'historique, à faire une seule fois) :
```bash
pip install git-filter-repo
git filter-repo --path doc.txt --invert-paths
git remote add origin https://github.com/NabySidime/LogSonar.git
git push --force --all
```

### Prérequis du serveur
- Linux (Debian, Ubuntu…) avec **Docker** et le plugin **docker compose** (v2.24 ou plus récent).
- 200 Mo de RAM libres et 1 Go de disque.
- Un sous-domaine si vous voulez accéder à l'interface en HTTPS (ex. `logsonar.tikipay.org`), sinon un tunnel SSH suffit.

Vérifier :
```bash
docker --version && docker compose version
```

---

## 1. Installer

```bash
cd /opt
sudo git clone https://github.com/NabySidime/LogSonar.git logsonar
sudo chown -R $USER: logsonar && cd logsonar
cp .env.example .env
nano .env
```

Dans `.env`, au minimum :
```bash
LOGSONAR_INSTANCE_NAME=Tikipay
TZ=Europe/Paris
LOGSONAR_TRUSTED_PROXIES=172.16.0.0/12        # réseaux Docker : votre reverse proxy
LOGSONAR_WHITELIST_IPS=                       # votre IP fixe d'administration, si vous en avez une
LOGSONAR_ALLOWED_REDIRECT_DOMAINS=tikipay.org
```

### Choisir le mode de lancement

**A. Simple** — l'interface écoute sur `127.0.0.1:8081` du serveur :
```bash
docker compose up -d --build
```

**B. Recommandé** — LogSonar rejoint le réseau Docker de votre application. C'est nécessaire pour l'analyse des requêtes POST (étape 5) et pratique si votre reverse proxy est lui-même dans Docker.
```bash
docker network ls                       # repérez le réseau de Tikipay, ex. tikipay_default
echo "PROXY_NETWORK=tikipay_default" >> .env
docker compose -f docker-compose.yml -f docker-compose.proxy.yml up -d --build
```

Vérifier que tout tourne :
```bash
docker compose ps                       # logsonar : "Up (healthy)", logsonar-socket-proxy : "Up"
docker compose logs logsonar | tail -20 # affiche le CODE D'INSTALLATION
```

---

## 2. Rendre l'interface accessible

### Option 1 : tunnel SSH (aucune exposition, mode A uniquement)
Depuis votre PC :
```bash
ssh -L 8081:127.0.0.1:8081 utilisateur@serveur
```
Puis ouvrez http://localhost:8081.

### Option 2 : sous-domaine HTTPS
Un exemple Nginx complet est fourni : [`integrations/nginx/logsonar.conf`](../integrations/nginx/logsonar.conf).

1. DNS : un enregistrement `A` `logsonar.tikipay.org` → IP du serveur.
2. Copiez le fichier dans la configuration Nginx et remplacez le nom de domaine.
3. Certificat : `sudo certbot --nginx -d logsonar.tikipay.org`
4. `sudo nginx -t && sudo systemctl reload nginx`

Le fichier d'exemple bloque `/api/ingest` depuis Internet : le middleware passe par le réseau Docker interne.

> Recommandé : limitez l'accès à vos IP (`allow` / `deny` dans le fichier Nginx) ou passez par un VPN.

---

## 3. Premier accès

1. Ouvrez l'interface et saisissez le **code d'installation** (`docker compose logs logsonar`).
2. Créez le compte administrateur (10 caractères, une majuscule, un chiffre).
3. Scannez le QR code avec Google Authenticator, Authy, Bitwarden… La 2FA est obligatoire.
4. Facultatif : **Utilisateurs** → jusqu'à 2 comptes supplémentaires (3 au total). « Lecture seule » suffit pour consulter.

---

## 4. Configurer (Paramètres)

| Réglage | Conseil |
|---|---|
| **Email (Brevo)** | Nouvelle clé API, expéditeur **vérifié** chez Brevo, vos destinataires. Cliquez sur **Tester**. |
| **Discord / Telegram** | Recommandé pour être prévenu sur téléphone. Cliquez sur **Tester**. |
| **Gravité minimale** | « Élevée et critique » au début, pour éviter le bruit. |
| **Rapport quotidien** | Laissez activé : résumé chaque matin, rapport complet par email. |
| **Seuils** | Gardez les valeurs par défaut la première semaine, puis ajustez. |
| **Certificats TLS** | `tikipay.org, www.tikipay.org, logsonar.tikipay.org` |
| **Conteneurs surveillés** | Mettez en sourdine les conteneurs sans intérêt (bases de données bavardes…). |

Puis **Rapports → Générer et envoyer** pour vérifier que l'email du rapport arrive bien (avec sa pièce jointe).

---

## 5. Analyser les requêtes POST de Tikipay (Django)

Nécessite le **mode B** de l'étape 1 (LogSonar sur le réseau de Tikipay).

> **Déjà fait dans Tikipay et billetair** : le middleware est installé (`backend/logsonar_middleware.py` pour Tikipay, `backend/config/logsonar_middleware.py` pour billetair), ajouté à `MIDDLEWARE`, et les variables sont dans leur docker-compose. Il ne reste qu'à **ajouter le jeton** (étape 1 ci-dessous, puis `LOGSONAR_TOKEN=lsi_...` dans `backend/.env.production` pour Tikipay, `backend/.env` pour billetair) et redéployer. Sans jeton, le middleware reste inactif.

1. **Paramètres → Analyse des requêtes POST → Activer** : copiez les 3 lignes affichées (le jeton n'est montré qu'une fois).
2. Copiez [`integrations/django/logsonar_middleware.py`](../integrations/django/logsonar_middleware.py) dans le projet Tikipay, par exemple `tikipay/logsonar_middleware.py`.
3. Dans `settings.py`, ajoutez-le **à la fin** :
   ```python
   MIDDLEWARE = [
       # ... middlewares existants ...
       "tikipay.logsonar_middleware.LogSonarMiddleware",
   ]
   ```
4. Ajoutez les variables au service web de Tikipay (exemple complet : [`integrations/docker-compose.app-example.yml`](../integrations/docker-compose.app-example.yml)) :
   ```yaml
   environment:
     LOGSONAR_URL: http://logsonar:8000
     LOGSONAR_TOKEN: ${LOGSONAR_TOKEN}      # le jeton, dans le .env de Tikipay
     LOGSONAR_SOURCE: tikipay
     # URL non transmises : webhooks signés de prestataires, espaces d'admin où l'on saisit du HTML
     LOGSONAR_EXCLUDE_PATHS: /payments/callback/,/admin-panel/,/admin/
   ```
5. Redéployez Tikipay.

**Tester** (depuis votre PC, remplacez l'URL par une page de formulaire de Tikipay) :
```bash
curl -X POST https://tikipay.org/connexion/ -d "username=admin' OR 1=1--&password=test"
```
Dans LogSonar → **Menaces**, une « Tentative d'Injection SQL » doit apparaître avec « Corps : username=… ». Dans **Paramètres**, l'application « tikipay » doit être marquée *active*.

Pas d'impact si LogSonar est arrêté : le middleware ignore silencieusement les échecs d'envoi.

---

## 6. Vérifications finales

- [ ] **Vue d'ensemble** : CPU, mémoire et disques du serveur s'affichent (pas ceux d'une VM Docker Desktop).
- [ ] **Conteneurs** : tous les conteneurs de Tikipay sont listés, ceux qui exposent des logs HTTP sont « analysés ».
- [ ] **Trafic** : les requêtes par minute augmentent quand vous naviguez sur le site.
- [ ] **Vulnérabilités** : le premier scan se lance quelques secondes après le démarrage (puis chaque nuit à 3 h). L'onglet « Configuration » contient l'audit SSH/pare-feu du serveur.
- [ ] Une notification de test est arrivée sur chaque canal configuré.
- [ ] `curl -s https://tikipay.org/.env` → une alerte « Recherche de fichiers sensibles » apparaît dans **Menaces**.

---

## Mettre à jour LogSonar

```bash
cd /opt/logsonar
./scripts/backup.sh                     # sauvegarde avant mise à jour
git pull
docker compose up -d --build            # ajoutez -f docker-compose.proxy.yml en mode B
```
Les données (volume `logsonar-data`) sont conservées.

## Désinstaller

```bash
docker compose down        # arrêt, données conservées
docker compose down -v     # arrêt ET suppression des données
```

---

## En cas de problème

| Symptôme | Cause probable / solution |
|---|---|
| « Docker inaccessible » | `docker compose ps` : le conteneur `logsonar-socket-proxy` doit tourner. |
| Toutes les attaques viennent d'une IP en `172.x` | `LOGSONAR_TRUSTED_PROXIES` n'est pas renseigné, ou Nginx n'envoie pas `X-Forwarded-For` / ne logue pas l'IP réelle. |
| Aucune requête comptée dans Trafic | Le conteneur qui reçoit le trafic n'écrit pas de logs d'accès : activez-les (Gunicorn : `--access-logfile -`). |
| Le middleware n'envoie rien | `docker exec <conteneur tikipay> python -c "import urllib.request;print(urllib.request.urlopen('http://logsonar:8000/healthz').read())"` doit répondre. Sinon : LogSonar n'est pas sur le réseau de Tikipay (mode B). |
| Pas d'email | Expéditeur non vérifié chez Brevo, ou clé révoquée. Détail : `docker compose logs logsonar | grep notification`. |
| Téléphone 2FA perdu | `docker exec -it logsonar python -m app.cli reset-2fa <utilisateur>` |
| Mot de passe oublié | `docker exec -it logsonar python -m app.cli reset-password <utilisateur>` |
| Code d'installation perdu | `docker compose restart logsonar && docker compose logs logsonar` (affiché tant qu'aucun compte n'existe). |
