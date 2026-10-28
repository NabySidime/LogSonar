# Accès en lecture seule (Claude, scripts)

Un **jeton de lecture** permet à un outil externe de consulter LogSonar — par exemple Claude Code sur votre PC, pour analyser les alertes avec vous — **sans pouvoir rien modifier**.

## Ce qu'un jeton peut et ne peut pas faire

| Peut consulter | Ne peut jamais |
|---|---|
| Vue d'ensemble et score | Modifier un paramètre ou un seuil |
| Serveur, conteneurs, trafic | Traiter, prendre en compte ou résoudre une alerte |
| Menaces (attaques détectées) | Lancer un scan, générer ou supprimer un rapport |
| Alertes | Voir ou modifier les comptes, ni les paramètres (secrets compris) |
| Vulnérabilités, audit, certificats | Créer d'autres jetons |
| Rapports quotidiens | Envoyer des notifications ou des données (middleware) |

La règle est appliquée par LogSonar lui-même, à trois niveaux :
1. **méthode** : toute requête autre que `GET` est refusée, quelle que soit l'adresse ;
2. **liste fermée** de pages de consultation (paramètres, comptes et temps réel exclus) ;
3. **rôle « lecteur »**, inférieur à « lecture seule », refusé par toutes les actions d'administration.

Le jeton n'est stocké que sous forme d'empreinte (SHA-256), il expire (7 jours à 1 an), et chaque utilisation est visible : date, IP, activité. 5 jetons actifs au maximum ; une tentative avec un faux jeton est limitée comme une tentative de connexion.

---

## Mise en place avec Claude Code

### 1. Créer le jeton (sur LogSonar en production)
**Paramètres → Accès en lecture seule → Créer un jeton** : nom « Claude », durée 30 jours. Copiez-le.

### 2. Le placer dans une variable d'environnement de votre PC
Pas dans une conversation ni dans un fichier du projet : ainsi le jeton n'apparaît jamais dans l'historique.

Windows (PowerShell) :
```powershell
[Environment]::SetEnvironmentVariable("LOGSONAR_URL", "https://logsonar.tikipay.org", "User")
[Environment]::SetEnvironmentVariable("LOGSONAR_READ_TOKEN", "lsr_...", "User")
```
Linux / macOS (`~/.bashrc` ou `~/.zshrc`) :
```bash
export LOGSONAR_URL=https://logsonar.tikipay.org
export LOGSONAR_READ_TOKEN=lsr_...
```
Puis **redémarrez VS Code / le terminal** pour que Claude Code voie les variables.

### 3. Réseau
Si l'interface est réservée à certaines IP (`allow` dans Nginx), ajoutez celle de votre PC, ou passez par le VPN.

### 4. Utilisation
Demandez simplement : « regarde les alertes de LogSonar », « analyse le rapport d'hier », « que faire pour les vulnérabilités critiques ? ».
Claude lit les données avec des commandes comme :
```bash
curl -s -H "Authorization: Bearer $LOGSONAR_READ_TOKEN" "$LOGSONAR_URL/api/alerts?status=active"
```
Le jeton reste dans la variable : il n'est jamais affiché. Chaque commande passe par votre validation dans Claude Code, et **toute action** (corriger, mettre à jour, bannir une IP, résoudre une alerte) reste de votre fait : Claude vous donne la marche à suivre.

### Couper l'accès
**Paramètres → Accès en lecture seule → Révoquer** : effet immédiat.

---

## Pages accessibles (API)

| Route | Contenu |
|---|---|
| `GET /api/overview` | score, état du serveur, attaques du jour, conteneurs |
| `GET /api/alerts?status=active` | alertes en cours (`resolved`, `all`) ; période : `since`, `until` |
| `GET /api/security/events?limit=100` | attaques détectées ; filtres `status` (`200`, `200,301`, `2xx`, `none`), `since`, `until`, `ip`, `attack_type`, `severity` |
| `GET /api/security/stats?days=7` | statistiques d'attaques (ou `since`/`until`), dont la répartition par code (`by_status`) |
| `GET /api/host?range=24h` (ou `since`/`until`) · `/api/host/processes` | métriques et processus du serveur |
| `GET /api/containers` · `/api/containers/{nom}/history` | conteneurs |
| `GET /api/traffic` | trafic HTTP |
| `GET /api/system` | état de LogSonar |
| `GET /api/vulns/summary` · `/api/vulns/findings` · `/api/vulns/config` · `/api/vulns/tls` | vulnérabilités, audit, certificats |
| `GET /api/reports` · `/api/reports/{fichier}` | rapports quotidiens |

`since` et `until` sont des horodatages Unix en secondes.

## Ce que contiennent ces données
Adresses IP des attaquants, URL visées, extraits d'attaques (jamais de mot de passe ni de donnée bancaire), métriques, liste des paquets vulnérables. Aucun secret (clés API, mots de passe, jetons) n'est accessible. Traitez néanmoins le jeton comme un mot de passe.
