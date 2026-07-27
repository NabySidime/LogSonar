# LogSonar

> **LogSonar est une plateforme légère d'observabilité et de sécurité pour applications conteneurisées.**
>
> Déployée en quelques minutes, elle surveille vos services Docker en temps réel, détecte les attaques, analyse les vulnérabilités et fournit des rapports compréhensibles sans nécessiter une infrastructure lourde comme ELK ou Wazuh.

---

## Notre vision

Aujourd'hui, les solutions de cybersécurité sont souvent pensées pour les grandes entreprises. Elles nécessitent plusieurs services, beaucoup de ressources et une configuration complexe.

LogSonar suit une approche différente.

Notre objectif est de proposer une plateforme capable d'offrir les fonctionnalités essentielles d'un SIEM moderne tout en restant :

* légère ;
* simple à installer ;
* facile à comprendre ;
* adaptée aux VPS et petites infrastructures.

Une seule commande Docker suffit pour commencer à surveiller votre environnement.

---

## Pourquoi LogSonar ?

LogSonar ne cherche pas à remplacer les solutions d'entreprise.

Il répond à un besoin différent :

> Fournir aux développeurs, freelances, startups et PME une solution de sécurité moderne qu'ils peuvent installer en quelques minutes.

L'objectif est de permettre à chacun de comprendre ce qui se passe sur son infrastructure sans devoir devenir expert en cybersécurité.

---

Ensuite je remplacerais la section **Fonctionnalités** par quelque chose de plus organisé.

# Fonctionnalités

## Surveillance en temps réel

* Surveillance des conteneurs Docker
* Flux de logs WebSocket ultra-rapide
* Terminal temps réel
* Pause/Reprise
* Recherche dans les événements
* Dashboard interactif

---

## Détection de menaces

* Détection de plus de 20 attaques
* Analyse comportementale
* Détection par signatures
* Whitelist IP/CIDR
* Alertes critiques
* Historique des incidents

---

## Analyse de sécurité

* Scan des dépendances Python
* Scan des services système
* Vérification des versions
* Rapports quotidiens
* Explications pédagogiques

---

## Administration

* Authentification 2FA
* RBAC
* Gestion des utilisateurs
* Paramètres centralisés
* Purge automatique

---

Puis j'ajouterais une nouvelle partie.

# Philosophie

LogSonar repose sur quatre principes.

## Observer

Collecter les informations importantes sur votre infrastructure.

## Comprendre

Transformer les événements techniques en informations compréhensibles.

## Alerter

Notifier rapidement lorsqu'un risque apparaît.

## Agir

Aider l'utilisateur à résoudre le problème avant qu'il ne devienne critique.

---

STRUCTURE

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


Et surtout, j'ajouterais une roadmap publique.

# Roadmap

## Version 1.x (actuelle)

* ✅ Surveillance Docker
* ✅ Dashboard
* ✅ Détection de menaces
* ✅ Rapports HTML
* ✅ Alertes Email
* ✅ Scan des dépendances
* ✅ Scan système
* ✅ Authentification 2FA
* ✅ WebSocket temps réel

---

## Version 2.0 — Moteur de détection modulaire

* ⏳ Architecture par plugins
* ⏳ Signatures indépendantes
* ⏳ Chargement dynamique des règles
* ⏳ Création de règles personnalisées
* ⏳ Packs de signatures

---

## Version 2.5 — Tableau de bord avancé

* ⏳ Score global de sécurité
* ⏳ Timeline des attaques
* ⏳ Carte mondiale des IP attaquantes
* ⏳ Analyse par conteneur
* ⏳ Historique des incidents
* ⏳ Tableau de bord personnalisable

---

## Version 3.0 — Observabilité

* ⏳ Utilisation CPU
* ⏳ Utilisation mémoire
* ⏳ Utilisation disque
* ⏳ Santé des conteneurs
* ⏳ Surveillance Docker Events
* ⏳ Disponibilité des services
* ⏳ Surveillance des certificats SSL

---

## Version 3.5 — Gestion des vulnérabilités

* ⏳ Base CVE
* ⏳ Score CVSS
* ⏳ MITRE ATT&CK
* ⏳ Recommandations automatiques
* ⏳ Historique des vulnérabilités

---

## Version 4.0 — Réponse aux incidents

* ⏳ Blocage automatique d'IP
* ⏳ Intégration Fail2Ban
* ⏳ Intégration CrowdSec
* ⏳ Quarantaine de conteneurs
* ⏳ Réponses automatiques configurables

---

## Version 5.0 — Plateforme

* ⏳ Multi-hôtes
* ⏳ Multi-serveurs
* ⏳ Multi-sites
* ⏳ API publique
* ⏳ Webhooks
* ⏳ Plugin SDK
* ⏳ Intégrations Slack, Discord, Teams
* ⏳ Authentification SSO

---

# Ce que LogSonar n'est pas

LogSonar n'a pas vocation à remplacer des plateformes telles que Wazuh, Splunk ou Elastic dans les grandes infrastructures.

Son objectif est de proposer une alternative moderne, légère et simple, capable d'offrir une excellente visibilité sur la sécurité d'applications conteneurisées sans nécessiter une architecture complexe.