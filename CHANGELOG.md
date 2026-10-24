# Historique des versions

## 2.0.0 — refonte complète

LogSonar devient un outil de surveillance générique pour **n'importe quel serveur Docker**, et plus seulement pour Tikipay.

### Nouveautés
- **Serveur** : CPU, mémoire, swap, disques, réseau, charge, processus les plus gourmands, espace occupé par Docker.
- **Conteneurs** : état, CPU/mémoire par conteneur, alertes de crash, de manque de mémoire (OOM), de healthcheck en échec et de redémarrage en boucle.
- **Trafic** : requêtes par minute, détection des pics anormaux (comparés au trafic habituel), taux d'erreurs 5xx.
- **Scanner de vulnérabilités** : paquets Debian/Ubuntu/Alpine, Python et npm des conteneurs et du serveur, comparés à OSV.dev, avec la version corrigée à installer.
- **Audit de configuration** : base de données exposée, conteneur privilégié, socket Docker monté, SSH, pare-feu, redémarrage requis…
- **Certificats TLS** : alerte avant expiration.
- **Analyse du corps des requêtes POST**, via un middleware Django (ou l'API `/api/ingest`).
- **Alertes** avec déduplication, escalade et résolution automatique ; notifications par email (Brevo), Discord, Slack, Telegram et webhook.
- **Rapport quotidien** : verdict, actions prioritaires, comparaison avec la veille, graphiques ; envoyé automatiquement.
- **Score de sécurité** sur 100, avec le détail de chaque point perdu.
- **Nouvelle interface** : temps réel, mode sombre, mobile.
- **Jetons d'accès en lecture seule** pour consulter les données depuis un outil externe (voir `docs/ACCES-LECTURE.md`).

### Sécurité
- Mots de passe bcrypt (la v1 utilisait SHA-256 sans sel).
- 2FA TOTP obligatoire, limitation des tentatives par compte et par IP.
- 3 comptes maximum.
- Accès Docker en lecture seule (docker-socket-proxy), conteneur sans root, système de fichiers en lecture seule.
- Secrets chiffrés, jamais renvoyés au navigateur.
- Suppression de `doc.txt`, qui contenait des clés API Brevo (à révoquer : voir `docs/DEPLOIEMENT.md`).

### Migration depuis la v1
Les événements d'attaque sont importés automatiquement. Les comptes ne le sont pas : un nouvel administrateur est créé à l'installation. Détails dans le README.
