# Contribuer à LogSonar

Merci de votre intérêt ! LogSonar est l'œuvre de Naby Sidime (voir `NOTICE`).

## Comment proposer un changement

1. **Forkez** le dépôt, puis créez une branche (`git checkout -b ma-correction`).
2. Faites vos changements et lancez les tests : `pip install -r requirements.txt pytest && pytest -q`.
3. Ouvrez une **pull request** vers `main`. Personne ne pousse directement sur `main` :
   chaque changement est relu et validé par le mainteneur avant d'être fusionné.

## Règles

- **Commits signés** obligatoires (SSH ou GPG) : GitHub doit les afficher « Verified ».
  Guide : https://docs.github.com/fr/authentication/managing-commit-signature-verification
- Les tests doivent passer (vérifiés automatiquement sur chaque pull request).
- Ne retirez pas les en-têtes `SPDX-License-Identifier` et `Copyright` des fichiers.
- Jamais de secret (clé API, mot de passe, jeton) dans le code ou les tests.

En proposant une contribution, vous acceptez qu'elle soit publiée sous la licence MIT du projet.

## Signaler une faille de sécurité

Ne publiez pas de ticket public : utilisez l'onglet **Security → Report a vulnerability** du dépôt.
