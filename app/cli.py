"""
Commandes de secours, à lancer dans le conteneur :

  docker exec -it logsonar python -m app.cli users
  docker exec -it logsonar python -m app.cli reset-2fa <utilisateur>
  docker exec -it logsonar python -m app.cli reset-password <utilisateur>
"""
from __future__ import annotations

import asyncio
import getpass
import sys

from . import db, security


async def _main(argv: list[str]) -> int:
    await db.init_db()
    try:
        if not argv or argv[0] in ("-h", "--help"):
            print(__doc__)
            return 0
        cmd = argv[0]
        if cmd == "users":
            for u in await db.fetchall("SELECT id, username, role, totp_enabled FROM users ORDER BY id"):
                print(f"{u['id']:>3}  {u['username']:<24} {u['role']:<7} 2FA={'oui' if u['totp_enabled'] else 'non'}")
            return 0
        if len(argv) < 2:
            print("Nom d'utilisateur manquant.")
            return 1
        user = await db.fetchone("SELECT * FROM users WHERE username = ?", (argv[1],))
        if not user:
            print("Utilisateur introuvable.")
            return 1
        if cmd == "reset-2fa":
            await db.execute(
                "UPDATE users SET totp_secret = '', totp_enabled = 0, token_version = token_version + 1 WHERE id = ?",
                (user["id"],))
            print("2FA réinitialisée : un nouveau QR code sera proposé à la prochaine connexion.")
            return 0
        if cmd == "reset-password":
            pwd = getpass.getpass("Nouveau mot de passe : ")
            err = security.validate_password(pwd)
            if err:
                print(err)
                return 1
            if pwd != getpass.getpass("Confirmation : "):
                print("Les mots de passe ne correspondent pas.")
                return 1
            await db.execute(
                "UPDATE users SET password_hash = ?, token_version = token_version + 1 WHERE id = ?",
                (security.hash_password(pwd), user["id"]))
            print("Mot de passe modifié.")
            return 0
        print(f"Commande inconnue : {cmd}")
        return 1
    finally:
        await db.close_db()


if __name__ == "__main__":
    sys.exit(asyncio.run(_main(sys.argv[1:])))
