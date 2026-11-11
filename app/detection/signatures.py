# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Naby Sidime. LogSonar : https://github.com/NabySidime/LogSonar
"""
Signatures d'attaques.

Chaque règle précise sur quelles « surfaces » elle s'applique :
  url     : chemin + query string décodés d'une requête HTTP
  ua      : User-Agent
  referer : en-tête Referer
  app     : ligne de log applicative (non HTTP)
  body    : corps d'une requête (POST/PUT/PATCH), transmis par le middleware applicatif

Les règles sont volontairement précises : un outil qui crie au loup en permanence
finit ignoré. Pour en ajouter, il suffit d'ajouter une entrée à RULES.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Rule:
    name: str
    severity: str
    pattern: str
    surfaces: frozenset = field(default_factory=lambda: frozenset({"url"}))
    regex: re.Pattern = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self.regex = re.compile(self.pattern, re.IGNORECASE)


def _r(name: str, severity: str, surfaces: set[str], *alternatives: str) -> Rule:
    return Rule(name, severity, "(?:" + "|".join(alternatives) + ")", frozenset(surfaces))


URL = {"url"}
URL_REF = {"url", "referer"}
ALL_HTTP = {"url", "ua", "referer"}
APP = {"app"}
BODY = {"body"}

RULES: list[Rule] = [
    _r("Tentative Log4Shell (Log4J)", "critical", ALL_HTTP | APP | BODY,
       r"\$\{jndi:",
       r"\$\{(?:lower|upper|env|sys|::-)[^}]*\}[^}]*(?:ndi|ldap|rmi)",
       r"jndi:(?:ldaps?|rmi|dns|iiop|corba|nds)://"),

    _r("Tentative d'Injection de Commande", "critical", URL_REF | BODY,
       r"[;|`]\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|ncat|bash|sh|python3?|perl|php)\b(?!\s*=)",
       r"&&\s*(?:cat|ls|id|whoami|uname|wget|curl|ping)\b",
       r"\$\((?:cat|ls|id|whoami|uname|curl|wget|sleep)\b",
       r"\|\s*(?:ba)?sh\b",
       r"/bin/(?:ba)?sh\b",
       r"\bcmd(?:\.exe)?\s*/c\b",
       r"\bpowershell(?:\.exe)?\s+-",
       r"\b(?:system|passthru|shell_exec|popen|proc_open)\s*\(",
       r"\bwget\s+https?://",
       r"\bcurl\s+(?:-\w+\s+)*https?://.*\|\s*(?:ba)?sh"),

    _r("Tentative de Désérialisation Malveillante", "critical", URL_REF | APP | BODY,
       r"rO0AB[A-Za-z0-9+/]{8}",
       r"\baced0005",
       r"O:\d+:\"[A-Za-z_\\]+\":\d+:\{",
       r"__reduce__"),

    _r("Tentative d'Injection SQL", "high", URL_REF | BODY,
       r"\bunion\b(?:\s+all)?\s+select\b",
       r"'\s*(?:or|and)\s+'?\w+'?\s*=\s*'?\w+",
       r"\b(?:or|and)\s+\d+\s*=\s*\d+",
       r"'\s*(?:--|#|/\*)",
       r";\s*(?:drop|truncate|alter)\s+(?:table|database)\b",
       r";\s*(?:insert\s+into|delete\s+from|update\s+\w+\s+set)\b",
       r"\binformation_schema\b",
       r"\b(?:pg_sleep|sleep|benchmark)\s*\(\s*\d",
       r"\bwaitfor\s+delay\b",
       r"\bxp_cmdshell\b",
       r"\b(?:load_file|extractvalue|updatexml)\s*\(",
       r"\binto\s+(?:out|dump)file\b",
       r"\bconcat\s*\(\s*0x[0-9a-f]+"),

    _r("Tentative d'Injection de Template (SSTI)", "high", URL_REF | BODY,
       r"\{\{\s*\d+\s*\*\s*\d+\s*\}\}",
       r"\$\{\s*\d+\s*\*\s*\d+\s*\}",
       r"\{\{[^}]*(?:__class__|__globals__|__builtins__|config\.items|self\._)",
       r"#\{\s*\d+\s*\*\s*\d+\s*\}",
       r"\$\{T\(java"),

    _r("Tentative de SSRF (Falsification de Requête Côté Serveur)", "high", URL | BODY,
       r"169\.254\.169\.254",
       r"metadata\.google\.internal",
       r"100\.100\.100\.200",
       r"=\s*(?:https?://)?(?:127\.\d+\.\d+\.\d+|localhost|0\.0\.0\.0|\[::1?\])(?::\d+)?(?:/|$|&)",
       r"=\s*(?:gopher|dict|file|ldap|tftp)://"),

    _r("Tentative XXE (Injection d'Entité XML)", "high", URL_REF | APP | BODY,
       r"<!(?:DOCTYPE|ENTITY)[^>]+SYSTEM",
       r"<!ENTITY\s+%?\s*\w+\s+SYSTEM"),

    _r("Tentative de Path Traversal", "high", URL | BODY,
       r"(?:\.\.[\\/]){2,}",
       r"\.\.[\\/](?:etc|proc|var|windows|boot|root)\b",
       r"%c0%ae|%c1%9c|%252e%252e",
       r"/etc/(?:passwd|shadow|group|hosts)\b",
       r"/proc/self/(?:environ|cmdline|fd)",
       r"\b(?:c|d):[\\/]+(?:windows|boot\.ini|inetpub)"),

    _r("Tentative de Cross-Site Scripting (XSS)", "medium", URL_REF | BODY,
       r"<\s*script\b",
       r"<\s*/\s*script\s*>",
       r"\bjavascript\s*:",
       r"\bvbscript\s*:",
       r"[\s\"'/<;]on(?:error|load|click|mouse\w+|focus|blur|key\w+|submit|change|input|toggle|animation\w*|pointer\w+)\s*=",
       r"<\s*(?:iframe|frame|embed|object|svg|math|details|marquee)\b[^>]*>",
       r"<\s*img\b[^>]*\bsrc\s*=",
       r"\bdocument\.(?:cookie|domain|write)\b",
       r"\b(?:alert|prompt|confirm)\s*\(\s*['\"\d`/]",
       r"\bdata:text/html"),

    _r("Recherche de fichiers sensibles", "medium", URL,
       r"/\.env(?:\.[\w-]+)?(?:$|[?/])",
       r"/\.git(?:/|$)",
       r"/\.(?:svn|hg|aws|ssh|docker|kube|vscode|idea)/",
       r"/\.(?:htaccess|htpasswd|DS_Store|bash_history|npmrc|pgpass)\b",
       r"/(?:id_rsa|id_dsa|id_ed25519)\b",
       r"/(?:wp-config\.php|config\.php\.bak|settings\.py|database\.yml|secrets\.ya?ml|credentials\.json)",
       r"/[\w.-]*\.(?:sql|sql\.gz|bak|old|swp|backup|dump)(?:$|\?)",
       r"/(?:phpmyadmin|pma|myadmin|adminer)(?:[/.]|$)",
       r"/(?:server-status|server-info)\b",
       r"/vendor/phpunit/",
       r"/(?:wp-login\.php|xmlrpc\.php)",
       r"/actuator/(?:env|heapdump|gateway)"),

    _r("Scan de vulnérabilités (Bot)", "low", {"ua"},
       r"\b(?:sqlmap|nikto|nmap|masscan|zgrab|nuclei|acunetix|wpscan|dirbuster|gobuster|feroxbuster|ffuf|wfuzz|"
       r"hydra|openvas|nessus|w3af|skipfish|zaproxy|whatweb|httpx-toolkit|jaeles|commix|arachni|netsparker|"
       r"l9explore|l9tcpid|CensysInspect|internet-measurement|Expanse)\b",
       r"Nmap Scripting Engine"),

    _r("Scan de vulnérabilités (Bot)", "low", URL,
       r"/(?:HNAP1|boaform|goform|cgi-bin/luci|GponForm|setup\.cgi|tmUnblock\.cgi|hndUnblock\.cgi|device\.rsp)",
       r"/cgi-bin/[\w.-]+\.(?:sh|cgi|pl)",
       r"/(?:shell|cmd|c99|r57|wso)\.php",
       r"/solr/admin/|/jenkins/script|/manager/html|/console/login"),

    _r("Alerte interne de l'application", "medium", APP,
       r"\bSuspiciousOperation\b",
       r"\bDisallowedHost\b",
       r"Invalid HTTP_HOST header",
       r"CSRF (?:verification|token)[^\n]*(?:failed|missing|invalid|incorrect)",
       r"Forbidden \(CSRF",
       r"\bLOGSONAR_POST_ATTACK\b"),

    _r("Échec d'authentification", "low", APP,
       r"Failed password for",
       r"authentication failed for user",
       r"password authentication failed",
       r"Invalid (?:user|credentials|login)",
       r"Access denied for user",
       r"(?:login|authentication) (?:failed|failure)"),
]

# Explications pour le dashboard et les rapports
EXPLANATIONS: dict[str, dict] = {
    "Tentative d'Injection SQL": {
        "what": "Des commandes SQL sont glissées dans l'URL ou un formulaire pour manipuler la base de données : vol de données, contournement de connexion, suppression de tables.",
        "fix": "Utilisez uniquement l'ORM ou des requêtes paramétrées. Ne concaténez jamais une entrée utilisateur dans une requête SQL.",
    },
    "Tentative de Cross-Site Scripting (XSS)": {
        "what": "Injection de JavaScript destiné à s'exécuter dans le navigateur d'un visiteur (vol de session, redirection).",
        "fix": "Échappez toutes les données affichées, activez un en-tête Content-Security-Policy strict.",
    },
    "Tentative de Path Traversal": {
        "what": "Des séquences ../ servent à sortir du dossier web pour lire des fichiers du système.",
        "fix": "Résolvez le chemin (Path.resolve) et vérifiez qu'il reste dans le dossier autorisé.",
    },
    "Tentative d'Injection de Commande": {
        "what": "L'attaquant essaie de faire exécuter des commandes système au serveur (; | $( ) ...).",
        "fix": "Ne passez jamais d'entrée utilisateur à un shell (subprocess avec shell=True, os.system).",
    },
    "Tentative Log4Shell (Log4J)": {
        "what": "Exploitation de la CVE-2021-44228 : une chaîne ${jndi:...} force le serveur à charger du code distant.",
        "fix": "Mettez Log4j à jour (2.17.1 minimum). Même sans Java, ces requêtes signalent un scan actif.",
    },
    "Tentative de SSRF (Falsification de Requête Côté Serveur)": {
        "what": "L'attaquant pousse le serveur à appeler une adresse interne (métadonnées cloud, services internes).",
        "fix": "Filtrez les URLs fournies par l'utilisateur et bloquez les plages privées en sortie.",
    },
    "Tentative XXE (Injection d'Entité XML)": {
        "what": "Une entité XML externe tente de faire lire un fichier local au parseur XML.",
        "fix": "Désactivez les entités externes (en Python : defusedxml).",
    },
    "Tentative de Redirection Ouverte": {
        "what": "Un paramètre de redirection pointe vers un domaine externe, utile pour du phishing sous votre nom.",
        "fix": "N'autorisez que des redirections relatives ou vers une liste blanche de domaines.",
    },
    "Scan de vulnérabilités (Bot)": {
        "what": "Un outil automatique cartographie votre serveur à la recherche de failles connues.",
        "fix": "Bloquez les IP récidivistes (Fail2Ban, CrowdSec) et masquez les en-têtes de version.",
    },
    "Recherche de fichiers sensibles": {
        "what": "Recherche de fichiers oubliés en production : .env, .git, sauvegardes SQL, configs.",
        "fix": "Bloquez ces chemins dans le reverse proxy (return 404). Une réponse 200 ici est une fuite.",
    },
    "Alerte interne de l'application": {
        "what": "L'application a elle-même signalé une opération suspecte (hôte invalide, CSRF, etc.).",
        "fix": "Consultez la requête qui a déclenché l'erreur dans les logs de l'application.",
    },
    "Tentative d'Injection de Template (SSTI)": {
        "what": "Des expressions de template ({{7*7}}) testent si le moteur de rendu exécute du code.",
        "fix": "Ne construisez jamais un template à partir d'une entrée utilisateur.",
    },
    "Tentative de Désérialisation Malveillante": {
        "what": "Des données sérialisées piégées (Java, PHP, pickle) visent une exécution de code.",
        "fix": "Ne désérialisez jamais de données non fiables avec pickle ou équivalent. Utilisez JSON.",
    },
    "Fichier sensible exposé": {
        "what": "Un fichier sensible (.env, .git, sauvegarde...) a été demandé ET servi avec succès (HTTP 200) : son contenu a probablement fuité.",
        "fix": "Bloquez le chemin immédiatement, puis changez tous les secrets que ce fichier contenait.",
    },
    "Échec d'authentification": {
        "what": "Des connexions échouent sur un service (SSH, base de données, application).",
        "fix": "Si cela se répète depuis la même IP, c'est une attaque par force brute : bloquez-la.",
    },
    "Force brute": {
        "what": "Une même IP envoie énormément de requêtes vers la même URL (souvent une page de connexion).",
        "fix": "Ajoutez une limite de débit sur cette URL et bannissez l'IP.",
    },
    "Flood": {
        "what": "Une même IP envoie un volume anormal de requêtes : scraping agressif ou début de déni de service.",
        "fix": "Activez une limite de débit dans le reverse proxy (limit_req dans Nginx).",
    },
}
