# 🛡️ Starter Kit CERT — POC

Ce projet est une implémentation personnelle inspirée de l'article **"Déploiement opérationnel d'un starter kit du CERT"** publié dans [MISC n°142](https://connect.ed-diamond.com/misc/misc-142/deploiement-operationnel-d-un-starter-kit-du-cert-retour-d-experience-et-outils-open-source-pour-la-surveillance-proactive).


[![Python](https://img.shields.io/badge/Python-3.12-blue?logo=python&logoColor=white)](https://python.org)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](https://docker.com)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Stable-brightgreen)]()
[![MISC](https://img.shields.io/badge/Inspired%20by-MISC%20N°142-red)]()
[![Author](https://img.shields.io/badge/Author-Skurt0x90-black?logo=github)](https://github.com/Skurt0x90)

---

## Pré-requis

- [Docker](https://docs.docker.com/get-docker/) installé sur votre machine.
- [Docker Compose](https://docs.docker.com/compose/install/) installé (généralement inclus avec Docker Desktop).

---

## Lancement

```bash
cp .env.example .env
sudo docker compose --profile test up --build
```

| Service                 | URL                              | Attendu          |
|:------------------------|:---------------------------------|:-----------------|
| signal_cli              | http://localhost:8080/v1/about   | JSON version     |
| alert_service           | http://localhost:5005/health     | {"status":"ok"}  |
| web_watcher             | http://localhost:5001/health     | {"status":"ok"}  |
| web_watcher data        | http://localhost:5001/api/data   | JSON des sites   |
| vuln_scanner            | http://localhost:5002/health     | {"status":"ok"}  |
| vuln_scanner data       | http://localhost:5002/api/data   | JSON des CVE     |
| ransomware_monitor      | http://localhost:5003/health     | {"status":"ok"}  |
| ransomware_monitor data | http://localhost:5003/api/data   | JSON ransomware  |
| social_monitor          | http://localhost:5004/health     | {"status":"ok"}  |
| social_monitor data     | http://localhost:5004/api/data   | JSON social      |
| dashboard               | http://localhost:8050            | Interface Dash   |
| DVWA                    | http://localhost:8888            | Interface DVWA   |

---
 
## Configuration
 
Copiez `.env.example` en `.env` et renseignez vos valeurs (SMTP, Signal...).
 
La liste des cibles à surveiller se définit dans `data/inputs/targets.txt` :
 
```
# domaine,longitude,latitude,label,scan_mode
exemple.fr,2.3522,48.8566,Paris,passive
monmembre.fr,2.3522,48.8566,Lyon,active
```
 
- `passive` (défaut) — surveillance non intrusive, aucune autorisation requise
- `active` — modules de scan supplémentaires (nmap), **nécessite une convention signée avec le membre**
 
Les sources de surveillance sont configurables via des fichiers plats dans `data/inputs/` :
 
| Fichier                   | Format       | Usage                                  |
|:--------------------------|:-------------|:---------------------------------------|
| `rss_feeds.txt`           | `name\|url`  | Flux RSS CTI/institutionnels surveillés |
| `telegram_channels.txt`   | handle       | Canaux Telegram publics surveillés     |
| `keywords.txt`            | mot-clé      | Termes de corrélation sectorielle      |
| `members.txt`             | domaine      | Membres et sous-traitants surveillés   |
 
Tous ces fichiers acceptent les commentaires (`#`) et les lignes vides.
 
---

## Fonctionnalités

- **Web Watcher** — surveillance de la disponibilité, temps de réponse, SSL, détection de défacement ✅
- **Alerting** — notifications email HTML par cycle ✅ / Signal ⚠️ *(enregistrement du numéro à effectuer manuellement — voir ci-dessous)*
- **Dashboard** — carte Leaflet dark, compteurs globaux, panel vuln, onglets CVE/DNS/typosquats ✅
- **Vuln Scanner** — surveillance de la surface d'attaque ✅
  - Headers HTTP → croisement NVD/CVE ✅
  - Énumération de sous-domaines via crt.sh ✅
  - Vérification SPF / DMARC ✅
  - Détection de typosquatting via dnstwist ✅
  - Scan nmap + CVE sur services exposés (mode `active`) ✅
- **Ransomware Monitor** — veille sur les sites de leak ransomware ✅ clear web (Ransomlive, Ransomlook, Ransomfeed)
- **Social Monitor** — veille OSINT via flux RSS CTI/institutionnels et scraping Telegram public ✅
 
### Ce qui n'est pas implémenté (hors scope de ce POC)
 
| Fonctionnalité | Raison |
|:---|:---|
| Ransomware Monitor — dark web (.onion) | Nécessite un proxy Tor dédié ; les sources clear web couvrent l'essentiel des revendications publiques |
| Social Monitor — Twitter/X | API devenue payante et très restrictive |
| Social Monitor — HaveIBeenPwned | Nécessite une vérification de propriété de domaine par email |
 
---

## Enregistrement Signal *(optionnel)*
 
L'alerting Signal est fonctionnel mais nécessite un enregistrement manuel unique :
 
```bash
# 1. Enregistrer le numéro
docker exec signal_cli signal-cli -u +336XXXXXXXX register
 
# 2. Vérifier avec le code SMS reçu
docker exec signal_cli signal-cli -u +336XXXXXXXX verify CODE
 
# 3. Récupérer l'ID du groupe (créer le groupe sur le téléphone avant)
docker exec signal_cli signal-cli -u +336XXXXXXXX listGroups
 
# 4. Ajouter dans .env
SIGNAL_CLI_GROUP_ID=group.XXXXXXXXXXXXXXXX==
```
 
> ⚠️ L'enregistrement est rate-limited — réessayer après quelques minutes en cas de 429.
 
---

## Tests

Un service DVWA (Damn Vulnerable Web Application) est disponible pour tester le vuln_scanner sur une cible volontairement vulnérable, sans toucher aux vrais membres :

```bash
sudo docker compose --profile test up --build
```

DVWA sera accessible sur http://localhost:8888 et ajouté automatiquement dans les cibles du vuln_scanner en mode `passive` et `active`.

---

## Screenshot

![Map](screenshots/dashboard.png)
![Detail](screenshots/detail.png)
![Help](screenshots/help.png)

---

## Stack

- Python 3.12 / Flask / APScheduler
- Docker / Docker Compose
- Dash / dash-leaflet / dash-mantine-components
- GitHub Actions + Codecov

---

## Licence

MIT