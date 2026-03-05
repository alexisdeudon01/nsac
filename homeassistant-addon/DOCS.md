# NSAC - Network Security Audit Console

## Installation

1. Ajoutez ce repository dans Home Assistant :
   - Settings > Add-ons > Add-on Store > Menu (3 points) > Repositories
   - Ajoutez : `https://github.com/alexisdeudon01/nsac`

2. Installez l'add-on "NSAC - Android Audit Lab"

3. Configurez les options selon vos besoins

4. Demarrez l'add-on

## Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `mobsf_enabled` | `true` | Demarre MobSF au lancement |
| `mitmproxy_enabled` | `true` | Demarre mitmproxy au lancement |
| `auto_start_services` | `true` | Demarrage automatique des services Docker |
| `transparent_proxy` | `false` | Active la redirection iptables au demarrage |

## Pre-requis

- Raspberry Pi 4 ou Pi 5 (4GB+ RAM recommande)
- Home Assistant OS ou Supervised
- Appareil Android connecte via ADB (USB ou WiFi)
- Pour le bypass SSL : appareil roote

## Acces

- **Dashboard NSAC** : port 5000 (ou via le panel HA)
- **MobSF** : port 8000
- **Mitmproxy Web** : port 8081

## Fonctionnalites

- Dashboard temps reel (WebSocket)
- Gestion des containers Docker (start/stop/restart/logs)
- Detection et gestion des appareils ADB
- Audit IPC automatise (composants exported, permissions, deeplinks)
- Frida SSL pinning bypass (universel Android 7+)
- Upload et analyse APK via MobSF
- Proxy transparent avec toggle on/off
- Journal d'evenements en temps reel
