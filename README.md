# ALTCHA for MetForm

[![WordPress](https://img.shields.io/badge/WordPress-6.0%2B-blue?style=flat-square)](https://wordpress.org)
[![PHP](https://img.shields.io/badge/PHP-7.4_%7C_8.0_%7C_8.2-777BB4?style=flat-square)](https://www.php.net)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Spam Protection](https://img.shields.io/badge/Protection-Proof--of--Work-orange?style=flat-square)](https://altcha.org)

DSGVO-konforme, cookielose Spam-Schutz-Integration für MetForm-Formulare in WordPress auf Basis von ALTCHA (Proof-of-Work).


## Problemstellung & Lösung

Klassische CAPTCHA-Lösungen wie Google reCAPTCHA übertragen personenbezogene Daten in Drittstaaten und erfordern oft störende Interaktionen (z. B. Bilderrätsel).

Dieses Plugin integriert das quelloffene ALTCHA-System direkt in den Validierungszyklus von MetForm:
- **DSGVO-konform:** Keine Cookies zur Nachverfolgung, kein Datentransfer an Werbenetzwerke.
- **Proof-of-Work:** Der Client löst im Hintergrund eine kryptografische Challenge, ohne dass die Benutzererfahrung beeinträchtigt wird.
- **Nahtlose Integration:** Klinkt sich in MetForms nativen Validierungsfilter (`mf_after_validation_check`) ein.


## Architektur & Ablauf

```mermaid
sequenceDiagram
    autonumber
    actor Client as Browser
    participant WP as WordPress REST-API
    participant Srv as ALTCHA-Server
    participant Val as MetForm-Validierung

    Client->>WP: GET /wp-json/altcha/v1/challenge
    WP->>Srv: Challenge anfordern (CORS-Proxy)
    Srv-->>WP: Challenge Payload
    WP-->>Client: Challenge Payload
    Note over Client: Proof of Work im Hintergrund berechnen
    Client->>Val: Formular absenden mit Cookie (mf_altcha)
    Val->>Val: Ablaufzeit pruefen
    Val->>Val: Replay-Schutz pruefen (Transients)
    Val->>Val: HMAC-Signatur verifizieren
    Val->>Val: Proof of Work pruefen
    alt Erfolgreich
        Val-->>Client: Formular gespeichert
    else Ungueltig oder Replay
        Val-->>Client: Fehlermeldung
    end
```


## Kernfunktionen

- **REST-API Challenge Proxy (`altcha/v1/challenge`):** Verhindert CORS-Konflikte, indem WordPress die Challenge direkt an den Browser ausliefert.
- **Replay Protection:** Bereits eingereichte Challenges werden temporär via WordPress Transients (`altcha_<hash>`) gespeichert und für Folgeanfragen blockiert.
- **HMAC- & PoW-Validierung:** Serverseitige Verifizierung der Signatur mittels `hash_equals()` zum Schutz vor Timing-Attacken.
- **MetForm-Kompatibilität:** Nutzt den internen Filter `mf_after_validation_check`, sodass Fehlermeldungen direkt im Frontend-Formular gerendert werden.


## Installation & Einrichtung

1. Ordner `altcha-metform` in das Verzeichnis `wp-content/plugins/` kopieren.
2. In der Datei `wp-config.php` den geheimen HMAC-Schlüssel definieren:
   ```php
   define('ALTCHA_HMAC_KEY', 'dein-geheimer-hmac-key');
   ```
3. Plugin im WordPress-Adminbereich unter **Plugins** aktivieren.
4. Die Proxy-URL bei Bedarf in `altcha-metform.php` anpassen (`$altcha_server`).


## Tech Stack

- **PHP 7.4+ / 8.0+** (Hash HMAC, Transients API, REST API)
- **WordPress Plugin API** (Hooks & Filters)
- **MetForm Plugin API**
- **Vanilla JavaScript** (Web Component & State Listener)


## Lizenz

Lizenziert unter der [MIT-Lizenz](LICENSE).
