# ArborPress – Sicherheitsevaluierung & Versionsschema

**Datum**: Juli 2026  
**Stand**: ArborPress 0.1.0  
**Status**: Produktionsreife mit empfohlenen Verbesserungen

---

## 📋 Inhaltsverzeichnis

1. [Versionsschema](#versionsschema)
2. [Sicherheitsbewertung nach Kategorie](#sicherheitsbewertung-nach-kategorie)
3. [Abhängigkeiten: Audit & Upgrade-Roadmap](#abhängigkeiten-audit--upgrade-roadmap)
4. [Proxy-Szenarien (nginx/Traefik)](#proxy-szenarien-nginxtraefik)
5. [Priorisierte Handlungsliste](#priorisierte-handlungsliste)

---

## Versionsschema

### Empfehlung: SemVer ohne Vorab-Zeitplan

Versionen werden erst beim Release festgelegt. Bis dahin gelten nur
die branch-internen Labels `alpha`, `beta`, `rc` und `patch-sec`.

**Praktische Regel**:
- `0.x.y` für laufende Entwicklungs- und Stabilisierungsschritte
- `1.0.0` erst, wenn die Kern-Sicherheitsblöcke abgeschlossen und validiert sind
- `x.y.z-sec` nur für kritische, außerplanmäßige Security-Fixes

---

## Sicherheitsbewertung nach Kategorie

### ✅ KATEGORIE 1: Authentifizierung & Kryptographie

**Status**: STARK

#### Implementiert
- ✅ **WebAuthn/FIDO2** (py_webauthn ≥2.5) – Primary Auth
  - W3C Level 3 konform mit allen §5.4-Flags (UV/RK/Attestation)
  - RP-ID-Lock gegen Domain-Wechsel (W3C §5.3)
  - Punycode-Encoding für IDN (IDNA ≥3.10)
- ✅ **Passwort-Hashing** (Argon2-cffi ≥25.1) – Break-Glass
  - Memory: 65MB, Time: 3 Iterationen (gut für 2026)
  - Mit Salt + Pepper aus Secret-Key
- ✅ **HIBP-Check** (Have I Been Pwned) – k-Anonymity
  - Nur erste 5 SHA-1-Chars an API → Zero-Knowledge
  - fail_open bei Timeout (keine Lockouts bei API-Ausfall)
- ✅ **TOTP/HOTP** (pyotp ≥2.9) – MFA
  - SHA-256, 8-12 Sekunden
- ✅ **Break-Glass Codes** – Recovery
  - 16 Base64-kodierte Codes pro Account
- ✅ **Session-Hardening** (Quart)
  - HttpOnly + SameSite=Strict + Secure (bei HTTPS)

**Empfehlungen**:
- [ ] **py_webauthn ≥2.6** prüfen (kann AttestationFormat-Whitelisting haben)
- [ ] **cryptography ≥45.0** regelmäßig tracken (OpenPGP-Key-Ops)

---

### ✅ KATEGORIE 2: Input-Validierung & Output-Encoding

**Status**: GUT (mit kleineren Lücken)

#### Implementiert
- ✅ **SSRF-Guard** (arborpress/core/validators.py)
  - Blocklist private IPs: 10/8, 172.16/12, 192.168/16, 127/8, 169.254/16
  - DNS-Lookup mit Whitelist (public nur)
  - In image_fetch, oEmbed, federation
- ✅ **HTML Sanitization** (Bleach ≥6.2)
  - User-Content (Kommentare, Federation) → Strip tags
  - SVG blockiert in image_fetch + CSP: media-src 'self'
- ✅ **Email Validation** (email-validator ≥2.2)
  - RFC 5321/5322 + IDNA 2008 (Unicode-Domains)
- ✅ **Slug Canonicalization** (python-slugify ≥8.0)
- ✅ **Rate Limiting** (limits ≥5.0)
  - 10/minute auf /auth, /admin/login, /api/register
  - Pro-IP via X-Forwarded-For (bei Proxy)
- ✅ **SQL-Injection-Schutz**
  - SQLAlchemy ORM + Parameterized Queries

**Empfehlungen**:
- [ ] **Pydantic ≥2.11** prüfen (hat Custom Validators für URL-Normalisierung)
- [ ] **bleach ≥6.3** für strengere TAG_WHITELIST erwägen (z. B. video statt iframe)

---

### ✅ KATEGORIE 3: CSRF-Schutz & Session-Management

**Status**: STARK

#### Implementiert
- ✅ **Doppelte CSRF-Abwehr**:
  - 1. Origin/Referer-Header Check (Layer 1)
  - 2. CSRF-Token (Layer 2, secrets.token_hex(32))
- ✅ **Session-Cookie-Hardening**
  - HttpOnly=True (kein JS-Zugriff)
  - SameSite=Strict (nur Same-Site)
  - Secure=True (nur HTTPS bei base_url=https)
- ✅ **Admin-Path-Obscurity**
  - /admin/ konfigurierbar → /admin-xyz/
- ✅ **Step-Up-Sessions**
  - 15 min TTL für sensitive Ops (Rollen, WebAuthn, Federation)
  - Admin 60 min TTL
- ✅ **Session-Invalidation bei Logout**

**Empfehlungen**:
- [ ] **Session-Encryption** (Quart-Cookie-Signing + optional Fernet)
  - Standardmäßig nur SignedSerialization
  - Für Passsensitive Deployments: `SESSION_COOKIE_ENCRYPTION = True`
- [ ] **CSRF-Middleware im Proxy** (nginx: $csrf_token-Var)

---

### ⚠️ KATEGORIE 4: Content Security Policy (CSP) & Header

**Status**: GUT (aber zu permissiv für produktiv)

#### Aktuell
```
default-src 'self';
script-src 'self';
style-src 'self' 'unsafe-inline';    # ← Zu permissiv
img-src 'self' data: https:;         # ← data: URIs erlaubt
media-src 'self';
font-src 'self';
frame-ancestors 'none';
base-uri 'self';
form-action 'self';
```

**Probleme**:
- ⚠️ `style-src 'unsafe-inline'` ermöglicht CSS-Injection (theoretisch low-risk, aber best-practice: Nonce)
- ⚠️ `img-src data:` ermöglicht Daten-Exfiltration via Data-URIs (bei User-Content)
- ❌ Kein HSTS (delegiert an Proxy – OK)
- ❌ Kein Referrer-Policy (konfigurierbar, Standard: strict-origin-when-cross-origin)

**Empfehlungen für Produktiv**:
```
# Phase 1 (v0.2.0)
script-src 'self' 'strict-dynamic';
style-src 'self' 'nonce-{random}';
img-src 'self' https: data: (via Whitelist);
upgrade-insecure-requests;
require-trusted-types-for 'script';  # CSP-3, experimentell

# Phase 2 (v1.0.0)
Entfernen von 'unsafe-inline' komplett
SVG-Rendering über Safe-API (nicht raw)
```

---

### ✅ KATEGORIE 5: HTTP-Header & Proxy-Sicherheit

**Status**: GUT (aber Proxy-Konfiguration entscheidend)

#### Implementiert
```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), ...
Cache-Control: no-store (für /admin, /auth)
Pragma: no-cache
Expires: 0
```

**Probleme**:
- ❌ **HSTS nicht von ArborPress gesetzt** (korrekt – muss vom Proxy kommen)
- ⚠️ **ReverseProxyMiddleware liest X-Forwarded-*-Header**
  - Nur wenn `trusted_proxies > 0` konfiguriert ist
  - **Sicherheitskritisch**: Muss richtig gesetzt sein

---

### ⚠️ KATEGORIE 6: Datenbank-Sicherheit

**Status**: GUT (aber requires korrekte Deployment-Config)

#### Implementiert
- ✅ **SQLAlchemy Async (mit asyncpg/aiomysql)**
  - Connection pooling mit SSL/TLS-Support
- ✅ **DB-Credentials in secrets.toml** (nicht .gitignore'd)
- ✅ **Prepared Statements** (ORM)
- ✅ **Audit-Logging** für sensitive Ops
  - DELETE, Role-Changes, Security-Settings
- ⚠️ **Passwort-Hashing vor DB-Speicher**
  - Aber: Session-Cookies in DB unverschlüsselt
  - **Fix**: Session-Encryption (Quart-Extension)

**Empfehlungen**:
- [ ] **DB-Level Encryption** (PostgreSQL pgcrypto, MySQL AES)
  - Für DSGVO Compliance
- [ ] **Connection-String Validation**
  - `CONFIG_VALIDATOR: ensure db.url != "sqlite:///:memory:"` bei Produktion
- [ ] **Backups mit Verschlüsselung**
  - `pg_dump | gpg -e` oder ähnlich

---

### ❌ KATEGORIE 7: Logging & Monitoring

**Status**: MINIMAL (Lücken in Produktion)

#### Implementiert
- ✅ **Audit-Logging** (arborpress/core/audit.py)
  - User IDs, Timestamps, Actions
  - Aber: **Nicht tamperproof** (könnte in DB manipuliert werden)
- ✅ **Level-basiertes Logging** (INFO, WARNING, ERROR)
- ⚠️ **Syslog-Support** (optional via Handler)
- ❌ **Keine Alerting** auf critical events (RCE, Auth-Fails)
- ❌ **Kein Log-Aggregation** (ELK, Splunk)

**Empfehlungen für Produktiv**:
- [ ] **Immutable Audit-Log**
  - Append-only Tabelle mit Hash-Chain (§12)
  - `CREATE TABLE audit_log_immutable (id SERIAL, hash CHAR(64), prev_hash CHAR(64), data JSON, PRIMARY KEY(id));`
- [ ] **Structured Logging** (JSON-Format)
  ```python
  import structlog
  log.info("user_login_failed", user_id=uid, reason="invalid_webauthn", ip=request.remote_addr)
  ```
- [ ] **Log-Forwarding**
  - Syslog → Splunk/ELK
  - Mit TLS-Verschlüsselung
- [ ] **Real-time Alerting**
  - >5 Failed Auth in 1 min → Alert
  - Role-Escalation → Alert
  - DB-Query-Time >5s → Warning

---

### ⚠️ KATEGORIE 8: Abhängigkeits-Sicherheit

**Status**: UNBEFRIEDIGEND (regelmäßige Audits erforderlich)

#### Kritische Abhängigkeiten & Aktuelle Versionen

| Paket | Aktuell | Sicher bis | Empfehlung | Kategorie |
|-------|---------|-----------|-----------|-----------|
| **quart** | ≥0.20 | 0.20.x | ≥0.20.10 (bugfixes) | CORE |
| **cryptography** | ≥44.0 | 44.0.x | **≥45.0** (OpenSSL-3.x ready) | CRITICAL |
| **sqlalchemy** | ≥2.0.40 | 2.0.x | **≥2.1.0** (Security-Releases) | CRITICAL |
| **asyncpg** | ≥0.31 | 0.31.x | ≥0.31.0 (current) | DB |
| **webauthn** | ≥2.5 | 2.5.x | ≥2.6 (wenn verfügbar) | AUTH |
| **argon2-cffi** | ≥25.1 | 25.1.x | ≥25.2 | AUTH |
| **bleach** | ≥6.2 | 6.2.x | ≥6.3 (Tag-Whitelist) | SECURITY |
| **httpx** | ≥0.28 | 0.28.x | ≥0.29 (TLS-Hardening) | HTTP |
| **idna** | ≥3.10 | 3.10.x | ≥3.11 (Unicode-Fixes) | SECURITY |
| **pydantic** | ≥2.10 | 2.10.x | **≥2.11** (Validators) | CONFIG |

**Sicherheitsmaßnahmen**:
- [ ] **Wöchentliche Dependency Audits**
  ```bash
  pip install safety
  safety check --json > /var/log/arborpress/audit.json
  ```
- [ ] **Renovate/Dependabot** (Auto-PR für Patches)
- [ ] **SBOM-Generierung** (cyclonedx)
  ```bash
  pip install cyclonedx-bom
  cyclonedx-bom -o requirements.sbom.json
  ```

---

### ❌ KATEGORIE 9: Container & Systemsicherheit

**Status**: TEILS (Dockerfile vorhanden, aber hardening nötig)

#### Aktuell (Containerfile.ubuntu)
- ✅ Base Image: `ubuntu:24.04` (LTS, reguläre Updates)
- ⚠️ **Läuft als root** (entrypoint.sh)
- ❌ **Kein Security Context** (umask, read-only fs)
- ❌ **Kein Image Signing** (für Registry)
- ⚠️ **pip install ohne Hash-Check**

**Hardening-Maßnahmen**:
```dockerfile
# Nicht-Root-User
RUN groupadd -r arborpress && useradd -r -g arborpress arborpress
USER arborpress

# Read-Only Filesystem
RUN mount --bind -o remount,ro /

# Security Options (in Compose)
security_opt:
  - no-new-privileges=true
  - seccomp=docker.json
cap_drop:
  - ALL
cap_add:
  - NET_BIND_SERVICE

# Scanning
docker scout cves ./Containerfile.ubuntu
trivy image --severity HIGH,CRITICAL arborpress:latest
```

---

### ⚠️ KATEGORIE 10: Reverse Proxy-Szenarien

**Status**: DOKUMENTIERT (essenzielle Blöcke nur)

#### nginx / Apache2
- Nur diese Blöcke dokumentieren: HTTPS-Redirect, Proxy-Header, Limit/Body-Size, statische Assets, optionales Auth-Rate-Limit.
- Vollständige vHosts sind bewusst nicht mehr Teil der Doku.
- `trusted_proxies` muss den echten Hop-Count widerspiegeln.

Beispielhafte Kernblöcke stehen in [docs/proxy/nginx.conf](docs/proxy/nginx.conf) und [docs/proxy/apache2.conf](docs/proxy/apache2.conf).

#### Traefik
- Labels sind die bevorzugte Betriebsart.
- Dokumentiert werden nur: Router, Middleware, Service, Healthcheck.
- Kein vollständiges `dynamic/*.yml`-Gerüst nötig.

Kernbeispiele stehen in [docs/proxy/traefik.yml](docs/proxy/traefik.yml).

---

## Abhängigkeiten: LTS-/Stabilitätsstrategie

ArborPress folgt bewusst einer **tested-major-line**-Strategie: pro Paket
wird eine aktuell getestete Major-Linie festgelegt und per Upper Bound gegen
unkontrollierte Sprünge abgesichert. Major-Upgrades erfolgen erst, wenn die
gesamte Testmatrix erfolgreich ist.

### Aktuell getestete Linien

| Paket | Getestet | Stabiler Bereich |
|-------|----------|------------------|
| quart | 0.20.0 | `>=0.20,<0.21` |
| hypercorn | 0.18.0 | `>=0.18,<0.19` |
| sqlalchemy | 2.0.49 | `>=2.0.49,<2.1` |
| cryptography | 46.0.6 | `>=46.0,<47` |
| bleach | 6.3.0 | `>=6.3,<7` |
| pydantic | 2.12.5 | `>=2.12,<3` |
| pydantic-settings | 2.13.1 | `>=2.13,<3` |
| httpx | 0.28.1 | `>=0.28,<0.29` |
| idna | 3.11 | `>=3.11,<4` |
| webauthn | 2.7.1 | `>=2.7,<3` |
| argon2-cffi | 25.1.0 | `>=25.1,<26` |
| pyotp | 2.9.0 | `>=2.9,<3` |
| limits | 5.8.0 | `>=5.8,<6` |
| aiosmtplib | 5.1.0 | `>=5.1,<6` |
| babel | 2.18.0 | `>=2.18,<3` |

### Pflege-Regel

- Patch-Updates innerhalb der stabilen Linie sind erwünscht, sobald die
  Tests grün bleiben.
- Major-Upgrades nur nach expliziter Prüfung der betroffenen Oberfläche.
- Wenn ein Paket keine formale LTS-Linie hat, wird die **aktuell getestete
  Major-Linie** als LTS-Ersatz behandelt.

### Beobachtete Upgrade-Kandidaten

- `sqlalchemy 2.1` erst dann anheben, wenn die DB-Tests und die App-Session-
  Pfade ohne Regression laufen.
- `quart 0.21` und `hypercorn 0.19` erst nach einem separaten Web-Stack-
  Durchlauf.
- `pydantic 3` und `httpx 0.29` nur mit gezielter Kompatibilitätsprüfung.

---

## Priorisierte Handlungsliste

### 🔴 KRITISCH (Blocker für v1.0.0)

- [ ] **cryptography ≥45.0** einspielen (OpenSSL-3.x)
  - **Effort**: 1–2h, **Impact**: CRITICAL
  - Befehl: `pip install -U cryptography && pytest`
  
- [ ] **SQL-Injection in Admin-Panel testen** (mit sqlmap)
  - **Effort**: 4h, **Impact**: CRITICAL
  - Befehl: `sqlmap -u "http://localhost:8066/admin/..." --forms`

- [ ] **RP-ID-Lock unter Last testen** (100+ Credentials)
  - **Effort**: 3h, **Impact**: HIGH
  - Scenario: Domain-Wechsel simulieren, verify Lock-State

- [ ] **SSRF-Guard mit realen URLs testen** (AWS IMDS, GCP Metadata)
  - **Effort**: 2h, **Impact**: HIGH
  - Test: `POST /api/v1/image-fetch {"url": "http://169.254.169.254/..."}`

---

### 🟠 HOCH (vor v0.3.0)

- [ ] **CSP-Header von 'unsafe-inline' befreien**
  - Effort: 6–8h, **Impact**: HIGH (XSS-Reduktion)
  - Approach: Nonce-Token für jede Seite generieren

- [ ] **Immutable Audit-Log** implementieren
  - Effort: 8–12h, **Impact**: HIGH (Compliance)
  - Approach: Hash-Chain mit Blake3

- [ ] **Structured Logging (structlog)** einführen
  - Effort: 4–6h, **Impact**: MEDIUM (Observability)

- [ ] **Dependency Scanning** (Safety/Renovate) aufsetzen
  - Effort: 2h, **Impact**: MEDIUM (DevOps)

- [ ] **Container-Hardening** (rootless, read-only, seccomp)
  - Effort: 4–6h, **Impact**: MEDIUM

---

### 🟡 MITTEL (nach v1.0.0)

- [ ] **WAF-Regeln** für nginx/Traefik (ModSecurity)
  - Effort: 6h, **Impact**: MEDIUM
  
- [ ] **API-Rate-Limiting** per Endpoint (nicht global)
  - Effort: 4h, **Impact**: MEDIUM

- [ ] **OAuth2/OIDC-Server** (für Plugins)
  - Effort: 12h, **Impact**: LOW

- [ ] **Penetration Test** (Extern, 1–2 Tage)
  - Effort: 16h (Budget), **Impact**: HIGH (Validierung)

---

### 🟢 NIEDRIG (später)

- [ ] **Fuzzing** (AFL, libfuzzer)
  - Effort: 8h, **Impact**: LOW (preventive)

- [ ] **Hardware Security Key** Support (YubiKey NFC)
  - Effort: 4h, **Impact**: LOW (Niche)

- [ ] **Multi-Signature Commits** (GPG)
  - Effort: 1h, **Impact**: LOW (DevOps)

---

## Proxy-Konfigurationsvorlage

### nginx (docs/proxy/nginx-hardened.conf)

```nginx
upstream arborpress {
    server app:8066;
    keepalive 32;
}

# Rate Limiting
limit_req_zone $binary_remote_addr zone=general:10m rate=100r/m;
limit_req_zone $binary_remote_addr zone=auth:10m rate=10r/m;

server {
    listen 80;
    listen [::]:80;
    server_name blog.example.com;
    
    # Redirect to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name blog.example.com;
    
    # TLS
    ssl_certificate /etc/ssl/certs/blog.example.com.crt;
    ssl_certificate_key /etc/ssl/private/blog.example.com.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:!aNULL:!MD5:!DSS';
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # HSTS
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    
    # CSP + Security Headers (App setzt auch, aber Proxy kann Override)
    add_header Content-Security-Policy "upgrade-insecure-requests; default-src 'self'" always;
    
    # Client Limits
    client_max_body_size 100M;  # Upload-Limit
    client_body_timeout 10s;
    client_header_timeout 10s;
    
    # Real IP (wenn hinter Proxy)
    set_real_ip_from 10.0.0.0/8;      # Docker
    real_ip_header X-Forwarded-For;
    real_ip_recursive on;
    
    # Logging
    access_log /var/log/nginx/arborpress-access.log combined buffer=32k flush=5s;
    error_log /var/log/nginx/arborpress-error.log warn;
    
    location / {
        limit_req zone=general burst=5 nodelay;
        
        proxy_pass http://arborpress;
        proxy_http_version 1.1;
        
        # Headers
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $server_name;
        proxy_set_header Connection "";
        
        # Timeouts
        proxy_connect_timeout 10s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
    }
    
    location /auth/ {
        limit_req zone=auth burst=3 nodelay;
        proxy_pass http://arborpress;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Deny admin access from untrusted IPs (optional)
    location /admin/ {
        allow 203.0.113.0/24;         # Office IP
        allow 198.51.100.5;           # VPN
        allow 10.0.0.0/8;             # Internal
        deny all;
        
        limit_req zone=auth burst=1 nodelay;
        proxy_pass http://arborpress;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Traefik (docs/proxy/traefik-hardened.yml)

```yaml
global:
  checkNewVersion: true
  sendAnonymousUsage: false

api:
  insecure: false
  dashboard: false
  entryPoint: traefik

entryPoints:
  http:
    address: ":80"
    http:
      redirections:
        entrypoint:
          scheme: https
          port: "443"
  https:
    address: ":443"
    http:
      tls:
        certResolver: letsencrypt
  traefik:
    address: "127.0.0.1:8080"

providers:
  docker:
    endpoint: "unix:///var/run/docker.sock"
    exposedByDefault: false
    network: arborpress

certificatesResolvers:
  letsencrypt:
    acme:
      email: admin@example.com
      storage: /etc/traefik/acme.json
      httpChallenge:
        entryPoint: http

middleware:
  security-headers:
    headers:
      sslRedirect: true
      sslHost: blog.example.com
      stsSeconds: 63072000
      stsIncludeSubdomains: true
      stsPreload: true
      contentTypeNosniff: true
      browserXssFilter: true
      referrerPolicy: "strict-origin-when-cross-origin"
      permissionsPolicy: "geolocation=(), microphone=()"

  rate-limit-auth:
    ratelimit:
      average: 10
      period: 60s
      burst: 3
      sourceCriterion:
        requestHeaderName: X-Forwarded-For

  rate-limit-general:
    ratelimit:
      average: 100
      period: 60s
      burst: 10
      sourceCriterion:
        requestHeaderName: X-Forwarded-For

  compress:
    compress:
      excludedContentTypes: image/png,image/jpeg

routers:
  arborpress-http:
    entryPoints: http
    rule: "Host(`blog.example.com`)"
    service: arborpress
    middlewares:
      - compress

  arborpress:
    entryPoints: https
    rule: "Host(`blog.example.com`)"
    service: arborpress
    middlewares:
      - security-headers
      - rate-limit-general
      - compress
    tls:
      certResolver: letsencrypt

  arborpress-auth:
    entryPoints: https
    rule: "Host(`blog.example.com`) && PathPrefix(`/auth/`)"
    service: arborpress
    middlewares:
      - security-headers
      - rate-limit-auth
    tls:
      certResolver: letsencrypt

  arborpress-admin:
    entryPoints: https
    rule: "Host(`blog.example.com`) && PathPrefix(`/admin/`)"
    service: arborpress
    middlewares:
      - security-headers
      - rate-limit-auth
    tls:
      certResolver: letsencrypt

services:
  arborpress:
    loadBalancer:
      servers:
        - url: "http://app:8066"
      passHostHeader: true
      healthCheck:
        scheme: http
        path: /
        interval: 10s
        timeout: 5s
```

---

## Checkliste für Go-Live (v1.0.0)

- [ ] Security Headers vollständig konfiguriert (nginx/Traefik)
- [ ] HTTPS mit HSTS 1 Jahr, preload
- [ ] Admin-Path nicht /admin (z. B. /admin-xyz-12345/)
- [ ] Rate Limiting auf alle Auth-Endpunkte
- [ ] Audit-Logging aktiviert + täglich exportiert
- [ ] DB-Backups verschlüsselt + gelagert (3-2-1-Regel)
- [ ] Dependencies aktuell (pip-audit clean)
- [ ] Logging an zentrale Stelle (Syslog/ELK)
- [ ] Alerting: >5 Auth-Fails/min → Notification
- [ ] Penetration Test durch externe Firma
- [ ] SBOM generiert + versioniert
- [ ] Incident-Response-Plan dokumentiert

---

**Nächster Schritt**: Bitte wähle eine der Kategorien (1–10) oder eine Prio-Stufe aus, um konkrete Implementierung zu starten.
