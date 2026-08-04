# ArborPress 0.2.0 – Stabilitaets-/Konsolidierungs-Checkliste

Stand: 2026-08-05

Ziel: 0.2.0 als belastbares Stabilitaets-Release.
1.0.0 erfolgt erst nach vollstaendig erfuellten Release-Gates.

## 1. Release Gates (Pflicht fuer 1.0.0)

- [ ] Upgrade-/Migrationspfad ueber mehrere Releases nachgewiesen
- [ ] Plugin-API/Manifest-Vertrag als stabil erklaert
- [ ] Betriebshandbuch inkl. Backup/Restore-Drills abgeschlossen
- [ ] Security-Audit-Punkte aus [SECURITY-AUDIT.md](../SECURITY-AUDIT.md) weitgehend abgearbeitet

### Gate A: Upgrade-/Migrationspfad

- [ ] Dokumentierte Upgrade-Pfade: n-2 -> n-1 -> n
- [ ] DB-Migrationen fuer PostgreSQL und MariaDB getestet
- [ ] Rollback-Prozedur dokumentiert und dry-run geprueft
- [ ] Release Notes enthalten Breaking-Change-Abschnitt

Nachweisartefakte:
- [ ] Migrations-Testprotokoll
- [ ] Rollback-Runbook
- [ ] Changelog-Eintrag pro Release

### Gate B: Plugin-API stabilisieren

- [ ] Manifest-Felder versioniert (min_core/compat-Strategie)
- [ ] Capabilities-Liste als semantischer Vertrag dokumentiert
- [ ] Deprecation-Policy fuer Capabilities festgelegt
- [ ] Plugin-Kompatibilitaetstests fuer Referenz-Plugins vorhanden

Nachweisartefakte:
- [ ] API-Vertrag im Dokuordner
- [ ] Testfall fuer inkompatible/fehlende Entry-Points

### Gate C: Betriebshandbuch + DR

- [ ] Standardbetrieb Bare-Metal + Container dokumentiert
- [ ] Backup/Restore PostgreSQL geuebt (pg_dump/pg_restore)
- [ ] Backup/Restore MariaDB geuebt (mysqldump/mysql)
- [ ] Incident-Playbook fuer Login-/WebAuthn-Ausfall dokumentiert

Nachweisartefakte:
- [ ] Runbook mit Befehlen, Dauer, RPO/RTO
- [ ] Letztes Restore-Datum und Ergebnis

### Gate D: Security-Audit-Restpunkte

- [ ] Offene Punkte aus [SECURITY-AUDIT.md](../SECURITY-AUDIT.md) priorisiert
- [ ] Kritische Punkte (High/Critical) auf 0 reduziert
- [ ] Mittlere Punkte mit Frist und Owner versehen

Nachweisartefakte:
- [ ] Audit-Backlog mit Status/Owner/Deadline

## 2. Python-Support-Policy

Gueltig fuer 0.2.x:
- Support: CPython 3.12 bis 3.14
- Produktions-Empfehlung: CPython 3.13 (reifer als 3.14, deutlich moderner als 3.11)
- Aktive Kompatibilitaetspruefung: CPython 3.14 (fruehe Regressionserkennung)
- Mindestversion im Paket: `requires-python >=3.12`

Lebenszyklusregel:
- Eine Python-Version wird spaetestens im naechsten Minor-Release nach Upstream-EOL als "deprecated" markiert.
- Entfernung erfolgt fruehestens ein Minor-Release spaeter, mit Migrationshinweis.

Pruefpunkte pro Release:
- [ ] Testlauf auf 3.12 (Mindestlinie)
- [ ] Testlauf auf 3.13 (empfohlene Produktionslinie)
- [ ] Testlauf auf aktuellster unterstuetzter Version (derzeit 3.14)

Operativer Hinweis (UBI-only Deployments):
- Auf `registry.access.redhat.com` ist derzeit kein `ubi9/python-313` Repository
	verfuegbar; UBI-Container basieren daher vorerst auf Python 3.12.
- Zielbild bleibt: 3.13 als Produktionslinie, sobald die UBI-Basis verfuegbar ist
	oder ein freigegebener interner Build-Standard fuer 3.13 existiert.

## 3. Dependency-Update-Prozess

Prinzip:
- Klasse A (Kern): nur gezielte Major-/Minor-Wechsel, separat geplant
- Klasse B (regelmaessig): monatliche Patchline-Updates innerhalb der Major-Linie
- Klasse C (optional): bei Einsatz im jeweiligen Deployment regelmaessig mitziehen

Taktung:
- Monatlich: Patchline-Update-Zyklus (Aenderungen innerhalb bestehender Range)
- Quartalsweise: Review auf noetige Minor-Anhebungen
- Bei Security-Advisory: ausserplanmaessiges Update

Sonderregel fuer kritische Kernpakete:
- `quart` und `webauthn` Major-Wechsel nur in separatem Hardening-Zweig
- Pflicht: komplette Regressionstests + manueller Auth-Flow-Test

Release-Artefakte:
- `pyproject.toml` mit stabilen Ranges
- `requirements-release.txt` mit validierten exakten Pins

## 4. Entscheidungsmatrix: 0.2.0 vs 1.0.0

0.2.0 ist freigabefaehig, wenn:
- [ ] Alle 0.2.0-Blocker aus den Gates adressiert sind
- [ ] Testsuite stabil gruen bleibt
- [ ] Doku konsistent zu Deploy/Dependencies ist

1.0.0 ist freigabefaehig, wenn:
- [ ] Alle vier Release-Gates oben vollstaendig erfuellt sind
- [ ] Kein High/Critical-Sicherheitsrestpunkt offen ist
- [ ] Upgrade-/Rollback-Prozess in mindestens zwei realen Release-Schritten belegt ist
