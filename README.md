# CIP / KVP Workflow POC

This repository contains a Flask + SQLite proof of concept that recreates the
legacy KVP tooling with modern authentication, workflow, logging, and
collaboration features. / Dieses Repository enthält einen Flask- +
SQLite-Prototyp, der die alte KVP-Lösung mit moderner Authentifizierung,
Workflow-, Logging- und Kollaborationslogik nachbildet.

## Key features / Hauptfunktionen

- Session-based authentication with `flask_login` plus password hashing via
  `werkzeug.security` and CSRF protection from `Flask-WTF`. / Sitzungsgestützte
  Authentifizierung mit `flask_login` sowie Passwort-Hashing über
  `werkzeug.security` und CSRF-Schutz durch `Flask-WTF`.
- Inline admin screens to curate departments, categories, seat types,
  priorities, and users. / Admin-Oberflächen zur Pflege von Abteilungen,
  Kategorien, Sitztypen, Prioritäten und Benutzern.
- Complete CIP workflow from draft to closure, including reporting, solution
  proposal, accept/reject, implementation, and effectiveness review. / Voller
  CIP-Workflow vom Entwurf bis zum Abschluss inklusive Meldung,
  Lösungsvorschlag, Freigabe/Ablehnung, Umsetzung und Wirksamkeitsbewertung.
- Draft-specific edit & cancel endpoints so creators can iterate safely before
  reporting. / Entwurfs-bezogene Bearbeiten- und Storno-Endpunkte, damit
  Antragsteller vor der Meldung sicher iterieren können.
- Dashboard filters (status, priority, department, text) and pagination to slice
  large backlogs. / Dashboard-Filter (Status, Priorität, Abteilung, Text) plus
  Pagination, um große Backlogs bequem zu durchsuchen.
- Automatic follow-up CIP creation when an implementation is not effective. /
  Automatische Folge-CIPs, wenn eine Maßnahme nicht wirksam ist.
- Workflow history tracking with `CIPMeasureHistory`. / Workflow-Historie mit
  `CIPMeasureHistory`.
- Task and request module so teams can assign work, share updates, and respond
  inline. / Aufgaben- und Anfrage-Modul, damit Teams Arbeit zuweisen, Updates
  teilen und direkt antworten können.
- Global audit log that lists every workflow or task action for transparency. /
  Globales Audit-Log, das jeden Workflow- oder Aufgaben-Schritt dokumentiert.
- **Self-service onboarding**: public registration, email confirmation tokens,
  and an approval queue handled by the admin mailbox
  `emre.guzel@fkt.com.tr`. / **Self-Service Onboarding**: Öffentliche
  Registrierung, E-Mail-Bestätigungstoken und eine Freigabewarteschlange über
  das Admin-Postfach `emre.guzel@fkt.com.tr`.
- KPI dashboard (open volume, per-department totals, close-time averages,
  recent-intake count). / KPI-Dashboard (offene Vorgänge, Abteilungsanteile,
  durchschnittliche Laufzeiten, Neueinträge der letzten 30 Tage).
- **Bilingual UI**: every button, label, and notification shows English and
  German copy side by side. / **Zweisprachige UI**: alle Buttons, Labels und
  Hinweise erscheinen gleichzeitig auf Englisch und Deutsch.

## Setup / Einrichtung

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py  # development server on http://localhost:5000
```

Open `http://localhost:5000/initdb` after the first run (or whenever you need
fresh demo data). It resets the SQLite schema and loads demo roles, master data,
and these users / Öffnen Sie `http://localhost:5000/initdb` nach dem ersten
Start (oder wann immer Demodaten benötigt werden). Dadurch wird das SQLite-
Schema zurückgesetzt und folgende Demo-Nutzer geladen:

- `admin` / `admin` (email `emre.guzel@fkt.com.tr` – approves registrations)
- `alice` / `alice`
- `bob` / `bob`

## Important routes / Wichtige Routen

| Route | Description / Beschreibung |
| --- | --- |
| `/login` | Sign in with the demo accounts / Anmeldung mit den Demobenutzern. |
| `/register` | Public registration with email confirmation / Öffentliche Registrierung inkl. E-Mail-Bestätigung. |
| `/confirm/<token>` | Link inside the confirmation "email" (logged for the POC) / Link in der Bestätigungs-"E-Mail" (im Log protokolliert). |
| `/` | Dashboard filtered by the active role (with filters & pagination) / Übersicht nach aktueller Rolle (inkl. Filter & Pagination). |
| `/cip/new` | Create a new CIP (CREATOR or ADMIN) / Neuen CIP anlegen (CREATOR oder ADMIN). |
| `/cip/<id>/edit` | Edit a DRAFT CIP before reporting / Entwurfs-CIP vor dem Melden bearbeiten. |
| `/cip/<id>` | CIP detail view with workflow actions and tasks / CIP-Details mit Workflow-Aktionen und Aufgaben. |
| `/kpi` | KPI cards for open counts, close-time averages, and department mix / KPI-Karten für offene Vorgänge, Durchlaufzeit und Abteilungsanteile. |
| `/logs` | System log with the latest 200 entries / Systemprotokoll mit den letzten 200 Einträgen. |
| `/admin` | Admin area for reference data and users / Verwaltungsbereich für Stammdaten und Benutzer. |
| `/admin/approvals` | Queue where admins approve confirmed users / Warteschlange, in der Admins bestätigte Nutzer freigeben. |
| `/initdb` | Reset the database and demo data / Datenbank und Demodaten zurücksetzen. |

## Self-service onboarding / Selbstregistrierung

1. Users visit `/register`, enter username/email/password, and receive a
   confirmation link (recorded in the system log for the demo). / Nutzer öffnen
   `/register`, geben Benutzername/E-Mail/Passwort ein und erhalten einen
   Bestätigungslink (im Systemlog dokumentiert).
2. The `/confirm/<token>` link marks their email as verified and notifies the
   administrator mailbox (`emre.guzel@fkt.com.tr` by default). / Der Link
   `/confirm/<token>` bestätigt die E-Mail-Adresse und informiert das
   Administrator-Postfach (standardmäßig `emre.guzel@fkt.com.tr`).
3. Admins open `/admin/approvals` to review and approve pending users; once
   approved, the requester can log in. / Admins rufen `/admin/approvals` auf,
   prüfen offene Anträge und geben Nutzer frei; danach ist die Anmeldung
   möglich.

## Logging and collaboration / Logging und Zusammenarbeit

- Every critical event (creation, reporting, solution decisions, implementation,
  effectiveness results, and task updates) is persisted to the `SystemLog`
  table. View them through `/logs`. / Jeder kritische Schritt (Erstellung,
  Meldung, Lösungsentscheidungen, Umsetzung, Wirksamkeitsbewertung und
  Aufgaben-Updates) wird im `SystemLog` gespeichert und ist über `/logs`
  einsehbar.
- The "Tasks and Requests / Aufgaben und Anfragen" section on each CIP detail
  page lets teams assign work, respond inline, and keep everything auditable. /
  Der Bereich "Tasks and Requests / Aufgaben und Anfragen" auf jeder CIP-Seite
  erlaubt es Teams, Aufgaben zuzuweisen, direkt zu antworten und alle Schritte
  nachvollziehbar zu halten.
- "Emails" (confirmation links and approval notices) are simulated by log
  entries so every notification remains auditable without a live SMTP server. /
  "E-Mails" (Bestätigungslinks und Freigabebenachrichtigungen) werden als
  Logeinträge simuliert, damit alle Hinweise ohne SMTP-Server nachvollziehbar
  bleiben.

## Notes / Hinweise

- Passwords are hashed with Werkzeug and every form carries a CSRF token so the
  demo already mirrors production-grade security defaults. / Passwörter werden
  mit Werkzeug gehasht und jedes Formular enthält ein CSRF-Token – die Demo
  spiegelt somit produktionsreife Sicherheits-Defaults wider.
- The default approval mailbox is `emre.guzel@fkt.com.tr`; override it with the
  `CIP_APPROVER_EMAIL` environment variable if needed. / Das standardmäßige
  Freigabe-Postfach lautet `emre.guzel@fkt.com.tr`; per `CIP_APPROVER_EMAIL`
  (Umgebungsvariable) kann es angepasst werden.
- The UI is rendered with a single `render_template_string` call so the business
  logic stays in one file; swapping to a dedicated frontend (React, etc.) is
  straightforward later. / Das UI wird per `render_template_string` in einer
  Datei gerendert; ein Wechsel zu einem eigenen Frontend (React usw.) ist später
  problemlos möglich.
