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
- Extended filtering (creator/responsible/risk/favorites) plus Kanban board and
  CSV export options. / Erweiterte Filter (Antragsteller/Verantwortlicher/
  Risiko/Favoriten) sowie Kanban-Board und CSV-Export.
- Automatic follow-up CIP creation when an implementation is not effective. /
  Automatische Folge-CIPs, wenn eine Maßnahme nicht wirksam ist.
- Workflow history tracking with `CIPMeasureHistory`. / Workflow-Historie mit
  `CIPMeasureHistory`.
- SLA monitoring, escalation workflows, risk scoring, and saving projections so
  overdue items are highlighted immediately. / SLA-Überwachung,
  Eskalationsabläufe, Risikobewertung und Einsparungsprognosen sorgen für eine
  sofortige Sichtbarkeit überfälliger Maßnahmen.
- Task and request module so teams can assign work, share updates, and respond
  inline. / Aufgaben- und Anfrage-Modul, damit Teams Arbeit zuweisen, Updates
  teilen und direkt antworten können.
- Attachment uploads, rich templates, threaded comments, and in-app
  notifications keep every artifact inside the CIP record. / Dateiuploads,
  mächtige Vorlagen, Kommentarverläufe und In-App-Benachrichtigungen halten
  alle Artefakte direkt im CIP-Datensatz.
- Meeting agenda tracking, managerial/department access rules with delegate
  support, KPI dashboards, HTML reports, and a lightweight REST API ensure the
  app fits broader governance flows. / Besprechungsagenda,
  Manager-/Abteilungszugriffe mit Vertreterregelung, KPI-Dashboards,
  HTML-Berichte und eine schlanke REST-API integrieren die App in bestehende
  Governance-Abläufe.
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

> **Heads-up / Hinweis:** The server now auto-checks the SQLite schema on
> startup and adds missing columns (risk, savings, escalation, onboarding
> fields, …) so older databases stop raising "no such column" errors. Existing
> data stays untouched, but you can still call `/initdb` for a full refresh. /
> **Info:** Der Server prüft beim Start automatisch das SQLite-Schema und fügt
> fehlende Spalten (Risiko, Einsparungen, Eskalation, Onboarding, …) hinzu,
> sodass ältere Datenbanken keine "no such column"-Fehler mehr auslösen. Die
> bestehenden Daten bleiben unverändert; `/initdb` kann dennoch für einen
> vollständigen Reset genutzt werden.

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
| `/board` | Kanban board grouped by status / Kanban-Board nach Status. |
| `/kpi` | KPI cards for open counts, close-time averages, and department mix / KPI-Karten für offene Vorgänge, Durchlaufzeit und Abteilungsanteile. |
| `/reports` | Monthly/category summaries / Monats- und Kategorienübersichten. |
| `/export/cip` | CSV export aligned with dashboard filters / CSV-Export gemäß Dashboard-Filtern. |
| `/logs` | System log with the latest 200 entries / Systemprotokoll mit den letzten 200 Einträgen. |
| `/notifications` | Personal notifications inbox / Persönlicher Benachrichtigungsbereich. |
| `/meetings` | CIP meeting overview and detail screens / Übersicht und Details zu CIP-Meetings. |
| `/admin` | Admin area for reference data and users / Verwaltungsbereich für Stammdaten und Benutzer. |
| `/admin/approvals` | Queue where admins approve confirmed users / Warteschlange, in der Admins bestätigte Nutzer freigeben. |
| `/admin/sla` | SLA rules / SLA-Regeln. |
| `/admin/templates` | Manage problem-description templates / Vorlagen verwalten. |
| `/admin/audit` | Latest audit log entries / Neueste Audit-Logs. |
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

## 0. GENEL GÖREV TANIMI (Codex’e koyacağın giriş)

You are an expert Python & Flask developer. You will extend an existing Flask+SQLAlchemy + Flask-Login based CIP/KVP web application. Do not break existing features. Keep the app as a single-file Flask app for now, but you may add small helper modules if really necessary. Use the existing style (render_template_string with BASE_TEMPLATE, SQLAlchemy models, Flask routes). For every new feature, update:

- SQLAlchemy models (migrations not needed, we can drop DB in development),
- Flask routes and logic,
- HTML forms inside render_page() calls,
- and keep everything runnable with python app.py.

Aşağıdaki gereksinimleri sırayla uygula.

1. **Dashboard & Kanban / Liste Görünümleri**
   - 1.1 Dashboard filtreleri
     - `/` route’una status (tek veya çoklu), department_id, priority_id, creator_id, responsible_id query parametreleri ekle.
     - Dashboard’da üst kısımda bu filtreleri içeren formu göster (Status, Department, Priority, Creator, Responsible).
     - Backend’de temel query’yi rol bazlı filtrele (ADMIN / CREATOR / RESPONSIBLE mantığı korunacak), ardından gelen filtreleri uygula.
   - 1.2 Kanban Board sayfası
     - `/board` route’u (login_required) ekle.
     - ADMIN tüm kayıtları, CREATOR kendi oluşturduklarını, RESPONSIBLE kendisine atananları görsün.
     - Her sütun bir status (DRAFT, REPORTED, SOLUTION_PROPOSED, SOLUTION_ACCEPTED, IMPLEMENTED, CLOSED_EFFECTIVE, CLOSED_NOT_EFFECTIVE).
     - Kartlar: #id, title, department, priority, due_date (planned_due_date), age.
     - Şimdilik sürükle-bırak yok; ileride JS ile `/cip/<id>/move` POST çağrısı için backend skeleton hazırla.

2. **SLA ve Eskalasyon**
   - 2.1 SLARule modeli ekle (`from_status`, `to_status`, `max_days`). `/admin/sla` CRUD ekranı hazırla.
   - 2.2 check_sla algoritması: CIPMeasureHistory’den geçişleri oku, SOLUTION_PROPOSED yoksa şimdiye kadar geçen süreyi hesapla. Dashboard ve view_cip’te ihlali kırmızı göster.
   - 2.3 Eskalasyon alanları: CIPMeasure’a `escalated_to_id`, `escalated_at`, `escalation_reason` ekle. `/cip/<id>/escalate` POST endpoint’i ile SLA ihlalinde yöneticilere eskalasyon yap.

3. **Risk ve Tasarruf**
   - CIPMeasure’a `risk_impact`, `risk_probability`, `safety_related`, `customer_impact` ekle; `risk_score` property’si olsun.
   - Dashboard’da “Risk score >= X” filtresi desteklensin. Yeni CIP formunda 1–5 select’leri ve checkbox’lar olsun. Detail view’da risk skoru göster.
   - Tasarruf alanları: `expected_saving_per_year`, `saving_currency`, opsiyonel `actual_saving_first_year`. EFFECTIVE kapanışta actual değer girilebilsin. Dashboard’da toplam expected/actual sum özetlenip gösterilsin.

4. **Dosya Ekleri & Şablonlar**
   - CIPAttachment modeli ve `/cip/<id>/attachments` (GET/POST) + `/attachments/<id>/download` rotaları.
   - `uploads/` klasörü için `app.config["UPLOAD_FOLDER"]` kullan.
   - CIPTemplate modeli; `/admin/templates` ile CRUD. Yeni CIP formunda template seçince problem_description alanı pre-fill edilsin.

5. **Yorum Sistemi ve Bildirimler**
   - CIPComment modeli, `/cip/<id>/comment` POST route’u. View sayfasında listele ve yorum formu ekle.
   - Notification modeli + `notify(user, message, link=None)` helper’ı. Status değişimlerinde (REPORTED→responsible, SOLUTION_PROPOSED→creator, SOLUTION_ACCEPTED→responsible, IMPLEMENTED→creator, CLOSED_*→her ikisi) ve yeni yorumlarda karşı tarafa bildirim gönder. Header’da “Notifications (N)” linki, `/notifications` ekranı ve tıklandığında read=True olup linke yönlendirme.

6. **CIP Meeting Modülü**
   - CIPMeeting ve CIPMeetingItem modelleri.
   - `/meetings`, `/meetings/new`, `/meetings/<id>` rotaları: toplantı bilgisi, ilgili CIP’ler ve yeni CIP ekleme formu.
   - CIP view’da ilgili toplantıları listele.

7. **Yetki Modeli ve Delegate**
   - User modeline `department_id` ve `delegate_id` ekle. Yeni rol tipi `MANAGER`.
   - MANAGER kendi departmanındaki tüm CIP’leri görebilsin. CREATOR / RESPONSIBLE kısıtları eskisi gibi.
   - `current_user_is_allowed` helper’ı: RESPONSIBLE ve measure.responsible_id == current_user.delegate_id ise delegate erişimi sağla.
   - Admin kullanıcı yönetim ekranında delegate seçimi sun.

8. **Raporlama & Export**
   - `/export/cip` route’u: dashboard filtreleriyle aynı parametreleri kabul etsin, CSV döndürsün (id, title, status, priority, creator, responsible, departments, dates, risk_score, expected_saving).
   - Dashboard’da “Excel’e aktar” butonu.
   - `/reports` sayfası: aylık açılan CIP sayıları (strftime('%Y-%m', created_at)), kategoriye göre CIP sayısı gibi tablolar.

9. **API & Audit Log**
   - `/api/cip` ve `/api/cip/<id>` GET endpoint’leri; `?token=SECRET` benzeri basit token kontrolü. CIPMeasure’a `to_dict()` ekle.
   - AuditLog modeli; önemli aksiyonlarda (_record_history) kayıt oluştur ve `/admin/audit` ekranında son 100 log’u listele.

10. **Küçük UX İyileştirmeleri**
    - Priority’ye göre renk kodlama (Low→success, Medium→default, High→danger).
    - `planned_due_date` yaklaşınca (<=3 gün) turuncu, geçmişse kırmızı uyarı.
    - Favoriler: CIPFavorite modeli, view_cip’te “⭐ Add to favorites” butonu; dashboard’da “Only favorites” filtresi.

"Bu kodu bozmadan, yukarıdaki gereksinimleri adım adım uygula. Gerekirse feature’ları bölüm bölüm ekle; her commit sonrası kodun çalıştığından emin ol." 
