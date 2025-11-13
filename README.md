# CIP / KVP Demo Application

This repository contains a lightweight Flask proof-of-concept that re-creates the
legacy Lotus Notes KVP workflow with modern tooling. It focuses on the domain
model, workflows, and admin experiences that were outlined in the specification.

## Features

- Session based authentication with `flask_login` and three roles (`ADMIN`,
  `CREATOR`, `RESPONSIBLE`).
- Master data management for departments, categories, seat types, priorities,
  and users.
- CIP measure CRUD with the complete workflow (draft → report → solution
  proposal → acceptance → implementation → effectiveness evaluation).
- Automatic creation of follow-up measures when an implementation is assessed
  as **not effective**.
- History tracking for each workflow state transition.

## Getting started

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py  # starts the development server on http://localhost:5000
```

After the first start (or whenever you want to reset demo data) hit
`http://localhost:5000/initdb` in your browser. That route rebuilds the SQLite
schema and inserts demo master-data plus users:

- `admin` / `admin`
- `alice` / `alice`
- `bob` / `bob`

## Important routes

| Path | Description |
| --- | --- |
| `/login` | Sign in with one of the demo accounts. |
| `/` | Dashboard that lists measures based on the active role. |
| `/cip/new` | Form for creators/admins to register a new CIP measure. |
| `/cip/<id>` | Detailed view with action buttons determined by the workflow state and role. |
| `/admin` | Entry point for managing reference data and users (admin only). |
| `/initdb` | Recreate the database schema and load demo data. |

## Notes

- Passwords are intentionally stored as clear text to keep the POC simple. Do
  **not** reuse the demo credentials in production environments.
- The UI intentionally relies on inline templates via `render_template_string`
  to align with the minimal POC requirement. The backend is structured so it
  can be migrated to a more sophisticated frontend later.
