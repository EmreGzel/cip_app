import os
from datetime import datetime
from functools import wraps

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template_string,
    request,
    url_for,
)
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_


app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("CIP_APP_SECRET", "dev-secret")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", "sqlite:///cip.db"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"


WORKFLOW_STATUSES = [
    "DRAFT",
    "REPORTED",
    "SOLUTION_PROPOSED",
    "SOLUTION_ACCEPTED",
    "SOLUTION_REJECTED",
    "IMPLEMENTED",
    "CLOSED_EFFECTIVE",
    "CLOSED_NOT_EFFECTIVE",
]

THEME_TYPES = ["CORRECTION", "OPTIMIZATION"]
EFFECTIVENESS_STATUSES = ["UNKNOWN", "EFFECTIVE", "NOT_EFFECTIVE"]
TASK_STATUS_LABELS = {
    "OPEN": "Open / Offen",
    "IN_PROGRESS": "In Progress / In Bearbeitung",
    "DONE": "Done / Abgeschlossen",
}
TASK_STATUSES = list(TASK_STATUS_LABELS.keys())


def bilingual(en_text, de_text):
    """Return a combined English / German UI string."""

    return f"{en_text} / {de_text}"


class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(32), unique=True, nullable=False)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey("role.id"), nullable=False)

    role = db.relationship("Role", backref=db.backref("users", lazy=True))


class Department(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), unique=True, nullable=False)


class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), unique=True, nullable=False)


class SeatType(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), unique=True, nullable=False)


class Priority(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)


class CIPMeasure(db.Model):
    __tablename__ = "cip_measure"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    problem_description = db.Column(db.Text, nullable=False)
    comments = db.Column(db.Text)
    status = db.Column(db.String(32), default="DRAFT", nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    creator_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    responsible_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    priority_id = db.Column(db.Integer, db.ForeignKey("priority.id"), nullable=False)

    reporting_department_id = db.Column(db.Integer, db.ForeignKey("department.id"))
    responsible_department_id = db.Column(db.Integer, db.ForeignKey("department.id"))
    category_id = db.Column(db.Integer, db.ForeignKey("category.id"))
    seat_type_id = db.Column(db.Integer, db.ForeignKey("seat_type.id"))

    theme_type = db.Column(db.String(32), default="CORRECTION", nullable=False)
    root_cause = db.Column(db.Text)

    attention_list = db.Column(db.Text)

    sofort_needed = db.Column(db.Boolean)
    sofort_action = db.Column(db.Text)
    planned_action = db.Column(db.Text)
    planned_due_date = db.Column(db.Date)
    effectiveness_check_method = db.Column(db.Text)
    effectiveness_check_date = db.Column(db.Date)
    implemented_action = db.Column(db.Text)

    effectiveness_status = db.Column(
        db.String(32), default="UNKNOWN", nullable=False
    )
    effectiveness_comment = db.Column(db.Text)

    parent_measure_id = db.Column(db.Integer, db.ForeignKey("cip_measure.id"))

    creator = db.relationship(
        "User", foreign_keys=[creator_id], backref=db.backref("created_measures", lazy=True)
    )
    responsible = db.relationship(
        "User",
        foreign_keys=[responsible_id],
        backref=db.backref("responsible_measures", lazy=True),
    )
    priority = db.relationship("Priority", backref=db.backref("measures", lazy=True))
    reporting_department = db.relationship(
        "Department",
        foreign_keys=[reporting_department_id],
        backref=db.backref("reporting_measures", lazy=True),
    )
    responsible_department = db.relationship(
        "Department",
        foreign_keys=[responsible_department_id],
        backref=db.backref("responsible_measures", lazy=True),
    )
    category = db.relationship("Category", backref=db.backref("measures", lazy=True))
    seat_type = db.relationship("SeatType", backref=db.backref("measures", lazy=True))
    parent = db.relationship(
        "CIPMeasure",
        remote_side=[id],
        backref=db.backref("children", lazy=True),
    )


class CIPMeasureHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    measure_id = db.Column(db.Integer, db.ForeignKey("cip_measure.id"), nullable=False)
    from_status = db.Column(db.String(32))
    to_status = db.Column(db.String(32), nullable=False)
    changed_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    changed_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    comment = db.Column(db.Text)

    measure = db.relationship("CIPMeasure", backref=db.backref("history", lazy=True))
    changed_by = db.relationship("User")


class SystemLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(64), nullable=False)
    description = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    measure_id = db.Column(db.Integer, db.ForeignKey("cip_measure.id"))

    user = db.relationship("User")
    measure = db.relationship("CIPMeasure")


class CIPTask(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    measure_id = db.Column(
        db.Integer, db.ForeignKey("cip_measure.id"), nullable=False
    )
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    assigned_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    assigned_to_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    status = db.Column(db.String(32), default="OPEN", nullable=False)
    response_note = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    measure = db.relationship("CIPMeasure", backref=db.backref("tasks", lazy=True))
    assigned_by = db.relationship(
        "User", foreign_keys=[assigned_by_id], backref=db.backref("assigned_tasks", lazy=True)
    )
    assigned_to = db.relationship(
        "User", foreign_keys=[assigned_to_id], backref=db.backref("incoming_tasks", lazy=True)
    )


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role.name != "ADMIN":
            abort(403)
        return func(*args, **kwargs)

    return wrapper


def creator_required(measure):
    if current_user.role.name != "CREATOR" or measure.creator_id != current_user.id:
        abort(403)


def responsible_required(measure):
    if (
        current_user.role.name != "RESPONSIBLE"
        or measure.responsible_id != current_user.id
    ) and current_user.role.name != "ADMIN":
        abort(403)


BASE_TEMPLATE = """
<!doctype html>
<html lang=\"en\">
<head>
    <meta charset=\"utf-8\">
    <title>CIP / KVP Tracking System / CIP / KVP Nachverfolgungssystem</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 1.5rem; background: #f7f7f7; }
        header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; }
        nav a { margin-right: 1rem; }
        table { border-collapse: collapse; width: 100%; margin-top: 1rem; background: #fff; }
        th, td { border: 1px solid #ddd; padding: 0.5rem; text-align: left; }
        th { background: #efefef; }
        form { margin-top: 1rem; background: #fff; padding: 1rem; border: 1px solid #ddd; }
        input[type=text], input[type=password], textarea, select, input[type=date] {
            width: 100%; padding: 0.5rem; margin-bottom: 0.5rem; border: 1px solid #ccc;
        }
        .button-row { display: flex; gap: 0.5rem; }
        .tag { display: inline-block; padding: 0.2rem 0.4rem; background: #0074d9; color: #fff; border-radius: 0.2rem; font-size: 0.85rem; }
        .status { font-weight: bold; }
        .flex { display: flex; gap: 2rem; flex-wrap: wrap; }
        .card { background: #fff; padding: 1rem; border: 1px solid #ddd; flex: 1 1 300px; }
        .danger { color: #b22222; }
        .success { color: #0a7d00; }
    </style>
</head>
<body>
    <header>
        <div>
            <strong>CIP / KVP Tracking System / CIP / KVP Nachverfolgungssystem</strong>
            {% if current_user.is_authenticated %}
                <span class=\"tag\">{{ current_user.role.name }}</span>
            {% endif %}
        </div>
        <nav>
            {% if current_user.is_authenticated %}
                <a href=\"{{ url_for('dashboard') }}\">Dashboard / Übersicht</a>
                <a href=\"{{ url_for('new_cip') }}\">New CIP / Neuer CIP</a>
                {% if current_user.role.name == 'ADMIN' %}
                    <a href=\"{{ url_for('admin_panel') }}\">Admin / Verwaltung</a>
                {% endif %}
                <a href=\"{{ url_for('view_logs') }}\">Logs / Protokolle</a>
                <a href=\"{{ url_for('logout') }}\">Logout / Abmelden</a>
            {% else %}
                <a href=\"{{ url_for('login') }}\">Login / Anmelden</a>
            {% endif %}
        </nav>
    </header>
    {% with messages = get_flashed_messages() %}
        {% if messages %}
            <ul>
                {% for message in messages %}
                    <li>{{ message }}</li>
                {% endfor %}
            </ul>
        {% endif %}
    {% endwith %}
    <main>
        {{ body|safe }}
    </main>
</body>
</html>
"""


def render_page(body_template, **context):
    context.setdefault("bilingual", bilingual)
    body = render_template_string(body_template, **context)
    return render_template_string(
        BASE_TEMPLATE,
        body=body,
        current_user=current_user,
        WORKFLOW_STATUSES=WORKFLOW_STATUSES,
        EFFECTIVENESS_STATUSES=EFFECTIVENESS_STATUSES,
        TASK_STATUSES=TASK_STATUSES,
        TASK_STATUS_LABELS=TASK_STATUS_LABELS,
        bilingual=bilingual,
        **context
    )


@app.route("/initdb")
def init_db():
    db.drop_all()
    db.create_all()

    roles = {name: Role(name=name) for name in ["ADMIN", "CREATOR", "RESPONSIBLE"]}
    db.session.add_all(roles.values())

    departments = [
        Department(name="Logistics"),
        Department(name="Production"),
        Department(name="Quality"),
        Department(name="Planning"),
    ]
    categories = [Category(name="Correction"), Category(name="Optimization")]
    seat_types = [SeatType(name="Coach Seat"), SeatType(name="Driver Seat")]
    priorities = [Priority(name="Low"), Priority(name="Medium"), Priority(name="High")]

    db.session.add_all(departments + categories + seat_types + priorities)

    demo_users = [
        User(username="admin", password="admin", role=roles["ADMIN"]),
        User(username="alice", password="alice", role=roles["CREATOR"]),
        User(username="bob", password="bob", role=roles["RESPONSIBLE"]),
    ]
    db.session.add_all(demo_users)
    db.session.commit()
    return (
        bilingual("Database refreshed with demo data", "Datenbank mit Demodaten aktualisiert"),
        200,
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()
        if user and user.password == password:
            login_user(user)
            return redirect(url_for("dashboard"))
        flash(
            bilingual(
                "Invalid username or password",
                "Ungültiger Benutzername oder Passwort",
            )
        )
    return render_page(
        """
        <h1>Sign In / Anmeldung</h1>
        <form method=\"post\">
            <label>Username / Benutzername</label>
            <input type=\"text\" name=\"username\" required>
            <label>Password / Passwort</label>
            <input type=\"password\" name=\"password\" required>
            <button type=\"submit\">Login / Anmelden</button>
        </form>
        """
    )


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def dashboard():
    if current_user.role.name == "ADMIN":
        measures = CIPMeasure.query.order_by(CIPMeasure.created_at.desc()).all()
    elif current_user.role.name == "CREATOR":
        measures = (
            CIPMeasure.query.filter_by(creator_id=current_user.id)
            .order_by(CIPMeasure.created_at.desc())
            .all()
        )
    else:
        measures = (
            CIPMeasure.query.filter_by(responsible_id=current_user.id)
            .order_by(CIPMeasure.created_at.desc())
            .all()
        )
    return render_page(
        """
        <h1>Dashboard / Übersicht</h1>
        <p>{{ measures|length }} CIP record(s) listed / {{ measures|length }} CIP-Datensätze angezeigt.</p>
        <table>
            <tr>
                <th>No</th>
                <th>Title / Titel</th>
                <th>Status / Status</th>
                <th>Priority / Priorität</th>
                <th>Creator / Antragsteller</th>
                <th>Responsible / Verantwortlicher</th>
                <th>Created / Erstellt</th>
            </tr>
            {% for measure in measures %}
            <tr>
                <td><a href=\"{{ url_for('view_cip', measure_id=measure.id) }}\">#{{ measure.id }}</a></td>
                <td>{{ measure.title }}</td>
                <td>{{ measure.status }}</td>
                <td>{{ measure.priority.name if measure.priority else '' }}</td>
                <td>{{ measure.creator.username }}</td>
                <td>{{ measure.responsible.username }}</td>
                <td>{{ measure.created_at.strftime('%Y-%m-%d') }}</td>
            </tr>
            {% endfor %}
        </table>
        """,
        measures=measures,
    )


def _form_options():
    return dict(
        departments=Department.query.order_by(Department.name).all(),
        categories=Category.query.order_by(Category.name).all(),
        seat_types=SeatType.query.order_by(SeatType.name).all(),
        priorities=Priority.query.order_by(Priority.name).all(),
        responsible_users=User.query.join(Role).filter(Role.name == "RESPONSIBLE").all(),
    )


@app.route("/cip/new", methods=["GET", "POST"])
@login_required
def new_cip():
    if current_user.role.name not in ("CREATOR", "ADMIN"):
        abort(403)
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("problem_description", "").strip()
        if not title or not description:
            flash(
                bilingual(
                    "Title and problem description are required",
                    "Titel und Problembeschreibung sind erforderlich",
                )
            )
        else:
            responsible_id = int(request.form.get("responsible_id"))
            priority_id = int(request.form.get("priority_id"))
            reporting_department_id = request.form.get("reporting_department_id") or None
            responsible_department_id = request.form.get("responsible_department_id") or None
            category_id = request.form.get("category_id") or None
            seat_type_id = request.form.get("seat_type_id") or None
            theme_type = request.form.get("theme_type") or "CORRECTION"
            root_cause = request.form.get("root_cause") or None
            attention_list = request.form.get("attention_list") or None

            measure = CIPMeasure(
                title=title,
                problem_description=description,
                creator_id=current_user.id,
                responsible_id=responsible_id,
                priority_id=priority_id,
                reporting_department_id=int(reporting_department_id)
                if reporting_department_id
                else None,
                responsible_department_id=int(responsible_department_id)
                if responsible_department_id
                else None,
                category_id=int(category_id) if category_id else None,
                seat_type_id=int(seat_type_id) if seat_type_id else None,
                theme_type=theme_type,
                root_cause=root_cause,
                attention_list=attention_list,
            )
            db.session.add(measure)
            db.session.flush()
            record_log(
                "CIP_OLUSTURMA",
                bilingual(
                    f"CIP #{measure.id} created",
                    f"CIP #{measure.id} erstellt",
                ),
                measure,
            )
            db.session.commit()
            flash(
                bilingual(
                    f"CIP #{measure.id} created",
                    f"CIP #{measure.id} erstellt",
                )
            )
            return redirect(url_for("view_cip", measure_id=measure.id))
    return render_page(
        """
        <h1>New CIP Record / Neuer CIP-Datensatz</h1>
        <form method=\"post\">
            <label>Title / Titel</label>
            <input type=\"text\" name=\"title\" required>
            <label>Problem Description / Problembeschreibung</label>
            <textarea name=\"problem_description\" rows=\"4\" required></textarea>
            <label>Reporting Department / Meldende Abteilung</label>
            <select name=\"reporting_department_id\">
                <option value=\"\">-</option>
                {% for d in departments %}
                    <option value=\"{{ d.id }}\">{{ d.name }}</option>
                {% endfor %}
            </select>
            <label>Responsible Department / Verantwortliche Abteilung</label>
            <select name=\"responsible_department_id\">
                <option value=\"\">-</option>
                {% for d in departments %}
                    <option value=\"{{ d.id }}\">{{ d.name }}</option>
                {% endfor %}
            </select>
            <label>Category / Kategorie</label>
            <select name=\"category_id\">
                <option value=\"\">-</option>
                {% for c in categories %}
                    <option value=\"{{ c.id }}\">{{ c.name }}</option>
                {% endfor %}
            </select>
            <label>Seat Type / Sitztyp</label>
            <select name=\"seat_type_id\">
                <option value=\"\">-</option>
                {% for s in seat_types %}
                    <option value=\"{{ s.id }}\">{{ s.name }}</option>
                {% endfor %}
            </select>
            <label>Priority / Priorität</label>
            <select name=\"priority_id\" required>
                {% for p in priorities %}
                    <option value=\"{{ p.id }}\" {% if p.name == 'Medium' %}selected{% endif %}>{{ p.name }}</option>
                {% endfor %}
            </select>
            <label>Responsible User / Verantwortlicher Benutzer</label>
            <select name=\"responsible_id\" required>
                {% for user in responsible_users %}
                    <option value=\"{{ user.id }}\">{{ user.username }}</option>
                {% endfor %}
            </select>
            <label>Theme Type / Thema-Art</label>
            <select name=\"theme_type\">
                {% for t in theme_types %}
                    <option value=\"{{ t }}\">{{ t }}</option>
                {% endfor %}
            </select>
            <label>Root Cause / Grundursache</label>
            <textarea name=\"root_cause\" rows=\"3\"></textarea>
            <label>Attention List (semicolon separated) / Verteilerliste (mit Semikolon)</label>
            <input type=\"text\" name=\"attention_list\">
            <button type=\"submit\">Create Record / Datensatz erstellen</button>
        </form>
        """,
        theme_types=THEME_TYPES,
        **_form_options(),
    )


@app.route("/cip/<int:measure_id>")
@login_required
def view_cip(measure_id):
    measure = CIPMeasure.query.get_or_404(measure_id)
    history = (
        CIPMeasureHistory.query.filter_by(measure_id=measure.id)
        .order_by(CIPMeasureHistory.changed_at.desc())
        .all()
    )
    tasks = (
        CIPTask.query.filter_by(measure_id=measure.id)
        .order_by(CIPTask.created_at.asc())
        .all()
    )
    users = User.query.order_by(User.username).all()
    return render_page(
        """
        <h1>CIP #{{ measure.id }} - {{ measure.title }}</h1>
        <div class=\"flex\">
            <div class=\"card\">
                <h3>Key Facts / Kerndaten</h3>
                <p>Status / Status: <span class=\"status\">{{ measure.status }}</span></p>
                <p>Priority / Priorität: {{ measure.priority.name if measure.priority else '-' }}</p>
                <p>Creator / Antragsteller: {{ measure.creator.username }}</p>
                <p>Responsible / Verantwortlicher: {{ measure.responsible.username }}</p>
                <p>Created At / Erstellt am: {{ measure.created_at.strftime('%Y-%m-%d %H:%M') }}</p>
                <p>Reporting Department / Meldende Abteilung: {{ measure.reporting_department.name if measure.reporting_department else '-' }}</p>
                <p>Responsible Department / Verantwortliche Abteilung: {{ measure.responsible_department.name if measure.responsible_department else '-' }}</p>
                <p>Category / Kategorie: {{ measure.category.name if measure.category else '-' }}</p>
                <p>Seat Type / Sitztyp: {{ measure.seat_type.name if measure.seat_type else '-' }}</p>
                <p>Theme Type / Thema-Art: {{ measure.theme_type }}</p>
                <p>Root Cause / Grundursache: {{ measure.root_cause or '-' }}</p>
                <p>Attention List / Verteilerliste: {{ measure.attention_list or '-' }}</p>
                {% if measure.parent %}
                    <p>Parent CIP / Übergeordnet: <a href=\"{{ url_for('view_cip', measure_id=measure.parent.id) }}\">#{{ measure.parent.id }}</a></p>
                {% endif %}
                {% if measure.children %}
                    <p>Follow-up CIP(s) / Folge-CIP(s):
                        {% for child in measure.children %}
                            <a href=\"{{ url_for('view_cip', measure_id=child.id) }}\">#{{ child.id }}</a>
                        {% endfor %}
                    </p>
                {% endif %}
            </div>
            <div class=\"card\">
                <h3>Problem & Comments / Problem & Kommentare</h3>
                <p>{{ measure.problem_description }}</p>
                {% if measure.comments %}
                    <h4>Comments / Kommentare</h4>
                    <p>{{ measure.comments }}</p>
                {% endif %}
            </div>
            <div class=\"card\">
                <h3>Action Plan / Maßnahmenplan</h3>
                <p>Immediate action needed? / Sofortmaßnahme notwendig?: {{ 'Yes / Ja' if measure.sofort_needed else 'No / Nein' }}</p>
                <p>Immediate action / Sofortmaßnahme: {{ measure.sofort_action or '-' }}</p>
                <p>Planned corrective action / Geplante Korrekturmaßnahme: {{ measure.planned_action or '-' }}</p>
                <p>Planned completion / Geplantes Ende: {{ measure.planned_due_date or '-' }}</p>
                <p>Effectiveness check method / Wirksamkeitsprüfung Methode: {{ measure.effectiveness_check_method or '-' }}</p>
                <p>Effectiveness check date / Wirksamkeitsprüfung Termin: {{ measure.effectiveness_check_date or '-' }}</p>
                <p>Implemented action / Umgesetzte Maßnahme: {{ measure.implemented_action or '-' }}</p>
                <p>Effectiveness status / Wirksamkeitsstatus: {{ measure.effectiveness_status }}</p>
                <p>Effectiveness note / Wirksamkeitsnotiz: {{ measure.effectiveness_comment or '-' }}</p>
            </div>
        </div>
        <h2>Workflow History / Workflow-Historie</h2>
        <table>
            <tr><th>From / Von</th><th>To / Nach</th><th>User / Benutzer</th><th>Date / Datum</th><th>Comment / Kommentar</th></tr>
            {% for entry in history %}
                <tr>
                    <td>{{ entry.from_status or '-' }}</td>
                    <td>{{ entry.to_status }}</td>
                    <td>{{ entry.changed_by.username }}</td>
                    <td>{{ entry.changed_at.strftime('%Y-%m-%d %H:%M') }}</td>
                    <td>{{ entry.comment or '-' }}</td>
                </tr>
            {% endfor %}
        </table>

        <h2>Tasks and Requests / Aufgaben und Anfragen</h2>
        {% if tasks %}
        <table>
            <tr><th>Title / Titel</th><th>Requested By / Anfragender</th><th>Assignee / Zuständiger</th><th>Status / Status</th><th>Details / Details</th><th>Response / Antwort</th></tr>
            {% for task in tasks %}
                <tr>
                    <td>{{ task.title }}</td>
                    <td>{{ task.assigned_by.username }}</td>
                    <td>{{ task.assigned_to.username }}</td>
                    <td>{{ TASK_STATUS_LABELS.get(task.status, task.status) }}</td>
                    <td>{{ task.description or '-' }}</td>
                    <td>
                        {% if task.response_note %}
                            <p>{{ task.response_note }}</p>
                        {% else %}
                            <p>-</p>
                        {% endif %}
                        <small>Updated / Aktualisiert: {{ task.updated_at.strftime('%Y-%m-%d %H:%M') }}</small>
                        {% if current_user.role.name == 'ADMIN' or current_user.id == task.assigned_to_id %}
                            <form method=\"post\" action=\"{{ url_for('update_task_status', task_id=task.id) }}\">
                                <label>Update Status / Status aktualisieren</label>
                                <select name=\"status\" required>
                                    {% for status in TASK_STATUSES %}
                                        <option value=\"{{ status }}\" {% if task.status == status %}selected{% endif %}>{{ TASK_STATUS_LABELS.get(status, status) }}</option>
                                    {% endfor %}
                                </select>
                                <label>Response / Antwort</label>
                                <textarea name=\"response_note\" rows=\"2\"></textarea>
                                <button type=\"submit\">Update / Aktualisieren</button>
                            </form>
                        {% endif %}
                    </td>
                </tr>
            {% endfor %}
        </table>
        {% else %}
            <p>No tasks or requests yet / Noch keine Aufgaben oder Anfragen vorhanden.</p>
        {% endif %}

        <h3>Create Task or Request / Aufgabe oder Anfrage erstellen</h3>
        <form method=\"post\" action=\"{{ url_for('create_task', measure_id=measure.id) }}\">
            <label>Title / Titel</label>
            <input type=\"text\" name=\"title\" required>
            <label>Details / Details</label>
            <textarea name=\"description\" rows=\"3\"></textarea>
            <label>Assignee / Zuständiger Benutzer</label>
            <select name=\"assigned_to_id\" required>
                {% for user in all_users %}
                    <option value=\"{{ user.id }}\">{{ user.username }} ({{ user.role.name }})</option>
                {% endfor %}
            </select>
            <button type=\"submit\">Assign Task / Aufgabe zuweisen</button>
        </form>

        {% if current_user.role.name == 'CREATOR' and measure.creator_id == current_user.id and measure.status == 'DRAFT' %}
            <form method=\"post\" action=\"{{ url_for('report_cip', measure_id=measure.id) }}\">
                <h3>Submit CIP Report / CIP melden</h3>
                <button type=\"submit\">Report / Melden</button>
            </form>
        {% endif %}

        {% if current_user.role.name in ['RESPONSIBLE', 'ADMIN'] and measure.responsible_id == current_user.id and measure.status in ['REPORTED', 'SOLUTION_REJECTED'] %}
            <form method=\"post\" action=\"{{ url_for('propose_solution', measure_id=measure.id) }}\">
                <h3>Propose Solution / Lösung vorschlagen</h3>
                <label><input type=\"checkbox\" name=\"sofort_needed\" value=\"1\" {% if measure.sofort_needed %}checked{% endif %}> Immediate action required / Sofortmaßnahme notwendig</label>
                <label>Immediate Action / Sofortmaßnahme</label>
                <textarea name=\"sofort_action\" rows=\"3\">{{ measure.sofort_action or '' }}</textarea>
                <label>Planned Corrective Action / Geplante Korrekturmaßnahme</label>
                <textarea name=\"planned_action\" rows=\"3\">{{ measure.planned_action or '' }}</textarea>
                <label>Planned Completion Date / Geplantes Enddatum</label>
                <input type=\"date\" name=\"planned_due_date\" value=\"{{ measure.planned_due_date }}\">
                <label>Effectiveness Check Method / Wirksamkeitsprüfung Methode</label>
                <textarea name=\"effectiveness_check_method\" rows=\"3\">{{ measure.effectiveness_check_method or '' }}</textarea>
                <label>Effectiveness Check Date / Wirksamkeitsprüfung Termin</label>
                <input type=\"date\" name=\"effectiveness_check_date\" value=\"{{ measure.effectiveness_check_date }}\">
                <button type=\"submit\">Submit Solution / Lösung senden</button>
            </form>
        {% endif %}

        {% if current_user.role.name == 'CREATOR' and measure.creator_id == current_user.id and measure.status == 'SOLUTION_PROPOSED' %}
            <form method=\"post\" action=\"{{ url_for('accept_solution', measure_id=measure.id) }}\">
                <h3>Accept Solution / Lösung akzeptieren</h3>
                <button type=\"submit\">Accept / Akzeptieren</button>
            </form>
            <form method=\"post\" action=\"{{ url_for('reject_solution', measure_id=measure.id) }}\">
                <h3>Reject Solution / Lösung ablehnen</h3>
                <label>Comment / Kommentar</label>
                <textarea name=\"comment\" rows=\"3\"></textarea>
                <button type=\"submit\">Reject / Ablehnen</button>
            </form>
        {% endif %}

        {% if current_user.role.name in ['RESPONSIBLE', 'ADMIN'] and measure.responsible_id == current_user.id and measure.status == 'SOLUTION_ACCEPTED' %}
            <form method=\"post\" action=\"{{ url_for('mark_implemented', measure_id=measure.id) }}\">
                <h3>Mark as Implemented / Als umgesetzt markieren</h3>
                <label>Implemented Action / Umgesetzte Maßnahme</label>
                <textarea name=\"implemented_action\" rows=\"3\">{{ measure.implemented_action or '' }}</textarea>
                <button type=\"submit\">Implemented / Umgesetzt</button>
            </form>
        {% endif %}

        {% if current_user.role.name == 'CREATOR' and measure.creator_id == current_user.id and measure.status == 'IMPLEMENTED' %}
            <form method=\"post\" action=\"{{ url_for('evaluate_effectiveness', measure_id=measure.id) }}\">
                <h3>Effectiveness Review / Wirksamkeitsbewertung</h3>
                <label>Result / Ergebnis</label>
                <select name=\"effectiveness_status\" required>
                    <option value=\"EFFECTIVE\">Effective / Wirksam</option>
                    <option value=\"NOT_EFFECTIVE\">Not Effective / Nicht wirksam</option>
                </select>
                <label>Comment / Kommentar</label>
                <textarea name=\"effectiveness_comment\" rows=\"3\"></textarea>
                <button type=\"submit\">Save Evaluation / Bewertung speichern</button>
            </form>
        {% endif %}
        """,
        measure=measure,
        history=history,
        tasks=tasks,
        all_users=users,
    )


def _parse_date(value):
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError:
        return None


def _record_history(measure, new_status, comment=None):
    entry = CIPMeasureHistory(
        measure_id=measure.id,
        from_status=measure.status,
        to_status=new_status,
        changed_by_id=current_user.id,
        comment=comment,
    )
    measure.status = new_status
    db.session.add(entry)


def record_log(event_type, description, measure=None):
    entry = SystemLog(
        event_type=event_type,
        description=description,
        user_id=current_user.id if current_user.is_authenticated else None,
        measure_id=measure.id if isinstance(measure, CIPMeasure) else measure,
    )
    db.session.add(entry)


@app.post("/cip/<int:measure_id>/report")
@login_required
def report_cip(measure_id):
    measure = CIPMeasure.query.get_or_404(measure_id)
    creator_required(measure)
    if measure.status != "DRAFT":
        flash(
            bilingual(
                "This CIP has already been reported",
                "Dieser CIP wurde bereits gemeldet",
            )
        )
        return redirect(url_for("view_cip", measure_id=measure.id))
    if measure.theme_type == "CORRECTION" and not measure.root_cause:
        flash(
            bilingual(
                "Root cause is required for CORRECTION",
                "Eine Grundursache ist für CORRECTION erforderlich",
            )
        )
        return redirect(url_for("view_cip", measure_id=measure.id))
    _record_history(measure, "REPORTED")
    record_log(
        "CIP_RAPOR",
        bilingual(
            f"CIP #{measure.id} reported",
            f"CIP #{measure.id} gemeldet",
        ),
        measure,
    )
    db.session.commit()
    flash(
        bilingual(
            "CIP reported",
            "CIP gemeldet",
        )
    )
    return redirect(url_for("view_cip", measure_id=measure.id))


@app.post("/cip/<int:measure_id>/propose_solution")
@login_required
def propose_solution(measure_id):
    measure = CIPMeasure.query.get_or_404(measure_id)
    responsible_required(measure)
    if measure.status not in ("REPORTED", "SOLUTION_REJECTED"):
        flash(
            bilingual(
                "Solution proposal cannot be submitted in the current state",
                "Lösungsvorschlag kann im aktuellen Status nicht eingereicht werden",
            )
        )
        return redirect(url_for("view_cip", measure_id=measure.id))
    measure.sofort_needed = bool(request.form.get("sofort_needed"))
    measure.sofort_action = request.form.get("sofort_action") or None
    measure.planned_action = request.form.get("planned_action") or None
    measure.planned_due_date = _parse_date(request.form.get("planned_due_date"))
    measure.effectiveness_check_method = (
        request.form.get("effectiveness_check_method") or None
    )
    measure.effectiveness_check_date = _parse_date(
        request.form.get("effectiveness_check_date")
    )
    _record_history(measure, "SOLUTION_PROPOSED")
    record_log(
        "COZUM_ONERISI",
        bilingual(
            f"{current_user.username} shared a solution for #{measure.id}",
            f"{current_user.username} hat einen Lösungsvorschlag für #{measure.id} geteilt",
        ),
        measure,
    )
    db.session.commit()
    flash(
        bilingual(
            "Solution proposal submitted",
            "Lösungsvorschlag eingereicht",
        )
    )
    return redirect(url_for("view_cip", measure_id=measure.id))


@app.post("/cip/<int:measure_id>/accept")
@login_required
def accept_solution(measure_id):
    measure = CIPMeasure.query.get_or_404(measure_id)
    creator_required(measure)
    if measure.status != "SOLUTION_PROPOSED":
        flash(
            bilingual(
                "Solution proposal is not in the expected state",
                "Der Lösungsvorschlag befindet sich nicht im erwarteten Status",
            )
        )
        return redirect(url_for("view_cip", measure_id=measure.id))
    _record_history(measure, "SOLUTION_ACCEPTED")
    record_log(
        "COZUM_ONAY",
        bilingual(
            f"Solution for #{measure.id} accepted",
            f"Lösung für #{measure.id} akzeptiert",
        ),
        measure,
    )
    db.session.commit()
    flash(
        bilingual(
            "Solution accepted",
            "Lösung akzeptiert",
        )
    )
    return redirect(url_for("view_cip", measure_id=measure.id))


@app.post("/cip/<int:measure_id>/reject")
@login_required
def reject_solution(measure_id):
    measure = CIPMeasure.query.get_or_404(measure_id)
    creator_required(measure)
    if measure.status != "SOLUTION_PROPOSED":
        flash(
            bilingual(
                "Solution proposal is not in the expected state",
                "Der Lösungsvorschlag befindet sich nicht im erwarteten Status",
            )
        )
        return redirect(url_for("view_cip", measure_id=measure.id))
    comment = request.form.get("comment") or bilingual(
        "Revision requested",
        "Überarbeitung angefordert",
    )
    _record_history(measure, "SOLUTION_REJECTED", comment=comment)
    record_log(
        "COZUM_RED",
        bilingual(
            f"Solution for #{measure.id} rejected: {comment}",
            f"Lösung für #{measure.id} abgelehnt: {comment}",
        ),
        measure,
    )
    db.session.commit()
    flash(
        bilingual(
            "Solution rejected",
            "Lösung abgelehnt",
        )
    )
    return redirect(url_for("view_cip", measure_id=measure.id))


@app.post("/cip/<int:measure_id>/implemented")
@login_required
def mark_implemented(measure_id):
    measure = CIPMeasure.query.get_or_404(measure_id)
    responsible_required(measure)
    if measure.status != "SOLUTION_ACCEPTED":
        flash(
            bilingual(
                "This CIP is not yet in implementation phase",
                "Dieser CIP befindet sich noch nicht in der Umsetzungsphase",
            )
        )
        return redirect(url_for("view_cip", measure_id=measure.id))
    implemented_action = request.form.get("implemented_action", "").strip()
    if not implemented_action:
        flash(
            bilingual(
                "Implemented action description is required",
                "Beschreibung der umgesetzten Maßnahme ist erforderlich",
            )
        )
        return redirect(url_for("view_cip", measure_id=measure.id))
    measure.implemented_action = implemented_action
    _record_history(measure, "IMPLEMENTED")
    record_log(
        "UYGULAMA_TAMAM",
        bilingual(
            f"Implementation completed for #{measure.id}",
            f"Umsetzung für #{measure.id} abgeschlossen",
        ),
        measure,
    )
    db.session.commit()
    flash(
        bilingual(
            "Implementation saved",
            "Umsetzung gespeichert",
        )
    )
    return redirect(url_for("view_cip", measure_id=measure.id))


@app.post("/cip/<int:measure_id>/effectiveness")
@login_required
def evaluate_effectiveness(measure_id):
    measure = CIPMeasure.query.get_or_404(measure_id)
    creator_required(measure)
    if measure.status != "IMPLEMENTED":
        flash(
            bilingual(
                "Implementation must be completed before evaluation",
                "Die Umsetzung muss vor der Bewertung abgeschlossen sein",
            )
        )
        return redirect(url_for("view_cip", measure_id=measure.id))
    status = request.form.get("effectiveness_status")
    comment = request.form.get("effectiveness_comment") or None
    if status not in ("EFFECTIVE", "NOT_EFFECTIVE"):
        flash(
            bilingual(
                "Invalid effectiveness selection",
                "Ungültige Wirksamkeitsauswahl",
            )
        )
        return redirect(url_for("view_cip", measure_id=measure.id))
    if status == "NOT_EFFECTIVE" and not comment:
        flash(
            bilingual(
                "Comment is required when selecting not effective",
                "Ein Kommentar ist erforderlich, wenn 'nicht wirksam' gewählt wird",
            )
        )
        return redirect(url_for("view_cip", measure_id=measure.id))
    measure.effectiveness_status = status
    measure.effectiveness_comment = comment

    if status == "EFFECTIVE":
        _record_history(
            measure,
            "CLOSED_EFFECTIVE",
            comment=bilingual("Found effective", "Als wirksam bewertet"),
        )
        record_log(
            "CIP_ETKIN",
            bilingual(
                f"#{measure.id} closed as effective",
                f"#{measure.id} als wirksam abgeschlossen",
            ),
            measure,
        )
        db.session.commit()
        flash(
            bilingual(
                "CIP closed as effective",
                "CIP als wirksam abgeschlossen",
            )
        )
        return redirect(url_for("view_cip", measure_id=measure.id))

    # NOT effective branch
    _record_history(
        measure,
        "CLOSED_NOT_EFFECTIVE",
        comment=comment or bilingual("Not effective", "Nicht wirksam"),
    )
    record_log(
        "CIP_ETKINSIZ",
        bilingual(
            f"#{measure.id} found not effective",
            f"#{measure.id} als nicht wirksam bewertet",
        ),
        measure,
    )

    follow_up = CIPMeasure(
        title=f"Follow-up for CIP #{measure.id} / Folge für CIP #{measure.id}",
        problem_description="",
        creator_id=measure.creator_id,
        responsible_id=measure.responsible_id,
        priority_id=measure.priority_id,
        reporting_department_id=measure.reporting_department_id,
        responsible_department_id=measure.responsible_department_id,
        category_id=measure.category_id,
        seat_type_id=measure.seat_type_id,
        theme_type=measure.theme_type,
        parent=measure,
    )
    db.session.add(follow_up)
    db.session.flush()
    record_log(
        "CIP_TAKIP",
        bilingual(
            f"#{measure.id} not effective, follow-up #{follow_up.id} created",
            f"#{measure.id} nicht wirksam, Folge-CIP #{follow_up.id} erstellt",
        ),
        follow_up,
    )
    db.session.commit()
    flash(
        bilingual(
            f"CIP not effective. Follow-up #{follow_up.id} opened.",
            f"CIP nicht wirksam. Folge-CIP #{follow_up.id} erstellt.",
        )
    )
    return redirect(url_for("view_cip", measure_id=measure.id))


@app.post("/cip/<int:measure_id>/tasks")
@login_required
def create_task(measure_id):
    measure = CIPMeasure.query.get_or_404(measure_id)
    title = request.form.get("title", "").strip()
    assigned_to_id = request.form.get("assigned_to_id")
    if not title or not assigned_to_id:
        flash(
            bilingual(
                "Task title and assignee are required",
                "Aufgabentitel und Zuständiger sind erforderlich",
            )
        )
        return redirect(url_for("view_cip", measure_id=measure.id))
    try:
        assigned_to_id = int(assigned_to_id)
    except (TypeError, ValueError):
        flash(
            bilingual(
                "Invalid user selection",
                "Ungültige Benutzerauswahl",
            )
        )
        return redirect(url_for("view_cip", measure_id=measure.id))
    assigned_to = User.query.get(assigned_to_id)
    if not assigned_to:
        flash(
            bilingual(
                "Selected user not found",
                "Ausgewählter Benutzer nicht gefunden",
            )
        )
        return redirect(url_for("view_cip", measure_id=measure.id))
    task = CIPTask(
        measure_id=measure.id,
        title=title,
        description=request.form.get("description") or None,
        assigned_by_id=current_user.id,
        assigned_to_id=assigned_to.id,
    )
    db.session.add(task)
    db.session.flush()
    record_log(
        "GOREV_OLUSTUR",
        bilingual(
            f"Task #{task.id} for CIP #{measure.id} assigned to {assigned_to.username}",
            f"Aufgabe #{task.id} für CIP #{measure.id} {assigned_to.username} zugewiesen",
        ),
        measure,
    )
    db.session.commit()
    flash(
        bilingual(
            "Task created and shared with the assignee",
            "Aufgabe erstellt und an den Zuständigen übermittelt",
        )
    )
    return redirect(url_for("view_cip", measure_id=measure.id))


@app.post("/tasks/<int:task_id>/status")
@login_required
def update_task_status(task_id):
    task = CIPTask.query.get_or_404(task_id)
    if current_user.role.name != "ADMIN" and task.assigned_to_id != current_user.id:
        abort(403)
    status = request.form.get("status")
    if status not in TASK_STATUSES:
        flash(
            bilingual(
                "Invalid task status selection",
                "Ungültiger Aufgabestatus",
            )
        )
        return redirect(url_for("view_cip", measure_id=task.measure_id))
    task.status = status
    response_note = request.form.get("response_note") or None
    if response_note:
        task.response_note = response_note
    record_log(
        "GOREV_GUNCELLE",
        bilingual(
            f"Task #{task.id} in CIP #{task.measure_id} updated to {status}",
            f"Aufgabe #{task.id} in CIP #{task.measure_id} auf {status} aktualisiert",
        ),
        task.measure,
    )
    db.session.commit()
    flash(
        bilingual(
            "Task updated",
            "Aufgabe aktualisiert",
        )
    )
    return redirect(url_for("view_cip", measure_id=task.measure_id))


@app.route("/logs")
@login_required
def view_logs():
    logs = (
        SystemLog.query.order_by(SystemLog.created_at.desc())
        .limit(200)
        .all()
    )
    return render_page(
        """
        <h1>System Logs / Systemprotokolle</h1>
        <p>Showing {{ logs|length }} recent entries / Anzeige der letzten {{ logs|length }} Protokolleinträge.</p>
        <table>
            <tr><th>Event / Ereignis</th><th>Description / Beschreibung</th><th>User / Benutzer</th><th>CIP</th><th>Date / Datum</th></tr>
            {% for log in logs %}
                <tr>
                    <td>{{ log.event_type }}</td>
                    <td>{{ log.description }}</td>
                    <td>{{ log.user.username if log.user else '-' }}</td>
                    <td>
                        {% if log.measure_id %}
                            <a href=\"{{ url_for('view_cip', measure_id=log.measure_id) }}\">#{{ log.measure_id }}</a>
                        {% else %}
                            -
                        {% endif %}
                    </td>
                    <td>{{ log.created_at.strftime('%Y-%m-%d %H:%M') }}</td>
                </tr>
            {% endfor %}
        </table>
        """,
        logs=logs,
    )


@app.route("/admin")
@login_required
@admin_required
def admin_panel():
    return render_page(
        """
        <h1>Admin Panel / Verwaltungsbereich</h1>
        <ul>
            <li><a href=\"{{ url_for('manage_users') }}\">Users / Benutzer</a></li>
            <li><a href=\"{{ url_for('manage_departments') }}\">Departments / Abteilungen</a></li>
            <li><a href=\"{{ url_for('manage_categories') }}\">Categories / Kategorien</a></li>
            <li><a href=\"{{ url_for('manage_seat_types') }}\">Seat Types / Sitztypen</a></li>
            <li><a href=\"{{ url_for('manage_priorities') }}\">Priorities / Prioritäten</a></li>
        </ul>
        """
    )


def _generic_manage(model, title_en, title_de, endpoint, usage_check):
    title_label = bilingual(title_en, title_de)
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        if name:
            if not model.query.filter_by(name=name).first():
                db.session.add(model(name=name))
                db.session.commit()
                flash(
                    bilingual(
                        f"{title_en} entry added",
                        f"{title_de}-Eintrag erstellt",
                    )
                )
            else:
                flash(
                    bilingual(
                        "Name already exists",
                        "Name ist bereits vorhanden",
                    )
                )
        else:
            flash(
                bilingual(
                    "Name is required",
                    "Name ist erforderlich",
                )
            )
    delete_id = request.args.get("delete")
    if delete_id:
        item = model.query.get(delete_id)
        if item:
            if usage_check(item):
                flash(
                    bilingual(
                        "Cannot delete: record in use",
                        "Löschen nicht möglich: Eintrag wird verwendet",
                    )
                )
            else:
                db.session.delete(item)
                db.session.commit()
                flash(
                    bilingual(
                        "Record deleted",
                        "Eintrag gelöscht",
                    )
                )
    items = model.query.order_by(model.name).all()
    return render_page(
        """
        <h1>{{ title_label }} Admin</h1>
        <form method=\"post\">
            <label>Name / Name</label>
            <input type=\"text\" name=\"name\" required>
            <button type=\"submit\">Add / Hinzufügen</button>
        </form>
        <table>
            <tr><th>Name / Name</th><th>Actions / Aktionen</th></tr>
            {% for item in items %}
                <tr>
                    <td>{{ item.name }}</td>
                    <td><a href=\"{{ url_for(endpoint, delete=item.id) }}\">Delete / Löschen</a></td>
                </tr>
            {% endfor %}
        </table>
        """,
        title_label=title_label,
        items=items,
        endpoint=endpoint,
    )


@app.route("/admin/departments", methods=["GET", "POST"])
@login_required
@admin_required
def manage_departments():
    def usage_check(dept):
        return (
            CIPMeasure.query.filter(
                or_(
                    CIPMeasure.reporting_department_id == dept.id,
                    CIPMeasure.responsible_department_id == dept.id,
                )
            ).count()
            > 0
        )

    return _generic_manage(Department, "Department", "Abteilung", "manage_departments", usage_check)


@app.route("/admin/categories", methods=["GET", "POST"])
@login_required
@admin_required
def manage_categories():
    def usage_check(category):
        return CIPMeasure.query.filter_by(category_id=category.id).count() > 0

    return _generic_manage(Category, "Category", "Kategorie", "manage_categories", usage_check)


@app.route("/admin/seat_types", methods=["GET", "POST"])
@login_required
@admin_required
def manage_seat_types():
    def usage_check(seat_type):
        return CIPMeasure.query.filter_by(seat_type_id=seat_type.id).count() > 0

    return _generic_manage(SeatType, "Seat Type", "Sitztyp", "manage_seat_types", usage_check)


@app.route("/admin/priorities", methods=["GET", "POST"])
@login_required
@admin_required
def manage_priorities():
    def usage_check(priority):
        return CIPMeasure.query.filter_by(priority_id=priority.id).count() > 0

    return _generic_manage(Priority, "Priority", "Priorität", "manage_priorities", usage_check)


@app.route("/admin/users", methods=["GET", "POST"])
@login_required
@admin_required
def manage_users():
    if request.method == "POST":
        action = request.form.get("action")
        if action == "create":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            role_id = request.form.get("role_id")
            if not username or not password or not role_id:
                flash(
                    bilingual(
                        "All fields are required",
                        "Alle Felder sind erforderlich",
                    )
                )
            elif User.query.filter_by(username=username).first():
                flash(
                    bilingual(
                        "Username already exists",
                        "Benutzername existiert bereits",
                    )
                )
            else:
                user = User(username=username, password=password, role_id=int(role_id))
                db.session.add(user)
                db.session.commit()
                flash(
                    bilingual(
                        "User created",
                        "Benutzer erstellt",
                    )
                )
        elif action == "update":
            user_id = int(request.form.get("user_id"))
            user = User.query.get_or_404(user_id)
            role_id = request.form.get("role_id")
            password = request.form.get("password", "")
            if role_id:
                user.role_id = int(role_id)
            if password:
                user.password = password
            db.session.commit()
            flash(
                bilingual(
                    "User updated",
                    "Benutzer aktualisiert",
                )
            )
    delete_id = request.args.get("delete")
    if delete_id:
        user = User.query.get(delete_id)
        if user:
            if user.created_measures or user.responsible_measures:
                flash(
                    bilingual(
                        "Cannot delete user referenced by CIP records",
                        "Benutzer mit CIP-Verknüpfungen kann nicht gelöscht werden",
                    )
                )
            else:
                db.session.delete(user)
                db.session.commit()
                flash(
                    bilingual(
                        "User deleted",
                        "Benutzer gelöscht",
                    )
                )
    users = User.query.order_by(User.username).all()
    roles = Role.query.order_by(Role.name).all()
    return render_page(
        """
        <h1>User Management / Benutzerverwaltung</h1>
        <h2>Create New User / Neuen Benutzer anlegen</h2>
        <form method=\"post\">
            <input type=\"hidden\" name=\"action\" value=\"create\">
            <label>Username / Benutzername</label>
            <input type=\"text\" name=\"username\" required>
            <label>Password / Passwort</label>
            <input type=\"password\" name=\"password\" required>
            <label>Role / Rolle</label>
            <select name=\"role_id\" required>
                {% for role in roles %}
                    <option value=\"{{ role.id }}\">{{ role.name }}</option>
                {% endfor %}
            </select>
            <button type=\"submit\">Create / Erstellen</button>
        </form>
        <h2>Existing Users / Bestehende Benutzer</h2>
        <table>
            <tr><th>Username / Benutzername</th><th>Role / Rolle</th><th>Update / Aktualisieren</th><th>Delete / Löschen</th></tr>
            {% for user in users %}
                <tr>
                    <td>{{ user.username }}</td>
                    <td>{{ user.role.name }}</td>
                    <td>
                        <form method=\"post\">
                            <input type=\"hidden\" name=\"action\" value=\"update\">
                            <input type=\"hidden\" name=\"user_id\" value=\"{{ user.id }}\">
                            <label>Role / Rolle</label>
                            <select name=\"role_id\">
                                {% for role in roles %}
                                    <option value=\"{{ role.id }}\" {% if role.id == user.role_id %}selected{% endif %}>{{ role.name }}</option>
                                {% endfor %}
                            </select>
                            <label>New Password / Neues Passwort</label>
                            <input type=\"password\" name=\"password\" placeholder=\"Leave blank to keep / Leer lassen um zu behalten\">
                            <button type=\"submit\">Update / Aktualisieren</button>
                        </form>
                    </td>
                    <td>
                        {% if user.username not in ['admin', 'alice', 'bob'] %}
                            <a href=\"{{ url_for('manage_users', delete=user.id) }}\">Delete / Löschen</a>
                        {% else %}
                            -
                        {% endif %}
                    </td>
                </tr>
            {% endfor %}
        </table>
        """,
        users=users,
        roles=roles,
    )


@app.errorhandler(403)
def forbidden(_):
    return render_page("<h1>Access denied / Zugriff verweigert</h1>"), 403


@app.errorhandler(404)
def not_found(_):
    return render_page("<h1>Page not found / Seite nicht gefunden</h1>"), 404


with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(debug=True)
