import os
import secrets
from datetime import datetime, timedelta
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
from sqlalchemy import func, or_
from flask_wtf import CSRFProtect
from flask_wtf.csrf import generate_csrf
from werkzeug.security import check_password_hash, generate_password_hash


app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("CIP_APP_SECRET", "dev-secret")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", "sqlite:///cip.db"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

ADMIN_APPROVER_EMAIL = os.environ.get("CIP_APPROVER_EMAIL", "emre.guzel@fkt.com.tr")

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
csrf = CSRFProtect(app)


WORKFLOW_STATUSES = [
    "DRAFT",
    "REPORTED",
    "SOLUTION_PROPOSED",
    "SOLUTION_ACCEPTED",
    "SOLUTION_REJECTED",
    "IMPLEMENTED",
    "CLOSED_EFFECTIVE",
    "CLOSED_NOT_EFFECTIVE",
    "CANCELLED",
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

FIELD_LABELS = {
    "root_cause": bilingual("root cause", "Grund"),
    "planned_action": bilingual("planned action", "geplante Maßnahme"),
    "planned_due_date": bilingual("planned due date", "geplantes Datum"),
    "implemented_action": bilingual("implemented action", "umgesetzte Maßnahme"),
    "effectiveness_status": bilingual(
        "effectiveness result",
        "Wirksamkeitsergebnis",
    ),
    "effectiveness_comment": bilingual(
        "effectiveness comment",
        "Wirksamkeitskommentar",
    ),
}

STATUS_REQUIREMENTS = {
    "REPORTED": ["root_cause"],
    "SOLUTION_PROPOSED": ["planned_action", "planned_due_date"],
    "IMPLEMENTED": ["implemented_action"],
    "CLOSED_EFFECTIVE": ["effectiveness_status"],
    "CLOSED_NOT_EFFECTIVE": ["effectiveness_status", "effectiveness_comment"],
}

STATUS_TIMESTAMPS = {
    "REPORTED": "reported_at",
    "SOLUTION_PROPOSED": "solution_proposed_at",
    "SOLUTION_ACCEPTED": "solution_accepted_at",
    "IMPLEMENTED": "implemented_at",
    "CLOSED_EFFECTIVE": "closed_at",
    "CLOSED_NOT_EFFECTIVE": "closed_at",
    "CANCELLED": "closed_at",
}


def _is_admin(user):
    return user.role.name == "ADMIN"


def _is_creator(user, measure):
    return measure is not None and measure.creator_id == user.id


def _is_responsible(user, measure):
    return measure is not None and measure.responsible_id == user.id


def _can_view_measure(user, measure):
    return measure is not None and (
        _is_admin(user) or _is_creator(user, measure) or _is_responsible(user, measure)
    )


PERMISSION_MATRIX = {
    "admin": lambda user, **ctx: _is_admin(user),
    "create_cip": lambda user, **ctx: user.role.name in ("CREATOR", "ADMIN"),
    "view_measure": lambda user, measure=None, **ctx: _can_view_measure(user, measure),
    "edit_draft": lambda user, measure=None, **ctx: measure
    and measure.status == "DRAFT"
    and (_is_admin(user) or (_is_creator(user, measure) and user.role.name == "CREATOR")),
    "report": lambda user, measure=None, **ctx: measure
    and measure.status == "DRAFT"
    and (_is_admin(user) or (_is_creator(user, measure) and user.role.name == "CREATOR")),
    "cancel": lambda user, measure=None, **ctx: measure
    and measure.status == "DRAFT"
    and (_is_admin(user) or (_is_creator(user, measure) and user.role.name == "CREATOR")),
    "propose_solution": lambda user, measure=None, **ctx: measure
    and measure.status in ("REPORTED", "SOLUTION_REJECTED")
    and (_is_admin(user) or (_is_responsible(user, measure) and user.role.name == "RESPONSIBLE")),
    "accept_solution": lambda user, measure=None, **ctx: measure
    and measure.status == "SOLUTION_PROPOSED"
    and (_is_admin(user) or (_is_creator(user, measure) and user.role.name == "CREATOR")),
    "reject_solution": lambda user, measure=None, **ctx: measure
    and measure.status == "SOLUTION_PROPOSED"
    and (_is_admin(user) or (_is_creator(user, measure) and user.role.name == "CREATOR")),
    "mark_implemented": lambda user, measure=None, **ctx: measure
    and measure.status == "SOLUTION_ACCEPTED"
    and (_is_admin(user) or (_is_responsible(user, measure) and user.role.name == "RESPONSIBLE")),
    "evaluate_effectiveness": lambda user, measure=None, **ctx: measure
    and measure.status == "IMPLEMENTED"
    and (_is_admin(user) or (_is_creator(user, measure) and user.role.name == "CREATOR")),
    "view_logs": lambda user, **ctx: user.is_authenticated,
    "view_kpi": lambda user, **ctx: user.is_authenticated,
    "create_task": lambda user, measure=None, **ctx: _can_view_measure(user, measure),
    "update_task_status": lambda user, task=None, **ctx: task
    and (user.role.name == "ADMIN" or task.assigned_to_id == user.id),
}


def can_do(user, action, **context):
    if not user or not user.is_authenticated:
        return False
    rule = PERMISSION_MATRIX.get(action)
    if not rule:
        return False
    return bool(rule(user, **context))


class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(32), unique=True, nullable=False)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey("role.id"), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    is_email_confirmed = db.Column(db.Boolean, default=False, nullable=False)
    requires_approval = db.Column(db.Boolean, default=True, nullable=False)
    approved_by_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    approved_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    role = db.relationship("Role", backref=db.backref("users", lazy=True))
    approved_by = db.relationship(
        "User",
        remote_side=[id],
        foreign_keys=[approved_by_id],
        backref=db.backref("approved_users", lazy=True),
    )

    @property
    def is_active(self):
        return self.is_email_confirmed and (
            not self.requires_approval or self.approved_at is not None
        )


class Department(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), unique=True, nullable=False)


class EmailVerificationToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    token = db.Column(db.String(255), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    used_at = db.Column(db.DateTime)

    user = db.relationship("User", backref=db.backref("email_tokens", lazy=True))


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
    reported_at = db.Column(db.DateTime)
    solution_proposed_at = db.Column(db.DateTime)
    solution_accepted_at = db.Column(db.DateTime)
    implemented_at = db.Column(db.DateTime)
    closed_at = db.Column(db.DateTime)

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
        if not can_do(current_user, "admin"):
            abort(403)
        return func(*args, **kwargs)

    return wrapper


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
                {% if can_do(current_user, 'create_cip') %}
                    <a href=\"{{ url_for('new_cip') }}\">New CIP / Neuer CIP</a>
                {% endif %}
                {% if can_do(current_user, 'admin') %}
                    <a href=\"{{ url_for('admin_panel') }}\">Admin / Verwaltung</a>
                {% endif %}
                <a href=\"{{ url_for('kpi_dashboard') }}\">KPI</a>
                <a href=\"{{ url_for('view_logs') }}\">Logs / Protokolle</a>
                <a href=\"{{ url_for('logout') }}\">Logout / Abmelden</a>
            {% else %}
                <a href=\"{{ url_for('login') }}\">Login / Anmelden</a>
                <a href=\"{{ url_for('register') }}\">Register / Registrieren</a>
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
        can_do=can_do,
        **context
    )


@app.context_processor
def inject_csrf():
    return {"csrf_token": generate_csrf}


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

    now = datetime.utcnow()
    demo_users = [
        User(
            username="admin",
            email=ADMIN_APPROVER_EMAIL,
            password=generate_password_hash("admin"),
            role=roles["ADMIN"],
            is_email_confirmed=True,
            requires_approval=False,
            approved_at=now,
            created_at=now,
        ),
        User(
            username="alice",
            email="alice@example.com",
            password=generate_password_hash("alice"),
            role=roles["CREATOR"],
            is_email_confirmed=True,
            requires_approval=False,
            approved_at=now,
            created_at=now,
        ),
        User(
            username="bob",
            email="bob@example.com",
            password=generate_password_hash("bob"),
            role=roles["RESPONSIBLE"],
            is_email_confirmed=True,
            requires_approval=False,
            approved_at=now,
            created_at=now,
        ),
    ]
    db.session.add_all(demo_users)
    db.session.commit()
    return (
        bilingual("Database refreshed with demo data", "Datenbank mit Demodaten aktualisiert"),
        200,
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    errors = []
    username = (request.form.get("username") or "").strip()
    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""
    if request.method == "POST":
        if not username or not email or not password:
            errors.append(
                bilingual(
                    "Username, email, and password are required",
                    "Benutzername, E-Mail und Passwort sind erforderlich",
                )
            )
        if User.query.filter_by(username=username).first():
            errors.append(
                bilingual(
                    "Username already exists",
                    "Benutzername existiert bereits",
                )
            )
        if User.query.filter_by(email=email).first():
            errors.append(
                bilingual(
                    "Email already registered",
                    "E-Mail ist bereits registriert",
                )
            )
        creator_role = Role.query.filter_by(name="CREATOR").first()
        if not creator_role:
            errors.append(
                bilingual(
                    "Creator role missing; run /initdb",
                    "Creator-Rolle fehlt; /initdb ausführen",
                )
            )
        if not errors:
            user = User(
                username=username,
                email=email,
                password=generate_password_hash(password),
                role=creator_role,
            )
            db.session.add(user)
            db.session.flush()
            token_value = create_email_token(user)
            record_log(
                "USER_REGISTERED",
                bilingual(
                    f"User {username} registered with email {email}",
                    f"Benutzer {username} mit E-Mail {email} registriert",
                ),
            )
            confirmation_link = url_for(
                "confirm_email", token=token_value, _external=True
            )
            send_system_email(
                email,
                bilingual(
                    "Confirm your CIP account",
                    "Bestätigen Sie Ihr CIP-Konto",
                ),
                bilingual(
                    f"Click to confirm: {confirmation_link}",
                    f"Zum Bestätigen klicken: {confirmation_link}",
                ),
            )
            db.session.commit()
            flash(
                bilingual(
                    "Registration successful. Please check your email to confirm.",
                    "Registrierung erfolgreich. Bitte E-Mail zur Bestätigung prüfen.",
                )
            )
            return redirect(url_for("login"))
        for error in errors:
            flash(error)
    return render_page(
        """
        <h1>Register / Registrieren</h1>
        <form method=\"post\">
            {{ csrf_token() }}
            <label>Username / Benutzername</label>
            <input type=\"text\" name=\"username\" value=\"{{ username }}\" required>
            <label>Email</label>
            <input type=\"email\" name=\"email\" value=\"{{ email }}\" required>
            <label>Password / Passwort</label>
            <input type=\"password\" name=\"password\" required>
            <button type=\"submit\">Register / Registrieren</button>
        </form>
        <p><a href=\"{{ url_for('login') }}\">Back to login / Zur Anmeldung</a></p>
        """,
        username=username,
        email=email,
    )


@app.route("/confirm/<token>")
def confirm_email(token):
    entry = EmailVerificationToken.query.filter_by(token=token).first()
    if not entry:
        flash(
            bilingual(
                "Invalid confirmation token",
                "Ungültiger Bestätigungs-Token",
            )
        )
        return redirect(url_for("login"))
    if entry.used_at:
        flash(
            bilingual(
                "Token already used",
                "Token bereits verwendet",
            )
        )
        return redirect(url_for("login"))
    user = entry.user
    entry.used_at = datetime.utcnow()
    user.is_email_confirmed = True
    needs_approval = user.requires_approval and not user.approved_at
    record_log(
        "EMAIL_CONFIRMED",
        bilingual(
            f"User {user.username} confirmed email",
            f"Benutzer {user.username} hat die E-Mail bestätigt",
        ),
    )
    if needs_approval:
        notify_admin_for_approval(user)
        flash(
            bilingual(
                "Email confirmed. Waiting for admin approval.",
                "E-Mail bestätigt. Warten auf Admin-Freigabe.",
            )
        )
    else:
        flash(
            bilingual(
                "Email confirmed. You can now log in.",
                "E-Mail bestätigt. Sie können sich jetzt anmelden.",
            )
        )
    db.session.commit()
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            if not user.is_email_confirmed:
                flash(
                    bilingual(
                        "Please confirm your email before logging in",
                        "Bitte bestätigen Sie Ihre E-Mail vor dem Anmelden",
                    )
                )
            elif user.requires_approval and not user.approved_at:
                flash(
                    bilingual(
                        "Your account awaits admin approval",
                        "Ihr Konto wartet auf die Admin-Freigabe",
                    )
                )
            else:
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
        <form method="post">
            {{ csrf_token() }}
            <label>Username / Benutzername</label>
            <input type="text" name="username" required>
            <label>Password / Passwort</label>
            <input type="password" name="password" required>
            <button type="submit">Login / Anmelden</button>
        </form>
        <p><a href="{{ url_for('register') }}">Register / Registrieren</a></p>
        """,
    )


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def dashboard():
    page = request.args.get("page", 1, type=int)
    status_filter = (request.args.get("status") or "").strip().upper()
    priority_filter = request.args.get("priority") or ""
    department_filter = request.args.get("department") or ""
    text_filter = (request.args.get("q") or "").strip()

    query = CIPMeasure.query
    if current_user.role.name == "ADMIN":
        pass
    elif current_user.role.name == "CREATOR":
        query = query.filter_by(creator_id=current_user.id)
    else:
        query = query.filter_by(responsible_id=current_user.id)

    if status_filter and status_filter in WORKFLOW_STATUSES:
        query = query.filter(CIPMeasure.status == status_filter)
    if priority_filter.isdigit():
        query = query.filter(CIPMeasure.priority_id == int(priority_filter))
    if department_filter.isdigit():
        query = query.filter(
            CIPMeasure.reporting_department_id == int(department_filter)
        )
    if text_filter:
        like = f"%{text_filter}%"
        query = query.filter(
            or_(
                CIPMeasure.title.ilike(like),
                CIPMeasure.problem_description.ilike(like),
            )
        )

    pagination = query.order_by(CIPMeasure.created_at.desc()).paginate(
        page=page, per_page=10, error_out=False
    )
    priorities = Priority.query.order_by(Priority.name).all()
    departments = Department.query.order_by(Department.name).all()
    filters = dict(
        status=status_filter,
        priority=priority_filter,
        department=department_filter,
        q=text_filter,
    )
    return render_page(
        """
        <h1>Dashboard / Übersicht</h1>
        <form method=\"get\">
            <div class=\"flex\">
                <div>
                    <label>Status</label>
                    <select name=\"status\">
                        <option value=\"\">All / Alle</option>
                        {% for status in WORKFLOW_STATUSES %}
                            <option value=\"{{ status }}\" {% if filters.status == status %}selected{% endif %}>{{ status }}</option>
                        {% endfor %}
                    </select>
                </div>
                <div>
                    <label>Priority / Priorität</label>
                    <select name=\"priority\">
                        <option value=\"\">All / Alle</option>
                        {% for priority in priorities %}
                            <option value=\"{{ priority.id }}\" {% if filters.priority|int == priority.id %}selected{% endif %}>{{ priority.name }}</option>
                        {% endfor %}
                    </select>
                </div>
                <div>
                    <label>Department / Abteilung</label>
                    <select name=\"department\">
                        <option value=\"\">All / Alle</option>
                        {% for department in departments %}
                            <option value=\"{{ department.id }}\" {% if filters.department|int == department.id %}selected{% endif %}>{{ department.name }}</option>
                        {% endfor %}
                    </select>
                </div>
                <div style=\"flex:1\">
                    <label>Search Text / Suchtext</label>
                    <input type=\"text\" name=\"q\" value=\"{{ filters.q }}\" placeholder=\"Title or problem description / Titel oder Problembeschreibung\">
                </div>
            </div>
            <div class=\"button-row\">
                <button type=\"submit\">Apply Filters / Filter anwenden</button>
                <a href=\"{{ url_for('dashboard') }}\">Reset / Zurücksetzen</a>
            </div>
        </form>
        <p>{{ pagination.total }} CIP record(s) listed / {{ pagination.total }} CIP-Datensätze angezeigt.</p>
        <table>
            <tr>
                <th>No</th>
                <th>Title / Titel</th>
                <th>Status / Status</th>
                <th>Priority / Priorität</th>
                <th>Department / Abteilung</th>
                <th>Creator / Antragsteller</th>
                <th>Responsible / Verantwortlicher</th>
                <th>Created / Erstellt</th>
            </tr>
            {% for measure in pagination.items %}
            <tr>
                <td><a href=\"{{ url_for('view_cip', measure_id=measure.id) }}\">#{{ measure.id }}</a></td>
                <td>{{ measure.title }}</td>
                <td>{{ measure.status }}</td>
                <td>{{ measure.priority.name if measure.priority else '' }}</td>
                <td>{{ measure.reporting_department.name if measure.reporting_department else '-' }}</td>
                <td>{{ measure.creator.username }}</td>
                <td>{{ measure.responsible.username }}</td>
                <td>{{ measure.created_at.strftime('%Y-%m-%d') }}</td>
            </tr>
            {% endfor %}
        </table>
        <div class=\"button-row\">
            {% if pagination.has_prev %}
                <a href=\"{{ url_for('dashboard', page=pagination.prev_num, status=filters.status, priority=filters.priority, department=filters.department, q=filters.q) }}\">&laquo; Prev / Zurück</a>
            {% endif %}
            <span>Page {{ pagination.page }} / {{ pagination.pages or 1 }}</span>
            {% if pagination.has_next %}
                <a href=\"{{ url_for('dashboard', page=pagination.next_num, status=filters.status, priority=filters.priority, department=filters.department, q=filters.q) }}\">Next / Weiter &raquo;</a>
            {% endif %}
        </div>
        """,
        pagination=pagination,
        priorities=priorities,
        departments=departments,
        filters=filters,
    )


def _form_options():
    return dict(
        departments=Department.query.order_by(Department.name).all(),
        categories=Category.query.order_by(Category.name).all(),
        seat_types=SeatType.query.order_by(SeatType.name).all(),
        priorities=Priority.query.order_by(Priority.name).all(),
        responsible_users=User.query.join(Role).filter(Role.name == "RESPONSIBLE").all(),
    )


CIP_FORM_TEMPLATE = """
        <h1>{{ heading }}</h1>
        <form method=\"post\" action=\"{{ form_action }}\">
            {{ csrf_token() }}
            <label>Title / Titel</label>
            <input type=\"text\" name=\"title\" value=\"{{ measure.title if measure else '' }}\" required>
            <label>Problem Description / Problembeschreibung</label>
            <textarea name=\"problem_description\" rows=\"4\" required>{{ measure.problem_description if measure else '' }}</textarea>
            <label>Reporting Department / Meldende Abteilung</label>
            <select name=\"reporting_department_id\">
                <option value=\"\">-</option>
                {% for d in departments %}
                    <option value=\"{{ d.id }}\" {% if measure and measure.reporting_department_id == d.id %}selected{% endif %}>{{ d.name }}</option>
                {% endfor %}
            </select>
            <label>Responsible Department / Verantwortliche Abteilung</label>
            <select name=\"responsible_department_id\">
                <option value=\"\">-</option>
                {% for d in departments %}
                    <option value=\"{{ d.id }}\" {% if measure and measure.responsible_department_id == d.id %}selected{% endif %}>{{ d.name }}</option>
                {% endfor %}
            </select>
            <label>Category / Kategorie</label>
            <select name=\"category_id\">
                <option value=\"\">-</option>
                {% for c in categories %}
                    <option value=\"{{ c.id }}\" {% if measure and measure.category_id == c.id %}selected{% endif %}>{{ c.name }}</option>
                {% endfor %}
            </select>
            <label>Seat Type / Sitztyp</label>
            <select name=\"seat_type_id\">
                <option value=\"\">-</option>
                {% for s in seat_types %}
                    <option value=\"{{ s.id }}\" {% if measure and measure.seat_type_id == s.id %}selected{% endif %}>{{ s.name }}</option>
                {% endfor %}
            </select>
            <label>Priority / Priorität</label>
            <select name=\"priority_id\" required>
                {% set selected_priority = measure.priority_id if measure else default_priority_id %}
                {% for p in priorities %}
                    <option value=\"{{ p.id }}\" {% if selected_priority == p.id %}selected{% endif %}>{{ p.name }}</option>
                {% endfor %}
            </select>
            <label>Responsible User / Verantwortlicher Benutzer</label>
            <select name=\"responsible_id\" required>
                {% for user in responsible_users %}
                    <option value=\"{{ user.id }}\" {% if measure and measure.responsible_id == user.id %}selected{% endif %}>{{ user.username }}</option>
                {% endfor %}
            </select>
            <label>Theme Type / Thema-Art</label>
            <select name=\"theme_type\">
                {% set selected_theme = measure.theme_type if measure else default_theme %}
                {% for t in theme_types %}
                    <option value=\"{{ t }}\" {% if selected_theme == t %}selected{% endif %}>{{ t }}</option>
                {% endfor %}
            </select>
            <label>Root Cause / Grundursache</label>
            <textarea name=\"root_cause\" rows=\"3\">{{ measure.root_cause if measure else '' }}</textarea>
            <label>Attention List (semicolon separated) / Verteilerliste (mit Semikolon)</label>
            <input type=\"text\" name=\"attention_list\" value=\"{{ measure.attention_list if measure else '' }}\">
            <div class=\"button-row\">
                <button type=\"submit\">{{ submit_label }}</button>
                {% if cancel_url %}
                    <a href=\"{{ cancel_url }}\">Cancel / Abbrechen</a>
                {% endif %}
            </div>
        </form>
"""


def _default_priority_id(priorities):
    for priority in priorities:
        if priority.name.lower() == "medium":
            return priority.id
    return priorities[0].id if priorities else None


@app.route("/cip/new", methods=["GET", "POST"])
@login_required
def new_cip():
    if not can_do(current_user, "create_cip"):
        abort(403)
    options = _form_options()
    default_priority_id = _default_priority_id(options["priorities"])
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("problem_description", "").strip()
        responsible_id = _to_int(request.form.get("responsible_id"))
        priority_id = _to_int(request.form.get("priority_id"))
        if not title or not description or not responsible_id or not priority_id:
            flash(
                bilingual(
                    "Title, description, priority and responsible user are required",
                    "Titel, Beschreibung, Priorität und Verantwortlicher sind erforderlich",
                )
            )
        else:
            measure = CIPMeasure(
                title=title,
                problem_description=description,
                creator_id=current_user.id,
                responsible_id=responsible_id,
                priority_id=priority_id,
                reporting_department_id=_to_int(
                    request.form.get("reporting_department_id")
                ),
                responsible_department_id=_to_int(
                    request.form.get("responsible_department_id")
                ),
                category_id=_to_int(request.form.get("category_id")),
                seat_type_id=_to_int(request.form.get("seat_type_id")),
                theme_type=request.form.get("theme_type") or "CORRECTION",
                root_cause=request.form.get("root_cause") or None,
                attention_list=request.form.get("attention_list") or None,
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
        CIP_FORM_TEMPLATE,
        heading=bilingual("New CIP Record", "Neuer CIP-Datensatz"),
        form_action=url_for("new_cip"),
        submit_label=bilingual("Create Record", "Datensatz erstellen"),
        cancel_url=url_for("dashboard"),
        measure=None,
        default_priority_id=default_priority_id,
        default_theme="CORRECTION",
        theme_types=THEME_TYPES,
        **options,
    )


@app.route("/cip/<int:measure_id>/edit", methods=["GET", "POST"])
@login_required
def edit_cip(measure_id):
    measure = CIPMeasure.query.get_or_404(measure_id)
    if not can_do(current_user, "edit_draft", measure=measure):
        abort(403)
    options = _form_options()
    default_priority_id = measure.priority_id or _default_priority_id(
        options["priorities"]
    )
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("problem_description", "").strip()
        responsible_id = _to_int(request.form.get("responsible_id"))
        priority_id = _to_int(request.form.get("priority_id"))
        if not title or not description or not responsible_id or not priority_id:
            flash(
                bilingual(
                    "Title, description, priority and responsible user are required",
                    "Titel, Beschreibung, Priorität und Verantwortlicher sind erforderlich",
                )
            )
        else:
            measure.title = title
            measure.problem_description = description
            measure.responsible_id = responsible_id
            measure.priority_id = priority_id
            measure.reporting_department_id = _to_int(
                request.form.get("reporting_department_id")
            )
            measure.responsible_department_id = _to_int(
                request.form.get("responsible_department_id")
            )
            measure.category_id = _to_int(request.form.get("category_id"))
            measure.seat_type_id = _to_int(request.form.get("seat_type_id"))
            measure.theme_type = request.form.get("theme_type") or "CORRECTION"
            measure.root_cause = request.form.get("root_cause") or None
            measure.attention_list = request.form.get("attention_list") or None
            record_log(
                "CIP_DRAFT_EDIT",
                bilingual(
                    f"CIP #{measure.id} updated",
                    f"CIP #{measure.id} aktualisiert",
                ),
                measure,
            )
            db.session.commit()
            flash(
                bilingual(
                    "Draft updated",
                    "Entwurf aktualisiert",
                )
            )
            return redirect(url_for("view_cip", measure_id=measure.id))
    return render_page(
        CIP_FORM_TEMPLATE,
        heading=bilingual("Edit Draft", "Entwurf bearbeiten"),
        form_action=url_for("edit_cip", measure_id=measure.id),
        submit_label=bilingual("Save Changes", "Änderungen speichern"),
        cancel_url=url_for("view_cip", measure_id=measure.id),
        measure=measure,
        default_priority_id=default_priority_id,
        default_theme=measure.theme_type or "CORRECTION",
        theme_types=THEME_TYPES,
        **options,
    )


@app.route("/cip/<int:measure_id>")
@login_required
def view_cip(measure_id):
    measure = CIPMeasure.query.get_or_404(measure_id)
    if not can_do(current_user, "view_measure", measure=measure):
        abort(403)
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
                {% if can_do(current_user, 'edit_draft', measure=measure) %}
                    <p><a href=\"{{ url_for('edit_cip', measure_id=measure.id) }}\">Edit Draft / Entwurf bearbeiten</a></p>
                {% endif %}
                {% if can_do(current_user, 'cancel', measure=measure) %}
                    <form method=\"post\" action=\"{{ url_for('cancel_cip', measure_id=measure.id) }}\">
                        {{ csrf_token() }}
                        <button type=\"submit\" class=\"danger\">Cancel Draft / Entwurf stornieren</button>
                    </form>
                {% endif %}
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
                        {% if can_do(current_user, 'update_task_status', task=task) %}
                            <form method=\"post\" action=\"{{ url_for('update_task_status', task_id=task.id) }}\">
                                {{ csrf_token() }}
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

        {% if can_do(current_user, 'create_task', measure=measure) %}
            <h3>Create Task or Request / Aufgabe oder Anfrage erstellen</h3>
            <form method=\"post\" action=\"{{ url_for('create_task', measure_id=measure.id) }}\">
                {{ csrf_token() }}
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
        {% endif %}

        {% if can_do(current_user, 'report', measure=measure) %}
            <form method=\"post\" action=\"{{ url_for('report_cip', measure_id=measure.id) }}\">
                {{ csrf_token() }}
                <h3>Submit CIP Report / CIP melden</h3>
                <button type=\"submit\">Report / Melden</button>
            </form>
        {% endif %}

        {% if can_do(current_user, 'propose_solution', measure=measure) %}
            <form method=\"post\" action=\"{{ url_for('propose_solution', measure_id=measure.id) }}\">
                {{ csrf_token() }}
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

        {% if can_do(current_user, 'accept_solution', measure=measure) %}
            <form method=\"post\" action=\"{{ url_for('accept_solution', measure_id=measure.id) }}\">
                {{ csrf_token() }}
                <h3>Accept Solution / Lösung akzeptieren</h3>
                <button type=\"submit\">Accept / Akzeptieren</button>
            </form>
            <form method=\"post\" action=\"{{ url_for('reject_solution', measure_id=measure.id) }}\">
                {{ csrf_token() }}
                <h3>Reject Solution / Lösung ablehnen</h3>
                <label>Comment / Kommentar</label>
                <textarea name=\"comment\" rows=\"3\"></textarea>
                <button type=\"submit\">Reject / Ablehnen</button>
            </form>
        {% endif %}

        {% if can_do(current_user, 'mark_implemented', measure=measure) %}
            <form method=\"post\" action=\"{{ url_for('mark_implemented', measure_id=measure.id) }}\">
                {{ csrf_token() }}
                <h3>Mark as Implemented / Als umgesetzt markieren</h3>
                <label>Implemented Action / Umgesetzte Maßnahme</label>
                <textarea name=\"implemented_action\" rows=\"3\">{{ measure.implemented_action or '' }}</textarea>
                <button type=\"submit\">Implemented / Umgesetzt</button>
            </form>
        {% endif %}

        {% if can_do(current_user, 'evaluate_effectiveness', measure=measure) %}
            <form method=\"post\" action=\"{{ url_for('evaluate_effectiveness', measure_id=measure.id) }}\">
                {{ csrf_token() }}
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


def _to_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def ensure_status_requirements(measure, target_status):
    required_fields = STATUS_REQUIREMENTS.get(target_status, [])
    missing = []
    for field in required_fields:
        value = getattr(measure, field)
        if value is None or (isinstance(value, str) and not value.strip()):
            missing.append(FIELD_LABELS.get(field, field))
    if missing:
        raise ValueError(
            bilingual(
                f"Missing data for {target_status}: {', '.join(missing)}",
                f"Fehlende Angaben für {target_status}: {', '.join(missing)}",
            )
        )


def _record_history(measure, new_status, comment=None):
    ensure_status_requirements(measure, new_status)
    entry = CIPMeasureHistory(
        measure_id=measure.id,
        from_status=measure.status,
        to_status=new_status,
        changed_by_id=current_user.id,
        comment=comment,
    )
    measure.status = new_status
    timestamp_field = STATUS_TIMESTAMPS.get(new_status)
    if timestamp_field:
        setattr(measure, timestamp_field, datetime.utcnow())
    db.session.add(entry)


def record_log(event_type, description, measure=None):
    entry = SystemLog(
        event_type=event_type,
        description=description,
        user_id=current_user.id if current_user.is_authenticated else None,
        measure_id=measure.id if isinstance(measure, CIPMeasure) else measure,
    )
    db.session.add(entry)


def send_system_email(recipient, subject, body):
    record_log(
        "EMAIL",
        bilingual(
            f"Email to {recipient}: {subject} - {body}",
            f"E-Mail an {recipient}: {subject} - {body}",
        ),
    )


def create_email_token(user):
    token_value = secrets.token_urlsafe(32)
    token = EmailVerificationToken(user=user, token=token_value)
    db.session.add(token)
    return token_value


def notify_admin_for_approval(user):
    admin_query = User.query.join(Role).filter(Role.name == "ADMIN")
    admins = []
    if ADMIN_APPROVER_EMAIL:
        primary = admin_query.filter(User.email == ADMIN_APPROVER_EMAIL).first()
        if primary:
            admins.append(primary)
    if not admins:
        admins = admin_query.all()
    if not admins:
        return
    approval_link = url_for("manage_approvals", _external=True)
    subject = bilingual("User approval required", "Benutzerfreigabe erforderlich")
    body = bilingual(
        f"Please approve user {user.username} ({user.email})", 
        f"Bitte Benutzer {user.username} ({user.email}) freigeben",
    )
    for admin in admins:
        send_system_email(admin.email, subject, f"{body}. {approval_link}")


@app.post("/cip/<int:measure_id>/cancel")
@login_required
def cancel_cip(measure_id):
    measure = CIPMeasure.query.get_or_404(measure_id)
    if not can_do(current_user, "cancel", measure=measure):
        abort(403)
    try:
        _record_history(measure, "CANCELLED")
    except ValueError as exc:
        flash(str(exc))
        return redirect(url_for("view_cip", measure_id=measure.id))
    record_log(
        "CIP_IPTAL",
        bilingual(
            f"CIP #{measure.id} cancelled",
            f"CIP #{measure.id} storniert",
        ),
        measure,
    )
    db.session.commit()
    flash(
        bilingual(
            "Draft cancelled",
            "Entwurf storniert",
        )
    )
    return redirect(url_for("dashboard"))


@app.post("/cip/<int:measure_id>/report")
@login_required
def report_cip(measure_id):
    measure = CIPMeasure.query.get_or_404(measure_id)
    if not can_do(current_user, "report", measure=measure):
        abort(403)
    try:
        _record_history(measure, "REPORTED")
    except ValueError as exc:
        flash(str(exc))
        return redirect(url_for("view_cip", measure_id=measure.id))
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
    if not can_do(current_user, "propose_solution", measure=measure):
        abort(403)
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
    try:
        _record_history(measure, "SOLUTION_PROPOSED")
    except ValueError as exc:
        flash(str(exc))
        return redirect(url_for("view_cip", measure_id=measure.id))
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
    if not can_do(current_user, "accept_solution", measure=measure):
        abort(403)
    try:
        _record_history(measure, "SOLUTION_ACCEPTED")
    except ValueError as exc:
        flash(str(exc))
        return redirect(url_for("view_cip", measure_id=measure.id))
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
    if not can_do(current_user, "reject_solution", measure=measure):
        abort(403)
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
    if not can_do(current_user, "mark_implemented", measure=measure):
        abort(403)
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
    try:
        _record_history(measure, "IMPLEMENTED")
    except ValueError as exc:
        flash(str(exc))
        return redirect(url_for("view_cip", measure_id=measure.id))
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
    if not can_do(current_user, "evaluate_effectiveness", measure=measure):
        abort(403)
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
        try:
            _record_history(
                measure,
                "CLOSED_EFFECTIVE",
                comment=bilingual("Found effective", "Als wirksam bewertet"),
            )
        except ValueError as exc:
            flash(str(exc))
            return redirect(url_for("view_cip", measure_id=measure.id))
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
    try:
        _record_history(
            measure,
            "CLOSED_NOT_EFFECTIVE",
            comment=comment or bilingual("Not effective", "Nicht wirksam"),
        )
    except ValueError as exc:
        flash(str(exc))
        return redirect(url_for("view_cip", measure_id=measure.id))
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
    if not can_do(current_user, "create_task", measure=measure):
        abort(403)
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
    if not can_do(current_user, "update_task_status", task=task):
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
    if not can_do(current_user, "view_logs"):
        abort(403)
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


@app.route("/kpi")
@login_required
def kpi_dashboard():
    if not can_do(current_user, "view_kpi"):
        abort(403)
    closed_statuses = {"CLOSED_EFFECTIVE", "CLOSED_NOT_EFFECTIVE", "CANCELLED"}
    open_count = (
        CIPMeasure.query.filter(~CIPMeasure.status.in_(tuple(closed_statuses))).count()
    )
    dept_counts = (
        db.session.query(Department.name, func.count(CIPMeasure.id))
        .outerjoin(Department, Department.id == CIPMeasure.reporting_department_id)
        .group_by(Department.name)
        .all()
    )
    avg_close_days = (
        db.session.query(
            func.avg(
                func.julianday(CIPMeasure.closed_at)
                - func.julianday(CIPMeasure.created_at)
            )
        )
        .filter(CIPMeasure.closed_at.isnot(None))
        .scalar()
    )
    if avg_close_days is not None:
        avg_close_days = round(avg_close_days, 1)
    recent_threshold = datetime.utcnow() - timedelta(days=30)
    recent_count = (
        CIPMeasure.query.filter(CIPMeasure.created_at >= recent_threshold).count()
    )
    return render_page(
        """
        <h1>KPI Dashboard / KPI-Übersicht</h1>
        <div class=\"flex\">
            <div class=\"card\">
                <h3>Open CIP / Offene CIP</h3>
                <p class=\"status\">{{ open_count }}</p>
            </div>
            <div class=\"card\">
                <h3>Avg. Close Days / Ø Abschlusstage</h3>
                <p class=\"status\">{{ avg_close_days if avg_close_days is not none else 'n/a' }}</p>
            </div>
            <div class=\"card\">
                <h3>Last 30 days opened / In den letzten 30 Tagen</h3>
                <p class=\"status\">{{ recent_count }}</p>
            </div>
        </div>
        <h2>By Reporting Department / Nach meldender Abteilung</h2>
        <table>
            <tr><th>Department / Abteilung</th><th>Count / Anzahl</th></tr>
            {% for name, count in dept_counts %}
                <tr><td>{{ name or 'Unknown' }}</td><td>{{ count }}</td></tr>
            {% endfor %}
        </table>
        """,
        open_count=open_count,
        avg_close_days=avg_close_days,
        recent_count=recent_count,
        dept_counts=dept_counts,
    )


@app.route("/admin/approvals", methods=["GET", "POST"])
@login_required
@admin_required
def manage_approvals():
    if request.method == "POST":
        user_id = request.form.get("user_id")
        if not user_id:
            abort(400)
        user = User.query.get_or_404(int(user_id))
        if not user.is_email_confirmed:
            flash(
                bilingual(
                    "User has not confirmed email",
                    "Benutzer hat die E-Mail nicht bestätigt",
                )
            )
            return redirect(url_for("manage_approvals"))
        if user.approved_at:
            flash(
                bilingual(
                    "User already approved",
                    "Benutzer bereits freigegeben",
                )
            )
            return redirect(url_for("manage_approvals"))
        user.approved_at = datetime.utcnow()
        user.approved_by_id = current_user.id
        record_log(
            "USER_APPROVED",
            bilingual(
                f"Admin approved {user.username}",
                f"Admin hat {user.username} freigegeben",
            ),
        )
        send_system_email(
            user.email,
            bilingual(
                "Your CIP account is approved",
                "Ihr CIP-Konto wurde freigegeben",
            ),
            bilingual(
                f"You can log in via {url_for('login', _external=True)}",
                f"Sie können sich über {url_for('login', _external=True)} anmelden",
            ),
        )
        db.session.commit()
        flash(
            bilingual(
                "User approved",
                "Benutzer freigegeben",
            )
        )
        return redirect(url_for("manage_approvals"))
    pending_users = (
        User.query.join(Role)
        .filter(
            User.is_email_confirmed.is_(True),
            User.requires_approval.is_(True),
            User.approved_at.is_(None),
        )
        .order_by(User.created_at.asc())
        .all()
    )
    return render_page(
        """
        <h1>Pending Approvals / Ausstehende Freigaben</h1>
        {% if not pending_users %}
            <p>No pending users / Keine offenen Benutzer.</p>
        {% else %}
            <table>
                <tr>
                    <th>Username</th>
                    <th>Email</th>
                    <th>Role</th>
                    <th>Registered</th>
                    <th>Action</th>
                </tr>
                {% for user in pending_users %}
                    <tr>
                        <td>{{ user.username }}</td>
                        <td>{{ user.email }}</td>
                        <td>{{ user.role.name }}</td>
                        <td>{{ user.created_at.strftime('%Y-%m-%d %H:%M') if user.created_at else '-' }}</td>
                        <td>
                            <form method=\"post\">
                                {{ csrf_token() }}
                                <input type=\"hidden\" name=\"user_id\" value=\"{{ user.id }}\">
                                <button type=\"submit\">Approve / Freigeben</button>
                            </form>
                        </td>
                    </tr>
                {% endfor %}
            </table>
        {% endif %}
        """,
        pending_users=pending_users,
    )


@app.route("/admin")
@login_required
@admin_required
def admin_panel():
    return render_page(
        """
        <h1>Admin Panel / Verwaltungsbereich</h1>
        <ul>
            <li><a href=\"{{ url_for('manage_approvals') }}\">Approvals / Freigaben</a></li>
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
            {{ csrf_token() }}
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
            email = (request.form.get("email") or "").strip().lower()
            if not username or not password or not role_id or not email:
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
            elif User.query.filter_by(email=email).first():
                flash(
                    bilingual(
                        "Email already exists",
                        "E-Mail existiert bereits",
                    )
                )
            else:
                user = User(
                    username=username,
                    email=email,
                    password=generate_password_hash(password),
                    role_id=int(role_id),
                    is_email_confirmed=True,
                    requires_approval=False,
                    approved_at=datetime.utcnow(),
                    approved_by_id=current_user.id,
                )
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
            email = (request.form.get("email") or "").strip().lower()
            if role_id:
                user.role_id = int(role_id)
            if password:
                user.password = generate_password_hash(password)
            if email:
                duplicate = User.query.filter(User.email == email, User.id != user.id).first()
                if duplicate:
                    flash(
                        bilingual(
                            "Email already exists",
                            "E-Mail existiert bereits",
                        )
                    )
                    return redirect(url_for("manage_users"))
                user.email = email
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
            {{ csrf_token() }}
            <input type=\"hidden\" name=\"action\" value=\"create\">
            <label>Username / Benutzername</label>
            <input type=\"text\" name=\"username\" required>
            <label>Email</label>
            <input type=\"email\" name=\"email\" required>
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
            <tr>
                <th>Username</th>
                <th>Email</th>
                <th>Role</th>
                <th>Status</th>
                <th>Update</th>
                <th>Delete</th>
            </tr>
            {% for user in users %}
                <tr>
                    <td>{{ user.username }}</td>
                    <td>{{ user.email }}</td>
                    <td>{{ user.role.name }}</td>
                    <td>
                        <div>
                            {{ 'Confirmed' if user.is_email_confirmed else 'Email pending' }} /
                            {{ 'Bestätigt' if user.is_email_confirmed else 'E-Mail ausstehend' }}
                        </div>
                        <div>
                            {% if not user.requires_approval %}
                                {{ 'Approval not required' }} / {{ 'Freigabe nicht nötig' }}
                            {% elif user.approved_at %}
                                {{ 'Approved' }} / {{ 'Freigegeben' }}
                            {% else %}
                                {{ 'Waiting for approval' }} / {{ 'Wartet auf Freigabe' }}
                            {% endif %}
                        </div>
                    </td>
                    <td>
                        <form method=\"post\">
                            {{ csrf_token() }}
                            <input type=\"hidden\" name=\"action\" value=\"update\">
                            <input type=\"hidden\" name=\"user_id\" value=\"{{ user.id }}\">
                            <label>Email</label>
                            <input type=\"email\" name=\"email\" value=\"{{ user.email }}\" required>
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
