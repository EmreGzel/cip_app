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
    <title>CIP / KVP Tool</title>
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
            <strong>CIP / KVP Tool</strong>
            {% if current_user.is_authenticated %}
                <span class=\"tag\">{{ current_user.role.name }}</span>
            {% endif %}
        </div>
        <nav>
            {% if current_user.is_authenticated %}
                <a href=\"{{ url_for('dashboard') }}\">Dashboard</a>
                <a href=\"{{ url_for('new_cip') }}\">New CIP</a>
                {% if current_user.role.name == 'ADMIN' %}
                    <a href=\"{{ url_for('admin_panel') }}\">Admin</a>
                {% endif %}
                <a href=\"{{ url_for('logout') }}\">Logout</a>
            {% else %}
                <a href=\"{{ url_for('login') }}\">Login</a>
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
    body = render_template_string(body_template, **context)
    return render_template_string(
        BASE_TEMPLATE,
        body=body,
        current_user=current_user,
        WORKFLOW_STATUSES=WORKFLOW_STATUSES,
        EFFECTIVENESS_STATUSES=EFFECTIVENESS_STATUSES,
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
    return "Database initialized with demo data", 200


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()
        if user and user.password == password:
            login_user(user)
            return redirect(url_for("dashboard"))
        flash("Invalid credentials")
    return render_page(
        """
        <h1>Login</h1>
        <form method=\"post\">
            <label>Username</label>
            <input type=\"text\" name=\"username\" required>
            <label>Password</label>
            <input type=\"password\" name=\"password\" required>
            <button type=\"submit\">Login</button>
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
        <h1>Dashboard</h1>
        <p>Showing {{ measures|length }} measure(s).</p>
        <table>
            <tr>
                <th>No</th>
                <th>Title</th>
                <th>Status</th>
                <th>Priority</th>
                <th>Creator</th>
                <th>Responsible</th>
                <th>Created</th>
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
            flash("Title and problem description are required")
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
            db.session.commit()
            flash(f"CIP #{measure.id} created")
            return redirect(url_for("view_cip", measure_id=measure.id))
    return render_page(
        """
        <h1>New CIP Measure</h1>
        <form method=\"post\">
            <label>Title</label>
            <input type=\"text\" name=\"title\" required>
            <label>Problem Description</label>
            <textarea name=\"problem_description\" rows=\"4\" required></textarea>
            <label>Reporting Department</label>
            <select name=\"reporting_department_id\">
                <option value=\"\">-</option>
                {% for d in departments %}
                    <option value=\"{{ d.id }}\">{{ d.name }}</option>
                {% endfor %}
            </select>
            <label>Responsible Department</label>
            <select name=\"responsible_department_id\">
                <option value=\"\">-</option>
                {% for d in departments %}
                    <option value=\"{{ d.id }}\">{{ d.name }}</option>
                {% endfor %}
            </select>
            <label>Category</label>
            <select name=\"category_id\">
                <option value=\"\">-</option>
                {% for c in categories %}
                    <option value=\"{{ c.id }}\">{{ c.name }}</option>
                {% endfor %}
            </select>
            <label>Seat Type</label>
            <select name=\"seat_type_id\">
                <option value=\"\">-</option>
                {% for s in seat_types %}
                    <option value=\"{{ s.id }}\">{{ s.name }}</option>
                {% endfor %}
            </select>
            <label>Priority</label>
            <select name=\"priority_id\" required>
                {% for p in priorities %}
                    <option value=\"{{ p.id }}\" {% if p.name == 'Medium' %}selected{% endif %}>{{ p.name }}</option>
                {% endfor %}
            </select>
            <label>Responsible User</label>
            <select name=\"responsible_id\" required>
                {% for user in responsible_users %}
                    <option value=\"{{ user.id }}\">{{ user.username }}</option>
                {% endfor %}
            </select>
            <label>Theme Type</label>
            <select name=\"theme_type\">
                {% for t in theme_types %}
                    <option value=\"{{ t }}\">{{ t }}</option>
                {% endfor %}
            </select>
            <label>Root Cause</label>
            <textarea name=\"root_cause\" rows=\"3\"></textarea>
            <label>Attention List (semicolon separated)</label>
            <input type=\"text\" name=\"attention_list\">
            <button type=\"submit\">Create</button>
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
    return render_page(
        """
        <h1>CIP #{{ measure.id }} - {{ measure.title }}</h1>
        <div class=\"flex\">
            <div class=\"card\">
                <h3>Metadata</h3>
                <p>Status: <span class=\"status\">{{ measure.status }}</span></p>
                <p>Priority: {{ measure.priority.name if measure.priority else '-' }}</p>
                <p>Creator: {{ measure.creator.username }}</p>
                <p>Responsible: {{ measure.responsible.username }}</p>
                <p>Created: {{ measure.created_at.strftime('%Y-%m-%d %H:%M') }}</p>
                <p>Reporting Department: {{ measure.reporting_department.name if measure.reporting_department else '-' }}</p>
                <p>Responsible Department: {{ measure.responsible_department.name if measure.responsible_department else '-' }}</p>
                <p>Category: {{ measure.category.name if measure.category else '-' }}</p>
                <p>Seat Type: {{ measure.seat_type.name if measure.seat_type else '-' }}</p>
                <p>Theme Type: {{ measure.theme_type }}</p>
                <p>Root Cause: {{ measure.root_cause or '-' }}</p>
                <p>Attention: {{ measure.attention_list or '-' }}</p>
                {% if measure.parent %}
                    <p>Parent Measure: <a href=\"{{ url_for('view_cip', measure_id=measure.parent.id) }}\">#{{ measure.parent.id }}</a></p>
                {% endif %}
                {% if measure.children %}
                    <p>Follow-up Measures:
                        {% for child in measure.children %}
                            <a href=\"{{ url_for('view_cip', measure_id=child.id) }}\">#{{ child.id }}</a>
                        {% endfor %}
                    </p>
                {% endif %}
            </div>
            <div class=\"card\">
                <h3>Problem Description</h3>
                <p>{{ measure.problem_description }}</p>
                {% if measure.comments %}
                    <h4>Comments</h4>
                    <p>{{ measure.comments }}</p>
                {% endif %}
            </div>
            <div class=\"card\">
                <h3>Action Plan</h3>
                <p>Sofortmaßnahme notwendig: {{ 'Yes' if measure.sofort_needed else 'No' }}</p>
                <p>Sofortmaßnahme: {{ measure.sofort_action or '-' }}</p>
                <p>Geplante Maßnahme: {{ measure.planned_action or '-' }}</p>
                <p>Geplanter Termin: {{ measure.planned_due_date or '-' }}</p>
                <p>Wirksamkeit mittels: {{ measure.effectiveness_check_method or '-' }}</p>
                <p>Beurteilungstermin: {{ measure.effectiveness_check_date or '-' }}</p>
                <p>Umgesetzte Maßnahme: {{ measure.implemented_action or '-' }}</p>
                <p>Wirksamkeit: {{ measure.effectiveness_status }}</p>
                <p>Wirksamkeit Notu: {{ measure.effectiveness_comment or '-' }}</p>
            </div>
        </div>
        <h2>Workflow History</h2>
        <table>
            <tr><th>From</th><th>To</th><th>User</th><th>Date</th><th>Comment</th></tr>
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

        {% if current_user.role.name == 'CREATOR' and measure.creator_id == current_user.id and measure.status == 'DRAFT' %}
            <form method=\"post\" action=\"{{ url_for('report_cip', measure_id=measure.id) }}\">
                <h3>Report Measure</h3>
                <button type=\"submit\">Report</button>
            </form>
        {% endif %}

        {% if current_user.role.name in ['RESPONSIBLE', 'ADMIN'] and measure.responsible_id == current_user.id and measure.status in ['REPORTED', 'SOLUTION_REJECTED'] %}
            <form method=\"post\" action=\"{{ url_for('propose_solution', measure_id=measure.id) }}\">
                <h3>Propose Solution</h3>
                <label><input type=\"checkbox\" name=\"sofort_needed\" value=\"1\" {% if measure.sofort_needed %}checked{% endif %}> Sofortmaßnahme notwendig</label>
                <label>Sofortmaßnahme</label>
                <textarea name=\"sofort_action\" rows=\"3\">{{ measure.sofort_action or '' }}</textarea>
                <label>Geplante Korrekturmaßnahme</label>
                <textarea name=\"planned_action\" rows=\"3\">{{ measure.planned_action or '' }}</textarea>
                <label>Geplanter Fertigungstermin</label>
                <input type=\"date\" name=\"planned_due_date\" value=\"{{ measure.planned_due_date }}\">
                <label>Prüfung der Wirksamkeit mittels</label>
                <textarea name=\"effectiveness_check_method\" rows=\"3\">{{ measure.effectiveness_check_method or '' }}</textarea>
                <label>Beurteilung der Wirksamkeit nach</label>
                <input type=\"date\" name=\"effectiveness_check_date\" value=\"{{ measure.effectiveness_check_date }}\">
                <button type=\"submit\">Submit Solution</button>
            </form>
        {% endif %}

        {% if current_user.role.name == 'CREATOR' and measure.creator_id == current_user.id and measure.status == 'SOLUTION_PROPOSED' %}
            <form method=\"post\" action=\"{{ url_for('accept_solution', measure_id=measure.id) }}\">
                <h3>Accept Solution</h3>
                <button type=\"submit\">Accept</button>
            </form>
            <form method=\"post\" action=\"{{ url_for('reject_solution', measure_id=measure.id) }}\">
                <h3>Reject Solution</h3>
                <label>Comment</label>
                <textarea name=\"comment\" rows=\"3\"></textarea>
                <button type=\"submit\">Reject</button>
            </form>
        {% endif %}

        {% if current_user.role.name in ['RESPONSIBLE', 'ADMIN'] and measure.responsible_id == current_user.id and measure.status == 'SOLUTION_ACCEPTED' %}
            <form method=\"post\" action=\"{{ url_for('mark_implemented', measure_id=measure.id) }}\">
                <h3>Mark as Implemented</h3>
                <label>Implemented Action</label>
                <textarea name=\"implemented_action\" rows=\"3\">{{ measure.implemented_action or '' }}</textarea>
                <button type=\"submit\">Mark Implemented</button>
            </form>
        {% endif %}

        {% if current_user.role.name == 'CREATOR' and measure.creator_id == current_user.id and measure.status == 'IMPLEMENTED' %}
            <form method=\"post\" action=\"{{ url_for('evaluate_effectiveness', measure_id=measure.id) }}\">
                <h3>Effectiveness Check</h3>
                <label>Result</label>
                <select name=\"effectiveness_status\" required>
                    <option value=\"EFFECTIVE\">Wirksam</option>
                    <option value=\"NOT_EFFECTIVE\">NICHT wirksam</option>
                </select>
                <label>Comment</label>
                <textarea name=\"effectiveness_comment\" rows=\"3\"></textarea>
                <button type=\"submit\">Submit Evaluation</button>
            </form>
        {% endif %}
        """,
        measure=measure,
        history=history,
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


@app.post("/cip/<int:measure_id>/report")
@login_required
def report_cip(measure_id):
    measure = CIPMeasure.query.get_or_404(measure_id)
    creator_required(measure)
    if measure.status != "DRAFT":
        flash("Measure already reported")
        return redirect(url_for("view_cip", measure_id=measure.id))
    if measure.theme_type == "CORRECTION" and not measure.root_cause:
        flash("Root cause is required for CORRECTION theme")
        return redirect(url_for("view_cip", measure_id=measure.id))
    _record_history(measure, "REPORTED")
    db.session.commit()
    flash("Measure reported")
    return redirect(url_for("view_cip", measure_id=measure.id))


@app.post("/cip/<int:measure_id>/propose_solution")
@login_required
def propose_solution(measure_id):
    measure = CIPMeasure.query.get_or_404(measure_id)
    responsible_required(measure)
    if measure.status not in ("REPORTED", "SOLUTION_REJECTED"):
        flash("Cannot propose solution in current state")
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
    db.session.commit()
    flash("Solution proposed")
    return redirect(url_for("view_cip", measure_id=measure.id))


@app.post("/cip/<int:measure_id>/accept")
@login_required
def accept_solution(measure_id):
    measure = CIPMeasure.query.get_or_404(measure_id)
    creator_required(measure)
    if measure.status != "SOLUTION_PROPOSED":
        flash("Solution not in proposed state")
        return redirect(url_for("view_cip", measure_id=measure.id))
    _record_history(measure, "SOLUTION_ACCEPTED")
    db.session.commit()
    flash("Solution accepted")
    return redirect(url_for("view_cip", measure_id=measure.id))


@app.post("/cip/<int:measure_id>/reject")
@login_required
def reject_solution(measure_id):
    measure = CIPMeasure.query.get_or_404(measure_id)
    creator_required(measure)
    if measure.status != "SOLUTION_PROPOSED":
        flash("Solution not in proposed state")
        return redirect(url_for("view_cip", measure_id=measure.id))
    comment = request.form.get("comment") or "Revision requested"
    _record_history(measure, "SOLUTION_REJECTED", comment=comment)
    db.session.commit()
    flash("Solution rejected")
    return redirect(url_for("view_cip", measure_id=measure.id))


@app.post("/cip/<int:measure_id>/implemented")
@login_required
def mark_implemented(measure_id):
    measure = CIPMeasure.query.get_or_404(measure_id)
    responsible_required(measure)
    if measure.status != "SOLUTION_ACCEPTED":
        flash("Measure is not ready for implementation")
        return redirect(url_for("view_cip", measure_id=measure.id))
    implemented_action = request.form.get("implemented_action", "").strip()
    if not implemented_action:
        flash("Implemented action is required")
        return redirect(url_for("view_cip", measure_id=measure.id))
    measure.implemented_action = implemented_action
    _record_history(measure, "IMPLEMENTED")
    db.session.commit()
    flash("Marked as implemented")
    return redirect(url_for("view_cip", measure_id=measure.id))


@app.post("/cip/<int:measure_id>/effectiveness")
@login_required
def evaluate_effectiveness(measure_id):
    measure = CIPMeasure.query.get_or_404(measure_id)
    creator_required(measure)
    if measure.status != "IMPLEMENTED":
        flash("Measure must be implemented before evaluation")
        return redirect(url_for("view_cip", measure_id=measure.id))
    status = request.form.get("effectiveness_status")
    comment = request.form.get("effectiveness_comment") or None
    if status not in ("EFFECTIVE", "NOT_EFFECTIVE"):
        flash("Invalid effectiveness choice")
        return redirect(url_for("view_cip", measure_id=measure.id))
    if status == "NOT_EFFECTIVE" and not comment:
        flash("Comment is required for NOT effective evaluation")
        return redirect(url_for("view_cip", measure_id=measure.id))
    measure.effectiveness_status = status
    measure.effectiveness_comment = comment

    if status == "EFFECTIVE":
        _record_history(measure, "CLOSED_EFFECTIVE", comment="Marked effective")
        db.session.commit()
        flash("Measure closed as effective")
        return redirect(url_for("view_cip", measure_id=measure.id))

    # NOT effective branch
    _record_history(
        measure,
        "CLOSED_NOT_EFFECTIVE",
        comment=comment or "Marked not effective",
    )

    follow_up = CIPMeasure(
        title=f"Follow-up for #{measure.id}",
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
    db.session.commit()
    flash(f"Measure closed as NOT effective. Follow-up #{follow_up.id} created.")
    return redirect(url_for("view_cip", measure_id=measure.id))


@app.route("/admin")
@login_required
@admin_required
def admin_panel():
    return render_page(
        """
        <h1>Admin Panel</h1>
        <ul>
            <li><a href=\"{{ url_for('manage_users') }}\">Users</a></li>
            <li><a href=\"{{ url_for('manage_departments') }}\">Departments</a></li>
            <li><a href=\"{{ url_for('manage_categories') }}\">Categories</a></li>
            <li><a href=\"{{ url_for('manage_seat_types') }}\">Seat Types</a></li>
            <li><a href=\"{{ url_for('manage_priorities') }}\">Priorities</a></li>
        </ul>
        """
    )


def _generic_manage(model, title, endpoint, usage_check):
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        if name:
            if not model.query.filter_by(name=name).first():
                db.session.add(model(name=name))
                db.session.commit()
                flash(f"{title} added")
            else:
                flash("Name already exists")
        else:
            flash("Name is required")
    delete_id = request.args.get("delete")
    if delete_id:
        item = model.query.get(delete_id)
        if item:
            if usage_check(item):
                flash("Cannot delete: value in use")
            else:
                db.session.delete(item)
                db.session.commit()
                flash("Deleted")
    items = model.query.order_by(model.name).all()
    return render_page(
        """
        <h1>{{ title }} Management</h1>
        <form method=\"post\">
            <label>Name</label>
            <input type=\"text\" name=\"name\" required>
            <button type=\"submit\">Add</button>
        </form>
        <table>
            <tr><th>Name</th><th>Actions</th></tr>
            {% for item in items %}
                <tr>
                    <td>{{ item.name }}</td>
                    <td><a href=\"{{ url_for(endpoint, delete=item.id) }}\">Delete</a></td>
                </tr>
            {% endfor %}
        </table>
        """,
        title=title,
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

    return _generic_manage(Department, "Department", "manage_departments", usage_check)


@app.route("/admin/categories", methods=["GET", "POST"])
@login_required
@admin_required
def manage_categories():
    def usage_check(category):
        return CIPMeasure.query.filter_by(category_id=category.id).count() > 0

    return _generic_manage(Category, "Category", "manage_categories", usage_check)


@app.route("/admin/seat_types", methods=["GET", "POST"])
@login_required
@admin_required
def manage_seat_types():
    def usage_check(seat_type):
        return CIPMeasure.query.filter_by(seat_type_id=seat_type.id).count() > 0

    return _generic_manage(SeatType, "Seat Type", "manage_seat_types", usage_check)


@app.route("/admin/priorities", methods=["GET", "POST"])
@login_required
@admin_required
def manage_priorities():
    def usage_check(priority):
        return CIPMeasure.query.filter_by(priority_id=priority.id).count() > 0

    return _generic_manage(Priority, "Priority", "manage_priorities", usage_check)


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
                flash("All fields are required")
            elif User.query.filter_by(username=username).first():
                flash("Username already exists")
            else:
                user = User(username=username, password=password, role_id=int(role_id))
                db.session.add(user)
                db.session.commit()
                flash("User created")
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
            flash("User updated")
    delete_id = request.args.get("delete")
    if delete_id:
        user = User.query.get(delete_id)
        if user:
            if user.created_measures or user.responsible_measures:
                flash("Cannot delete user referenced in measures")
            else:
                db.session.delete(user)
                db.session.commit()
                flash("User deleted")
    users = User.query.order_by(User.username).all()
    roles = Role.query.order_by(Role.name).all()
    return render_page(
        """
        <h1>User Management</h1>
        <h2>Create User</h2>
        <form method=\"post\">
            <input type=\"hidden\" name=\"action\" value=\"create\">
            <label>Username</label>
            <input type=\"text\" name=\"username\" required>
            <label>Password</label>
            <input type=\"password\" name=\"password\" required>
            <label>Role</label>
            <select name=\"role_id\" required>
                {% for role in roles %}
                    <option value=\"{{ role.id }}\">{{ role.name }}</option>
                {% endfor %}
            </select>
            <button type=\"submit\">Create</button>
        </form>
        <h2>Existing Users</h2>
        <table>
            <tr><th>Username</th><th>Role</th><th>Update</th><th>Delete</th></tr>
            {% for user in users %}
                <tr>
                    <td>{{ user.username }}</td>
                    <td>{{ user.role.name }}</td>
                    <td>
                        <form method=\"post\">
                            <input type=\"hidden\" name=\"action\" value=\"update\">
                            <input type=\"hidden\" name=\"user_id\" value=\"{{ user.id }}\">
                            <label>Role</label>
                            <select name=\"role_id\">
                                {% for role in roles %}
                                    <option value=\"{{ role.id }}\" {% if role.id == user.role_id %}selected{% endif %}>{{ role.name }}</option>
                                {% endfor %}
                            </select>
                            <label>New Password</label>
                            <input type=\"password\" name=\"password\" placeholder=\"Leave blank\">
                            <button type=\"submit\">Update</button>
                        </form>
                    </td>
                    <td>
                        {% if user.username not in ['admin', 'alice', 'bob'] %}
                            <a href=\"{{ url_for('manage_users', delete=user.id) }}\">Delete</a>
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
    return render_page("<h1>Forbidden</h1>", ), 403


@app.errorhandler(404)
def not_found(_):
    return render_page("<h1>Not Found</h1>"), 404


with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(debug=True)
