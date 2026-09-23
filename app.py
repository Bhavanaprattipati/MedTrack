from flask import (
    Flask,
    request,
    session,
    redirect,
    url_for,
    render_template,
    flash
)

import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import uuid
import os


# ============================================================
# Flask App Initialization
# ============================================================

app = Flask(__name__)

app.secret_key = "medtrack_secret_key"


# ============================================================
# Database Configuration
# ============================================================

DATABASE = "medtrack.db"


# ============================================================
# Database Connection
# ============================================================

def get_db_connection():
    """
    Create and return a connection to the SQLite database.
    """

    conn = sqlite3.connect(DATABASE)

    # Allows us to access columns using column names
    conn.row_factory = sqlite3.Row

    return conn


# ============================================================
# Initialize Database
# ============================================================

def init_db():

    conn = get_db_connection()

    cursor = conn.cursor()

    # --------------------------------------------------------
    # Users Table
    # --------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            password TEXT NOT NULL,
            age INTEGER,
            phone TEXT,
            role TEXT NOT NULL,
            medical_history TEXT,
            login_count INTEGER DEFAULT 0,
            created_at TEXT
        )
    """)

    # --------------------------------------------------------
    # Appointments Table
    # --------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS appointments (
            appointment_id TEXT PRIMARY KEY,
            doctor_email TEXT NOT NULL,
            doctor_name TEXT,
            patient_email TEXT NOT NULL,
            patient_name TEXT,
            appointment_date TEXT,
            appointment_time TEXT,
            symptoms TEXT,
            diagnosis TEXT,
            treatment_plan TEXT,
            prescription TEXT,
            follow_up TEXT,
            status TEXT DEFAULT 'pending',
            created_at TEXT
        )
    """)

    conn.commit()

    conn.close()


# ============================================================
# Helper Functions
# ============================================================

def is_logged_in():
    """
    Check whether a user is currently logged in.
    """

    return "email" in session


def get_user_role(email):
    """
    Get the role of a user using their email.
    """

    conn = get_db_connection()

    user = conn.execute(
        """
        SELECT role
        FROM users
        WHERE email = ?
        """,
        (email,)
    ).fetchone()

    conn.close()

    if user:
        return user["role"]

    return None


def get_user(email):
    """
    Get complete user details.
    """

    conn = get_db_connection()

    user = conn.execute(
        """
        SELECT *
        FROM users
        WHERE email = ?
        """,
        (email,)
    ).fetchone()

    conn.close()

    return user


# ============================================================
# Home Page
# ============================================================

@app.route("/")
def index():

    if is_logged_in():

        return redirect(
            url_for("dashboard")
        )

    return render_template(
        "index.html"
    )


# ============================================================
# Register User
# ============================================================

@app.route(
    "/register",
    methods=["GET", "POST"]
)
def register():

    # If already logged in
    if is_logged_in():

        return redirect(
            url_for("dashboard")
        )

    if request.method == "POST":

        # ----------------------------------------------------
        # Get Form Data
        # ----------------------------------------------------

        name = request.form.get(
            "name",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        age = request.form.get(
            "age",
            ""
        ).strip()

        role = request.form.get(
            "role",
            ""
        ).strip().lower()

        # ----------------------------------------------------
        # Validate Required Fields
        # ----------------------------------------------------

        if not name or not email or not password or not role:

            flash(
                "Please fill in all required fields.",
                "danger"
            )

            return render_template(
                "register.html"
            )

        # ----------------------------------------------------
        # Validate Password
        # ----------------------------------------------------

        if password != confirm_password:

            flash(
                "Passwords do not match.",
                "danger"
            )

            return render_template(
                "register.html"
            )

        # ----------------------------------------------------
        # Validate Role
        # ----------------------------------------------------

        if role not in ["doctor", "patient"]:

            flash(
                "Invalid role selected.",
                "danger"
            )

            return render_template(
                "register.html"
            )

        # ----------------------------------------------------
        # Check Existing User
        # ----------------------------------------------------

        conn = get_db_connection()

        existing_user = conn.execute(
            """
            SELECT email
            FROM users
            WHERE email = ?
            """,
            (email,)
        ).fetchone()

        if existing_user:

            conn.close()

            flash(
                "An account with this email already exists.",
                "danger"
            )

            return render_template(
                "register.html"
            )

        # ----------------------------------------------------
        # Hash Password
        # ----------------------------------------------------

        hashed_password = generate_password_hash(
            password
        )

        # ----------------------------------------------------
        # Insert User
        # ----------------------------------------------------

        conn.execute(
            """
            INSERT INTO users (
                email,
                name,
                password,
                age,
                role,
                login_count,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                email,
                name,
                hashed_password,
                age if age else None,
                role,
                0,
                datetime.now().isoformat()
            )
        )

        conn.commit()

        conn.close()

        flash(
            "Registration successful. Please log in.",
            "success"
        )

        return redirect(
            url_for("login")
        )

    return render_template(
        "register.html"
    )


# ============================================================
# Login Route
# ============================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if is_logged_in():

        return redirect(
            url_for("dashboard")
        )

    if request.method == "POST":

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        role = request.form.get(
            "role",
            ""
        ).strip().lower()

        # ----------------------------------------------------
        # Validate Input
        # ----------------------------------------------------

        if not email or not password or not role:

            flash(
                "Please fill in all required fields.",
                "danger"
            )

            return render_template(
                "login.html"
            )

        # ----------------------------------------------------
        # Find User
        # ----------------------------------------------------

        conn = get_db_connection()

        user = conn.execute(
            """
            SELECT *
            FROM users
            WHERE email = ?
            """,
            (email,)
        ).fetchone()

        # ----------------------------------------------------
        # User Not Found
        # ----------------------------------------------------

        if not user:

            conn.close()

            flash(
                "Email not found.",
                "danger"
            )

            return render_template(
                "login.html"
            )

        # ----------------------------------------------------
        # Verify Password
        # ----------------------------------------------------

        if not check_password_hash(
            user["password"],
            password
        ):

            conn.close()

            flash(
                "Invalid password.",
                "danger"
            )

            return render_template(
                "login.html"
            )

        # ----------------------------------------------------
        # Verify Role
        # ----------------------------------------------------

        if user["role"] != role:

            conn.close()

            flash(
                "Invalid role selected.",
                "danger"
            )

            return render_template(
                "login.html"
            )

        # ----------------------------------------------------
        # Store Session
        # ----------------------------------------------------

        session["email"] = user["email"]

        session["role"] = user["role"]

        session["name"] = user["name"]

        # ----------------------------------------------------
        # Update Login Count
        # ----------------------------------------------------

        conn.execute(
            """
            UPDATE users
            SET login_count = login_count + 1
            WHERE email = ?
            """,
            (email,)
        )

        conn.commit()

        conn.close()

        flash(
            "Login successful.",
            "success"
        )

        return redirect(
            url_for("dashboard")
        )

    return render_template(
        "login.html"
    )


# ============================================================
# Logout Route
# ============================================================

@app.route("/logout")
def logout():

    session.clear()

    flash(
        "You have been logged out.",
        "success"
    )

    return redirect(
        url_for("index")
    )


# ============================================================
# Dashboard
# ============================================================

@app.route("/dashboard")
def dashboard():

    if not is_logged_in():

        flash(
            "Please log in to continue.",
            "danger"
        )

        return redirect(
            url_for("login")
        )

    role = session["role"]

    email = session["email"]

    conn = get_db_connection()

    # ========================================================
    # Doctor Dashboard
    # ========================================================

    if role == "doctor":

        appointments = conn.execute(
            """
            SELECT *
            FROM appointments
            WHERE doctor_email = ?
            ORDER BY appointment_date, appointment_time
            """,
            (email,)
        ).fetchall()

        conn.close()

        return render_template(
            "doctor_dashboard.html",
            appointments=appointments
        )

    # ========================================================
    # Patient Dashboard
    # ========================================================

    elif role == "patient":

        appointments = conn.execute(
            """
            SELECT *
            FROM appointments
            WHERE patient_email = ?
            ORDER BY appointment_date, appointment_time
            """,
            (email,)
        ).fetchall()

        # Get all doctors

        doctors = conn.execute(
            """
            SELECT email, name, age
            FROM users
            WHERE role = 'doctor'
            ORDER BY name
            """
        ).fetchall()

        conn.close()

        return render_template(
            "patient_dashboard.html",
            appointments=appointments,
            doctors=doctors
        )

    conn.close()

    return redirect(
        url_for("login")
    )


# ============================================================
# Book Appointment
# ============================================================

@app.route(
    "/book_appointment",
    methods=["GET", "POST"]
)
def book_appointment():

    if not is_logged_in():

        flash(
            "Please log in to continue.",
            "danger"
        )

        return redirect(
            url_for("login")
        )

    if session["role"] != "patient":

        flash(
            "Only patients can book appointments.",
            "danger"
        )

        return redirect(
            url_for("dashboard")
        )

    # ========================================================
    # POST - Book Appointment
    # ========================================================

    if request.method == "POST":

        doctor_email = request.form.get(
            "doctor_email",
            ""
        ).strip().lower()

        symptoms = request.form.get(
            "symptoms",
            ""
        ).strip()

        appointment_date = request.form.get(
            "appointment_date",
            ""
        ).strip()

        appointment_time = request.form.get(
            "appointment_time",
            ""
        ).strip()

        # ----------------------------------------------------
        # Validation
        # ----------------------------------------------------

        if (
            not doctor_email
            or not symptoms
            or not appointment_date
            or not appointment_time
        ):

            flash(
                "Please fill in all required appointment details.",
                "danger"
            )

            return redirect(
                url_for("book_appointment")
            )

        patient_email = session["email"]

        conn = get_db_connection()

        # ----------------------------------------------------
        # Get Patient
        # ----------------------------------------------------

        patient = conn.execute(
            """
            SELECT *
            FROM users
            WHERE email = ?
            """,
            (patient_email,)
        ).fetchone()

        # ----------------------------------------------------
        # Get Doctor
        # ----------------------------------------------------

        doctor = conn.execute(
            """
            SELECT *
            FROM users
            WHERE email = ?
            AND role = 'doctor'
            """,
            (doctor_email,)
        ).fetchone()

        if not doctor:

            conn.close()

            flash(
                "Selected doctor was not found.",
                "danger"
            )

            return redirect(
                url_for("book_appointment")
            )

        # ----------------------------------------------------
        # Check Existing Appointment
        # ----------------------------------------------------

        existing = conn.execute(
            """
            SELECT appointment_id
            FROM appointments
            WHERE doctor_email = ?
            AND appointment_date = ?
            AND appointment_time = ?
            AND status != 'cancelled'
            """,
            (
                doctor_email,
                appointment_date,
                appointment_time
            )
        ).fetchone()

        if existing:

            conn.close()

            flash(
                "This time slot is already booked.",
                "danger"
            )

            return redirect(
                url_for("book_appointment")
            )

        # ----------------------------------------------------
        # Create Appointment ID
        # ----------------------------------------------------

        appointment_id = str(
            uuid.uuid4()
        )

        # ----------------------------------------------------
        # Insert Appointment
        # ----------------------------------------------------

        conn.execute(
            """
            INSERT INTO appointments (
                appointment_id,
                doctor_email,
                doctor_name,
                patient_email,
                patient_name,
                appointment_date,
                appointment_time,
                symptoms,
                status,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                appointment_id,
                doctor_email,
                doctor["name"],
                patient_email,
                patient["name"],
                appointment_date,
                appointment_time,
                symptoms,
                "pending",
                datetime.now().isoformat()
            )
        )

        conn.commit()

        conn.close()

        flash(
            "Appointment booked successfully.",
            "success"
        )

        return redirect(
            url_for("dashboard")
        )

    # ========================================================
    # GET - Display Doctors
    # ========================================================

    conn = get_db_connection()

    doctors = conn.execute(
        """
        SELECT *
        FROM users
        WHERE role = 'doctor'
        ORDER BY name
        """
    ).fetchall()

    conn.close()

    return render_template(
        "book_appointment.html",
        doctors=doctors
    )


# ============================================================
# View Appointment
# ============================================================

@app.route(
    "/view_appointment/<appointment_id>",
    methods=["GET", "POST"]
)
def view_appointment(appointment_id):

    if not is_logged_in():

        flash(
            "Please log in to continue.",
            "danger"
        )

        return redirect(
            url_for("login")
        )

    conn = get_db_connection()

    # --------------------------------------------------------
    # Get Appointment
    # --------------------------------------------------------

    appointment = conn.execute(
        """
        SELECT *
        FROM appointments
        WHERE appointment_id = ?
        """,
        (appointment_id,)
    ).fetchone()

    if not appointment:

        conn.close()

        flash(
            "Appointment not found.",
            "danger"
        )

        return redirect(
            url_for("dashboard")
        )

    # --------------------------------------------------------
    # Authorization Check
    # --------------------------------------------------------

    user_email = session["email"]

    if session["role"] == "doctor":

        if appointment["doctor_email"] != user_email:

            conn.close()

            flash(
                "You are not authorized to view this appointment.",
                "danger"
            )

            return redirect(
                url_for("dashboard")
            )

    elif session["role"] == "patient":

        if appointment["patient_email"] != user_email:

            conn.close()

            flash(
                "You are not authorized to view this appointment.",
                "danger"
            )

            return redirect(
                url_for("dashboard")
            )

    # ========================================================
    # Doctor Submits Diagnosis
    # ========================================================

    if (
        request.method == "POST"
        and session["role"] == "doctor"
    ):

        diagnosis = request.form.get(
            "diagnosis",
            ""
        ).strip()

        treatment_plan = request.form.get(
            "treatment_plan",
            ""
        ).strip()

        prescription = request.form.get(
            "prescription",
            ""
        ).strip()

        follow_up = request.form.get(
            "follow_up",
            ""
        ).strip()

        # ----------------------------------------------------
        # Update Appointment
        # ----------------------------------------------------

        conn.execute(
            """
            UPDATE appointments
            SET
                diagnosis = ?,
                treatment_plan = ?,
                prescription = ?,
                follow_up = ?,
                status = ?
            WHERE appointment_id = ?
            """,
            (
                diagnosis,
                treatment_plan,
                prescription,
                follow_up,
                "completed",
                appointment_id
            )
        )

        conn.commit()

        # Refresh appointment

        appointment = conn.execute(
            """
            SELECT *
            FROM appointments
            WHERE appointment_id = ?
            """,
            (appointment_id,)
        ).fetchone()

        flash(
            "Diagnosis submitted successfully.",
            "success"
        )

    conn.close()

    # --------------------------------------------------------
    # Display Correct Page Based on Role
    # --------------------------------------------------------

    if session["role"] == "doctor":

        return render_template(
            "view_appointment_doctor.html",
            appointment=appointment
        )

    return render_template(
        "view_appointment_patient.html",
        appointment=appointment
    )


# ============================================================
# Submit Diagnosis Route
# ============================================================

@app.route(
    "/submit_diagnosis/<appointment_id>",
    methods=["POST"]
)
def submit_diagnosis(appointment_id):

    if not is_logged_in():

        flash(
            "Please log in to continue.",
            "danger"
        )

        return redirect(
            url_for("login")
        )

    # Only doctor can submit diagnosis

    if session["role"] != "doctor":

        flash(
            "Only doctors can submit diagnosis.",
            "danger"
        )

        return redirect(
            url_for("dashboard")
        )

    conn = get_db_connection()

    # --------------------------------------------------------
    # Get Appointment
    # --------------------------------------------------------

    appointment = conn.execute(
        """
        SELECT *
        FROM appointments
        WHERE appointment_id = ?
        """,
        (appointment_id,)
    ).fetchone()

    if not appointment:

        conn.close()

        flash(
            "Appointment not found.",
            "danger"
        )

        return redirect(
            url_for("dashboard")
        )

    # --------------------------------------------------------
    # Verify Doctor Ownership
    # --------------------------------------------------------

    if appointment["doctor_email"] != session["email"]:

        conn.close()

        flash(
            "You are not authorized to submit diagnosis.",
            "danger"
        )

        return redirect(
            url_for("dashboard")
        )

    # --------------------------------------------------------
    # Get Diagnosis Data
    # --------------------------------------------------------

    diagnosis = request.form.get(
        "diagnosis",
        ""
    ).strip()

    treatment_plan = request.form.get(
        "treatment_plan",
        ""
    ).strip()

    prescription = request.form.get(
        "prescription",
        ""
    ).strip()

    follow_up = request.form.get(
        "follow_up",
        ""
    ).strip()

    # --------------------------------------------------------
    # Update Database
    # --------------------------------------------------------

    conn.execute(
        """
        UPDATE appointments
        SET
            diagnosis = ?,
            treatment_plan = ?,
            prescription = ?,
            follow_up = ?,
            status = ?
        WHERE appointment_id = ?
        """,
        (
            diagnosis,
            treatment_plan,
            prescription,
            follow_up,
            "completed",
            appointment_id
        )
    )

    conn.commit()

    conn.close()

    flash(
        "Diagnosis submitted successfully.",
        "success"
    )

    return redirect(
        url_for(
            "view_appointment",
            appointment_id=appointment_id
        )
    )


# ============================================================
# Search Appointments
# ============================================================

@app.route("/search")
def search_appointments():

    if not is_logged_in():

        flash(
            "Please log in to continue.",
            "danger"
        )

        return redirect(
            url_for("login")
        )

    search_term = request.args.get(
        "search",
        ""
    ).strip()

    email = session["email"]

    role = session["role"]

    conn = get_db_connection()

    # ========================================================
    # Doctor Search
    # ========================================================

    if role == "doctor":

        appointments = conn.execute(
            """
            SELECT *
            FROM appointments
            WHERE doctor_email = ?
            AND (
                patient_name LIKE ?
                OR patient_email LIKE ?
                OR appointment_date LIKE ?
                OR status LIKE ?
            )
            ORDER BY appointment_date, appointment_time
            """,
            (
                email,
                f"%{search_term}%",
                f"%{search_term}%",
                f"%{search_term}%",
                f"%{search_term}%"
            )
        ).fetchall()

    # ========================================================
    # Patient Search
    # ========================================================

    else:

        appointments = conn.execute(
            """
            SELECT *
            FROM appointments
            WHERE patient_email = ?
            AND (
                doctor_name LIKE ?
                OR doctor_email LIKE ?
                OR appointment_date LIKE ?
                OR status LIKE ?
            )
            ORDER BY appointment_date, appointment_time
            """,
            (
                email,
                f"%{search_term}%",
                f"%{search_term}%",
                f"%{search_term}%",
                f"%{search_term}%"
            )
        ).fetchall()

    conn.close()

    return render_template(
        "search_results.html",
        appointments=appointments,
        search_term=search_term
    )


# ============================================================
# Profile Route
# ============================================================

@app.route(
    "/profile",
    methods=["GET", "POST"]
)
def profile():

    if not is_logged_in():

        flash(
            "Please log in to continue.",
            "danger"
        )

        return redirect(
            url_for("login")
        )

    email = session["email"]

    conn = get_db_connection()

    # ========================================================
    # Update Profile
    # ========================================================

    if request.method == "POST":

        name = request.form.get(
            "name",
            ""
        ).strip()

        age = request.form.get(
            "age",
            ""
        ).strip()

        phone = request.form.get(
            "phone",
            ""
        ).strip()

        medical_history = request.form.get(
            "medical_history",
            ""
        ).strip()

        if not name:

            flash(
                "Name cannot be empty.",
                "danger"
            )

        else:

            conn.execute(
                """
                UPDATE users
                SET
                    name = ?,
                    age = ?,
                    phone = ?,
                    medical_history = ?
                WHERE email = ?
                """,
                (
                    name,
                    age if age else None,
                    phone,
                    medical_history,
                    email
                )
            )

            conn.commit()

            session["name"] = name

            flash(
                "Profile updated successfully.",
                "success"
            )

    # ========================================================
    # Get User Details
    # ========================================================

    user = conn.execute(
        """
        SELECT *
        FROM users
        WHERE email = ?
        """,
        (email,)
    ).fetchone()

    conn.close()

    return render_template(
        "profile.html",
        user=user
    )


# ============================================================
# Health Check Route
# ============================================================

@app.route("/health")
def health():

    return {
        "status": "healthy",
        "application": "MedTrack",
        "database": "SQLite",
        "timestamp": datetime.now().isoformat()
    }


# ============================================================
# Application Entry Point
# ============================================================

if __name__ == "__main__":

    # Create database and tables
    init_db()

    # Run Flask application
    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )