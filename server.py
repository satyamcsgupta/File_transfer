
from flask import (
    Flask, request, jsonify, send_file,
    render_template, redirect, url_for, session
)
from werkzeug.exceptions import RequestEntityTooLarge
from contextlib import closing
from functools import wraps
from dotenv import load_dotenv
from pathlib import Path
import hmac
import os
import re
import secrets
import stat
import uuid
import sqlite3

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

app = Flask(__name__, template_folder=str(BASE_DIR / "templates"))

APP_ENV = os.getenv("APP_ENV", "development").strip().lower()
if APP_ENV not in {"development", "production"}:
    raise RuntimeError("APP_ENV must be 'development' or 'production'")

secret_key = os.getenv("SECRET_KEY")
VAULT_PASSWORD = os.getenv("VAULT_PASSWORD")

if not secret_key or not VAULT_PASSWORD:
    raise RuntimeError("SECRET_KEY or VAULT_PASSWORD missing in .env")

if APP_ENV == "production" and len(secret_key) < 32:
    raise RuntimeError("Production SECRET_KEY must be at least 32 characters")

secure_cookie_setting = os.getenv("SESSION_COOKIE_SECURE")
if secure_cookie_setting is None:
    session_cookie_secure = APP_ENV == "production"
elif secure_cookie_setting.lower() in {"1", "true", "yes"}:
    session_cookie_secure = True
elif secure_cookie_setting.lower() in {"0", "false", "no"}:
    session_cookie_secure = False
else:
    raise RuntimeError("SESSION_COOKIE_SECURE must be a boolean value")

if APP_ENV == "production" and not session_cookie_secure:
    raise RuntimeError("SESSION_COOKIE_SECURE must be enabled in production")

try:
    max_content_length = int(
        os.getenv("MAX_CONTENT_LENGTH", str(100 * 1024 * 1024))
    )
except ValueError as exc:
    raise RuntimeError("MAX_CONTENT_LENGTH must be a positive integer") from exc

if max_content_length <= 0:
    raise RuntimeError("MAX_CONTENT_LENGTH must be a positive integer")

app.config.update(
    SECRET_KEY=secret_key,
    TEMPLATES_AUTO_RELOAD=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=session_cookie_secure,
    MAX_CONTENT_LENGTH=max_content_length,
)

DATA_DIR = Path(
    os.getenv("VAULT_DATA_DIR", str(BASE_DIR))
).expanduser().resolve()

UPLOAD_FOLDER = DATA_DIR / "uploads"
DB_PATH = DATA_DIR / "files.db"

FILE_ID_PATTERN = re.compile(r"RV-[0-9]{4,}\Z")

STORED_FILENAME_PATTERN = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}\.bin\Z"
)

DATA_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)


def init_db():
    with closing(sqlite3.connect(DB_PATH)) as conn, conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id TEXT UNIQUE,
                original_filename TEXT NOT NULL,
                stored_filename TEXT NOT NULL,
                uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)


init_db()


def login_required(route_function):
    @wraps(route_function)
    def wrapper(*args, **kwargs):
        if not session.get("authenticated"):
            if request.path.startswith("/api/") or request.endpoint == "upload_file":
                return jsonify({"error": "Authentication required"}), 401
            return redirect(url_for("home"))

        return route_function(*args, **kwargs)

    return wrapper


def get_csrf_token():
    token = session.get("_csrf_token")

    if not isinstance(token, str):
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token

    return token


@app.context_processor
def inject_csrf_token():
    return {"csrf_token": get_csrf_token}


def has_valid_csrf_token():
    expected = session.get("_csrf_token")
    supplied = (
        request.form.get("csrf_token")
        or request.headers.get("X-CSRF-Token", "")
    )

    return (
        isinstance(expected, str)
        and bool(supplied)
        and hmac.compare_digest(supplied, expected)
    )


def csrf_required(route_function):
    @wraps(route_function)
    def wrapper(*args, **kwargs):
        if not has_valid_csrf_token():
            return jsonify({"error": "Invalid or missing CSRF token"}), 400

        return route_function(*args, **kwargs)

    return wrapper


@app.errorhandler(RequestEntityTooLarge)
def handle_request_too_large(_error):
    return jsonify({
        "error": "Upload exceeds the configured size limit"
    }), 413


def resolve_upload_path(stored_filename):
    if (
        not isinstance(stored_filename, str)
        or not STORED_FILENAME_PATTERN.fullmatch(stored_filename)
    ):
        raise ValueError("Invalid stored filename")

    upload_root = UPLOAD_FOLDER.resolve(strict=True)
    candidate = upload_root / stored_filename

    if candidate.is_symlink():
        raise ValueError("Stored file cannot be a symbolic link")

    resolved_path = candidate.resolve(strict=False)

    if resolved_path.parent != upload_root:
        raise ValueError("Stored file is outside the upload directory")

    return resolved_path


def restore_quarantined_file(quarantined_path, original_path):
    if quarantined_path is None:
        return True

    try:
        quarantined_path.lstat()
    except FileNotFoundError:
        return True
    except OSError:
        app.logger.exception(
            "Unable to inspect a staged file after a deletion error"
        )
        return False

    try:
        os.replace(quarantined_path, original_path)
        return True
    except OSError:
        app.logger.exception(
            "Failed to restore a file after a deletion error"
        )
        return False


@app.route("/", methods=["GET", "POST"])
def home():
    if session.get("authenticated"):
        return render_template("index.html")

    if request.method == "POST":
        if not has_valid_csrf_token():
            return render_template(
                "login.html",
                error="Your login form expired. Please try again."
            ), 400

        entered_password = request.form.get("password", "")

        if hmac.compare_digest(entered_password, VAULT_PASSWORD):
            session.clear()
            session["authenticated"] = True
            session["_csrf_token"] = secrets.token_urlsafe(32)

            return redirect(url_for("home"))

        return render_template(
            "login.html",
            error="Incorrect password. Please try again."
        ), 401

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
@csrf_required
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/upload", methods=["POST"])
@login_required
@csrf_required
def upload_file():
    uploaded_file = request.files.get("file")

    if not uploaded_file or not uploaded_file.filename:
        return jsonify({"error": "No file received"}), 400

    original_filename = Path(uploaded_file.filename).name
    stored_filename = str(uuid.uuid4()) + ".bin"
    file_path = UPLOAD_FOLDER / stored_filename

    try:
        uploaded_file.save(str(file_path))
    except OSError:
        try:
            file_path.unlink(missing_ok=True)
        except OSError:
            app.logger.exception("Unable to remove partial upload")

        app.logger.exception("Unable to store uploaded file")
        return jsonify({"error": "Unable to store uploaded file"}), 500

    try:
        with closing(sqlite3.connect(DB_PATH)) as conn, conn:
            cursor = conn.execute("""
                INSERT INTO files (
                    original_filename,
                    stored_filename
                )
                VALUES (?, ?)
            """, (original_filename, stored_filename))

            file_id = f"RV-{cursor.lastrowid:04d}"

            conn.execute("""
                UPDATE files
                SET file_id = ?
                WHERE id = ?
            """, (file_id, cursor.lastrowid))

        return jsonify({
            "message": "File uploaded successfully!",
            "file_id": file_id,
            "filename": original_filename
        })

    except sqlite3.Error:
        try:
            file_path.unlink(missing_ok=True)
        except OSError:
            app.logger.exception(
                "Unable to remove upload after database error"
            )

        app.logger.exception("Database error while recording uploaded file")
        return jsonify({"error": "Database error"}), 500


@app.route("/api/files")
@login_required
def get_files():
    with closing(sqlite3.connect(DB_PATH)) as conn, conn:
        conn.row_factory = sqlite3.Row

        rows = conn.execute("""
            SELECT file_id, original_filename, uploaded_at
            FROM files
            ORDER BY id DESC
        """).fetchall()

    return jsonify([dict(row) for row in rows])


@app.route("/download/<file_id>")
@login_required
def download_file(file_id):
    if not FILE_ID_PATTERN.fullmatch(file_id):
        return jsonify({"error": "File not found"}), 404

    with closing(sqlite3.connect(DB_PATH)) as conn, conn:
        conn.row_factory = sqlite3.Row

        file_record = conn.execute("""
            SELECT original_filename, stored_filename
            FROM files
            WHERE file_id = ?
        """, (file_id,)).fetchone()

    if not file_record:
        return jsonify({"error": "File not found"}), 404

    filename = file_record["original_filename"]

    try:
        file_path = resolve_upload_path(file_record["stored_filename"])
    except (OSError, ValueError):
        app.logger.warning(
            "Stored file path is invalid for File ID %s", file_id
        )
        return jsonify({"error": "File is unavailable"}), 500

    if not file_path.is_file():
        return jsonify({"error": "File not found"}), 404

    return send_file(
        file_path,
        as_attachment=True,
        download_name=filename
    )


@app.route("/api/files/<file_id>", methods=["DELETE"])
@login_required
@csrf_required
def delete_file(file_id):
    if not FILE_ID_PATTERN.fullmatch(file_id):
        return jsonify({"error": "Invalid file ID"}), 400

    connection = None
    quarantined_path = None
    file_path = None
    file_record = None
    file_missing = False

    try:
        connection = sqlite3.connect(DB_PATH, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("BEGIN IMMEDIATE")

        file_record = connection.execute("""
            SELECT id, file_id, original_filename, stored_filename, uploaded_at
            FROM files
            WHERE file_id = ?
        """, (file_id,)).fetchone()

        if not file_record:
            connection.rollback()
            return jsonify({"error": "File not found"}), 404

        try:
            file_path = resolve_upload_path(file_record["stored_filename"])
        except (OSError, ValueError):
            connection.rollback()
            app.logger.warning(
                "Stored file path is invalid for File ID %s", file_id
            )
            return jsonify({"error": "Stored file is unavailable"}), 500

        try:
            file_stat = file_path.lstat()
        except FileNotFoundError:
            file_missing = True
        except OSError:
            connection.rollback()
            app.logger.exception(
                "Unable to inspect stored file for File ID %s", file_id
            )
            return jsonify({"error": "Unable to access stored file"}), 500
        else:
            if not stat.S_ISREG(file_stat.st_mode):
                connection.rollback()
                return jsonify({"error": "Stored file is unavailable"}), 500

            quarantined_path = (
                file_path.parent / f".{uuid.uuid4().hex}.pending-delete"
            )
            os.replace(file_path, quarantined_path)

        connection.execute(
            "DELETE FROM files WHERE id = ?",
            (file_record["id"],)
        )
        connection.commit()

    except sqlite3.Error:
        if connection is not None:
            connection.rollback()

        restore_quarantined_file(quarantined_path, file_path)

        app.logger.exception("Database error deleting File ID %s", file_id)
        return jsonify({"error": "Unable to delete file"}), 500

    except OSError:
        if connection is not None:
            connection.rollback()

        restore_quarantined_file(quarantined_path, file_path)

        app.logger.exception("Filesystem error deleting File ID %s", file_id)
        return jsonify({"error": "Unable to delete file"}), 500

    finally:
        if connection is not None:
            connection.close()

    if quarantined_path is not None:
        try:
            quarantined_path.unlink()
        except OSError:
            try:
                quarantined_path.lstat()
            except FileNotFoundError:
                pass
            except OSError:
                app.logger.exception(
                    "Unable to inspect staged file after cleanup failed "
                    "for File ID %s",
                    file_id
                )
                return jsonify({
                    "error": "Deletion could not be completed; "
                             "file state needs attention"
                }), 500
            else:
                try:
                    os.replace(quarantined_path, file_path)

                    with closing(
                        sqlite3.connect(DB_PATH, timeout=5)
                    ) as restore_connection, restore_connection:
                        restore_connection.execute("""
                            INSERT INTO files (
                                id, file_id, original_filename,
                                stored_filename, uploaded_at
                            )
                            VALUES (?, ?, ?, ?, ?)
                        """, (
                            file_record["id"],
                            file_record["file_id"],
                            file_record["original_filename"],
                            file_record["stored_filename"],
                            file_record["uploaded_at"],
                        ))

                except (OSError, sqlite3.Error):
                    app.logger.exception(
                        "Failed to restore database and file state "
                        "for File ID %s",
                        file_id
                    )
                    return jsonify({
                        "error": "Deletion could not be completed; "
                                 "file state needs attention"
                    }), 500

                return jsonify({
                    "error": "Unable to permanently remove file"
                }), 500

    return jsonify({
        "message": "File deleted successfully" if not file_missing
        else "File record deleted; the uploaded file was already missing",
        "file_id": file_id,
        "file_missing": file_missing,
    })


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
