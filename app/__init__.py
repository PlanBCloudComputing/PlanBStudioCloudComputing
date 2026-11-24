"""Plan B Studio Flask app factory.

Purpose: build the Flask app, register every route blueprint and serve the two
operations endpoints used by Cloud Run and the scaling demo.
Important logic:
  * INSTANCE_ID is a random id made once when this process starts. Each Cloud Run
    instance therefore has its own id, so the scaling demo can show requests being
    spread across instances.
  * Every response carries an X-Served-By header with that id (API_SPEC.md).
  * The app is stateless: nothing is written to disk or kept between requests.
  * /api/v1/healthz never touches the database; /api/v1/readyz does, and answers 503
    when the database cannot be reached.
  * Each feature lives in app/routes/<resource>.py as a blueprint registered below.
"""
import os
import uuid

from flask import Flask, jsonify, redirect

# Generated once per process, never changes while the instance lives.
INSTANCE_ID = uuid.uuid4().hex[:8]


def create_app():
    """Build the app: register the route blueprints and the operations endpoints."""
    # Imported here so that importing this package never needs a database or secrets.
    from app import db
    from app.routes.auth import auth_bp
    from app.routes.decisions import decisions_bp
    from app.routes.members import members_bp

    app = Flask(__name__)
    app.register_blueprint(auth_bp)
    app.register_blueprint(members_bp)
    app.register_blueprint(decisions_bp)

    @app.after_request
    def add_instance_header(response):
        response.headers["X-Served-By"] = INSTANCE_ID
        return response

    @app.get("/")
    def home():
        # The web screens live in app/static; send visitors of the bare URL to the start page.
        return redirect("/static/index.html")

    @app.get("/api/v1/healthz")
    def healthz():
        # No database call: checks the process is alive. Under /api/v1 because
        # Cloud Run's frontend reserves the bare /healthz path (it never reaches us).
        return jsonify(status="ok")

    @app.get("/api/v1/readyz")
    def readyz():
        # Ready only if the database answers; Cloud Run or a person can check this.
        try:
            with db.get_conn("viewer") as conn:
                conn.execute("SELECT 1")
        except Exception:
            response = jsonify(error="database_unavailable", message="Database is not reachable")
            response.status_code = 503
            response.headers["Retry-After"] = "5"
            return response
        return jsonify(status="ready")

    @app.get("/api/v1/whoami")
    def whoami():
        # K_REVISION is set by Cloud Run; "local" when running on a laptop.
        return jsonify(instance_id=INSTANCE_ID, revision=os.environ.get("K_REVISION", "local"))

    return app
