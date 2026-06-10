from flask import Flask
from config import Config
from extensions import mysql, socketio


# =========================
# CREATE APP
# =========================

def create_app():

    app = Flask(__name__)

    app.config.from_object(Config)
    app.secret_key = app.config["SECRET_KEY"]

    # Init MySQL
    mysql.init_app(app)

    # Init SocketIO
    socketio.init_app(
        app,
        cors_allowed_origins="*",
        async_mode="threading",
        transports=["polling"]   # Windows-safe
    )

    from modules.auth import auth_bp
    from modules.employee import employee_bp
    from modules.admin import admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(employee_bp)
    app.register_blueprint(admin_bp)

    @app.after_request
    def no_cache(response):

        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"

        return response

    return app


# =========================
# CREATE APP INSTANCE
# =========================

app = create_app()


# =========================
# SOCKET.IO ADMIN NAMESPACE
# =========================

@socketio.on("connect", namespace="/admin")
def admin_connect():
    print("✅ Admin connected to Live Monitor")


@socketio.on("disconnect", namespace="/admin")
def admin_disconnect():
    print("❌ Admin disconnected from Live Monitor")


# =========================
# RUN SERVER
# =========================

if __name__ == "__main__":

    print("🔹 http://127.0.0.1:5000")

    socketio.run(
        app,
        host="0.0.0.0",
        port=5000,
        debug=True
    )
