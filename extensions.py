from flaskext.mysql import MySQL
from flask_socketio import SocketIO

mysql = MySQL()

socketio = SocketIO(
    cors_allowed_origins="*",
    async_mode="threading",
    logger=True,
    engineio_logger=True
)