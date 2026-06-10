import os
from datetime import time

class Config:
    SECRET_KEY = "filesentinel_secret"

    MYSQL_DATABASE_HOST = "localhost"
    MYSQL_DATABASE_USER = "root"
    MYSQL_DATABASE_PASSWORD = "root"
    MYSQL_DATABASE_DB = "filesentinel"

    FILE_STORAGE = os.path.join(os.getcwd(), "storage/files")
    BACKUP_STORAGE = os.path.join(os.getcwd(), "storage/backups")
    PENDING_STORAGE = os.path.join(os.getcwd(), "storage/pending")
    PROFILE_STORAGE = os.path.join(os.getcwd(), "static/images/profiles")
    TEMP_STORAGE = os.path.join(os.getcwd(), "storage/temp") 





    # 🔐 FIXED, PERSISTENT ENCRYPTION KEY
    ENCRYPTION_KEY = b'bvqkcW5VSMnHxxLLVUnvkqehyKHMyH4dIGNrR2MbuwY='

    WORK_START = time(9, 0, 0)
    WORK_END   = time(18, 0, 0)
