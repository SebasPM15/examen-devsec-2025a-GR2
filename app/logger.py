from .db import get_connection
from datetime import datetime

def sanitize(value: str, max_len: int = 255) -> str:
    if not isinstance(value, str):
        value = str(value)
    value = value.replace('\n', ' ').replace('\r', ' ').strip()
    return value[:max_len]

def write_log(log_type: str, ip_address: str, username: str, action: str, http_status: int):
    conn = get_connection()
    cur = conn.cursor()
    try:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

        cur.execute("""
            INSERT INTO logs_repo.app_logs (
                timestamp, log_type, ip_address, username, action, http_status
            ) VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            sanitize(timestamp),
            sanitize(log_type.upper(), 10),
            sanitize(ip_address, 50),
            sanitize(username, 50),
            sanitize(action, 255),
            int(http_status)
        ))
        conn.commit()
    except Exception as e:
        print(f"No se pudo guardar el log: {e}")
        conn.rollback()
    finally:
        cur.close()
        conn.close()
