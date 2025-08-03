# app/db.py
import os
import psycopg2
from datetime import datetime

# Variables de entorno (definidas en docker-compose o con valores por defecto)
DB_HOST = os.environ.get('POSTGRES_HOST', 'db')
DB_PORT = os.environ.get('POSTGRES_PORT', '5432')
DB_NAME = os.environ.get('POSTGRES_DB', 'corebank')
DB_USER = os.environ.get('POSTGRES_USER', 'postgres')
DB_PASSWORD = os.environ.get('POSTGRES_PASSWORD', 'postgres')

def get_connection():
    conn = psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )
    return conn

def init_db():
    conn = get_connection()
    cur = conn.cursor()
    
    # Crear la tabla de usuarios
    cur.execute("""
    CREATE SCHEMA IF NOT EXISTS bank AUTHORIZATION postgres;
    
    CREATE TABLE IF NOT EXISTS bank.users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        full_name TEXT,
        email TEXT
    ); 
    """) # -> Se quitó el 'commit;' de aquí
    conn.commit()
    
    # Crear la tabla de cuentas
    cur.execute("""
    CREATE TABLE IF NOT EXISTS bank.accounts (
        id SERIAL PRIMARY KEY,
        balance NUMERIC NOT NULL DEFAULT 0,
        user_id INTEGER REFERENCES bank.users(id)
    );
    """) # -> Se quitó el 'commit;' de aquí
    conn.commit()
    
    # Crear la tabla de tarjetas de crédito
    cur.execute("""
    CREATE TABLE IF NOT EXISTS bank.credit_cards (
        id SERIAL PRIMARY KEY,
        limit_credit NUMERIC NOT NULL DEFAULT 1,
        balance NUMERIC NOT NULL DEFAULT 0,
        user_id INTEGER REFERENCES bank.users(id)
    ); 
    """) # -> Se quitó el 'commit;' de aquí
    
    # Create tokens table to persist authentication tokens
    cur.execute("""
    CREATE TABLE IF NOT EXISTS bank.tokens (
        token TEXT PRIMARY KEY,
        user_id INTEGER REFERENCES bank.users(id),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ); 
    """) # -> Se quitó el 'commit;' de aquí
    
    conn.commit()
    # --- INICIO DE CAMBIOS (Parte de TCE-04) - Ivan Simbana ---
    
    # Crear la tabla de establecimientos
    cur.execute("""
    CREATE TABLE IF NOT EXISTS bank.establecimientos (
        id SERIAL PRIMARY KEY,
        nombre TEXT NOT NULL,
        direccion TEXT
    );
    """)
    conn.commit()

    # Crear la tabla de códigos OTP
    cur.execute("""
    CREATE TABLE IF NOT EXISTS bank.otp_codes (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES bank.users(id),
        code TEXT NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        used BOOLEAN NOT NULL DEFAULT FALSE
    );
    """)
    conn.commit()


    # --- INICIO DE CAMBIOS (Parte de TCE-04) - Mateo Pilco ---
    
    # Se crea un nuevo esquema para datos sensibles de tarjetas
    cur.execute("CREATE SCHEMA IF NOT EXISTS bank_secure AUTHORIZATION postgres;")
    conn.commit()

    # Tabla para guardar de forma segura los datos de tarjetas encriptados
    cur.execute("""
    CREATE TABLE IF NOT EXISTS bank_secure.encrypted_cards (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES bank.users(id),
        encrypted_card_number TEXT NOT NULL,
        encrypted_expiry_date TEXT NOT NULL,
        encrypted_cvv TEXT NOT NULL,
        card_last_4_digits TEXT NOT NULL -- Para mostrar al usuario de forma segura
    );
    """)
    conn.commit()
    # --- FIN DE CAMBIOS ---
    
    # Insertar datos de ejemplo si no existen usuarios
    cur.execute("SELECT COUNT(*) FROM bank.users;")
    count = cur.fetchone()[0]
    if count == 0:
        sample_users = [
            ('user1', 'pass1', 'cliente', 'Usuario Uno', 'user1@example.com'),
            ('user2', 'pass2', 'cliente', 'Usuario Dos', 'user2@example.com'),
            ('user3', 'pass3', 'cajero',  'Usuario Tres', 'user3@example.com')
        ]
        for username, password, role, full_name, email in sample_users:
            cur.execute("""
                INSERT INTO bank.users (username, password, role, full_name, email)
                VALUES (%s, %s, %s, %s, %s) RETURNING id;
            """, (username, password, role, full_name, email))
            user_id = cur.fetchone()[0]
            # Crear una cuenta con saldo inicial 1000
            cur.execute("""
                INSERT INTO bank.accounts (balance, user_id)
                VALUES (%s, %s); commit;
            """, (1000, user_id))
            # Crear una tarjeta de crédito con límite 5000 y deuda 0
            cur.execute("""
                INSERT INTO bank.credit_cards (limit_credit, balance, user_id)
                VALUES (%s, %s, %s); commit;
            """, (5000, 0, user_id))
        conn.commit()
    
    # Insertar establecimientos de ejemplo si no existen
    cur.execute("SELECT COUNT(*) FROM bank.establecimientos;")
    if cur.fetchone()[0] == 0:
        cur.execute("""
            INSERT INTO bank.establecimientos (nombre, direccion) VALUES
            ('Tienda ABC', 'Av. Siempre Viva 123'),
            ('Restaurante XYZ', 'Calle Falsa 456');
        """)
        conn.commit()
        
        # Crear esquema separado para logs
    cur.execute("""
    CREATE SCHEMA IF NOT EXISTS logs_repo AUTHORIZATION postgres;
    """)
    conn.commit()


    # Crear tabla de logs
    cur.execute("""
    CREATE TABLE IF NOT EXISTS logs_repo.app_logs (
        id SERIAL PRIMARY KEY,
        timestamp TIMESTAMP NOT NULL,
        log_type TEXT NOT NULL,        -- INFO, DEBUG, WARNING, ERROR
        ip_address TEXT NOT NULL,
        username TEXT NOT NULL,
        action TEXT NOT NULL,
        http_status INTEGER NOT NULL
    );
    """)
    conn.commit()

    cur.close()
    conn.close()

def establecimiento_valido(id_establecimiento: int) -> bool:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM bank.establecimientos WHERE id = %s", (id_establecimiento,))
    count = cur.fetchone()[0]
    cur.close()
    conn.close()
    return count > 0

def save_otp(user_id: int, code: str, expires_at: datetime):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO bank.otp_codes (user_id, code, expires_at, used)
        VALUES (%s, %s, %s, FALSE)
    """, (user_id, code, expires_at))
    conn.commit()
    cur.close()
    conn.close()

def validate_otp(user_id: int, code: str) -> bool:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, expires_at, used FROM bank.otp_codes
        WHERE user_id = %s AND code = %s
        ORDER BY expires_at DESC LIMIT 1
    """, (user_id, code))
    row = cur.fetchone()
    if not row:
        cur.close()
        conn.close()
        return False

    otp_id, expires_at, used = row
    if used:
        cur.close()
        conn.close()
        return False
    if expires_at < datetime.utcnow():
        cur.close()
        conn.close()
        return False
    
    # Si llegamos aquí, es válido y no usado, entonces marcamos como usado
    try:
        cur.execute("UPDATE bank.otp_codes SET used = TRUE WHERE id = %s", (otp_id,))
        conn.commit()
    except Exception as e:
        conn.rollback()
        cur.close()
        conn.close()
        return False

    cur.close()
    conn.close()
    return True