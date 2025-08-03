import os
import random
import string
from datetime import datetime, timedelta
from cryptography.fernet import Fernet

# --- Manejo de Encriptación ---
key = os.environ.get('FERNET_KEY')
if not key:
    key = Fernet.generate_key().decode()
    print(f"ATENCION: No se encontró FERNET_KEY. Usando una clave generada: {key}")
    print("Por favor, configura esta variable de entorno en tu docker-compose.yml.")
cipher_suite = Fernet(key.encode())

def encrypt_data(data: str) -> str:
    """Se cifra un texto plano usando Fernet."""
    if not data:
        return ""
    return cipher_suite.encrypt(data.encode()).decode()

# --- Algoritmo de Luhn para validar tarjetas ---
def is_luhn_valid(card_number: str) -> bool:
    """Se valida un número de tarjeta de crédito usando el algoritmo de Luhn."""
    if not card_number.isdigit():
        return False
        
    num_digits = len(card_number)
    s = 0
    parity = (num_digits - 1) % 2
    for i, digit in enumerate(card_number):
        d = int(digit)
        if i % 2 == parity:
            d *= 2
        if d > 9:
            d -= 9
        s += d
    return s % 10 == 0

#-- funciones para OTP --
def generate_otp(length: int = 6) -> str:
    return ''.join(random.choices(string.digits, k=length))

def otp_expiration(minutes=5) -> datetime:
    return datetime.utcnow() + timedelta(minutes=minutes)