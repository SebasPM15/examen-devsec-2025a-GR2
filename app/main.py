from http.client import HTTPException
import secrets
from app.logger import write_log
from flask import Flask, request, g
from flask_restx import Api, Resource, fields # type: ignore
from functools import wraps
from .db import get_connection, init_db, save_otp, validate_otp
from .utils import encrypt_data, is_luhn_valid, generate_otp, otp_expiration
import logging
from datetime import datetime
from .jwt import create_jwt, verify_jwt


# Define a simple in-memory token store
tokens = {}

#log = logging.getLogger(__name__)
logging.basicConfig(
     filename="app.log",
     level=logging.DEBUG,
     encoding="utf-8",
     filemode="a",
     format="{asctime} - {levelname} - {message}",
     style="{",
     datefmt="%Y-%m-%d %H:%M",
)

# Configure Swagger security scheme for Bearer tokens
authorizations = {
    'Bearer': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'Authorization',
        'description': "Enter your token in the format **Bearer <token>**"
    }
}

app = Flask(__name__)
api = Api(
    app,
    version='1.0',
    title='Core Bancario API',
    description='API para operaciones bancarias, incluyendo autenticación y operaciones de cuenta.',
    doc='/swagger',  # Swagger UI endpoint
    authorizations=authorizations,
    security='Bearer'
)

# Create namespaces for authentication and bank operations
auth_ns = api.namespace('auth', description='Operaciones de autenticación')
bank_ns = api.namespace('bank', description='Operaciones bancarias')

# Define the expected payload models for Swagger
login_model = auth_ns.model('Login', {
    'username': fields.String(required=True, description='Nombre de usuario', example='user1'),
    'password': fields.String(required=True, description='Contraseña', example='pass1')
})

deposit_model = bank_ns.model('Deposit', {
    'account_number': fields.Integer(required=True, description='Número de cuenta', example=123),
    'amount': fields.Float(required=True, description='Monto a depositar', example=100)
})

withdraw_model = bank_ns.model('Withdraw', {
    'amount': fields.Float(required=True, description='Monto a retirar', example=100)
})

transfer_model = bank_ns.model('Transfer', {
    'target_username': fields.String(required=True, description='Usuario destino', example='user2'),
    'amount': fields.Float(required=True, description='Monto a transferir', example=100)
})

# Se modifica este modelo para actualizar la documetanción en el Swagger
credit_payment_model = bank_ns.model('CreditPayment', {
    'amount': fields.Float(required=True, description='Monto de la compra', example=100),
    'card_number': fields.String(required=True, description='Número de la tarjeta a usar', example='499273987160'),
    'expiry_date': fields.String(required=True, description='Fecha de expiración (MM/YY)', example='12/28'),
    'cvv': fields.String(required=True, description='CVV de la tarjeta', example='123'),
    'otp_code': fields.String(required=True, description='Código OTP recibido por el usuario', example='123456'),
    'establishment_id': fields.Integer(required=True, description='ID del establecimiento', example=1)

})

pay_credit_balance_model = bank_ns.model('PayCreditBalance', {
    'amount': fields.Float(required=True, description='Monto a abonar a la deuda de la tarjeta', example=50)
})

# ---------------- OTP MODELS ----------------

otp_request_model = auth_ns.model('OTPRequest', {
    #no se requiere user_id porque se obtiene del token
})

otp_validate_model = auth_ns.model('OTPValidate', {
    'code': fields.String(required=True, description='Código OTP'),
})

# ---------------- Token-Required Decorator ----------------

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            api.abort(401, "Authorization header missing or invalid")
        token = auth_header.split(" ")[1]
        payload = verify_jwt(token)
        if not payload:
            api.abort(401, "Invalid or expired token")
        
        # Guardar datos del usuario en `g.user` para uso en endpoints
        g.user = {
            "id": payload["user_id"],
            "username": payload["username"],
            "role": payload["role"],
            "email": payload.get("email", "")
        }
        return f(*args, **kwargs)
    return decorated

# ---------------- Authentication Endpoints ----------------

@auth_ns.route('/login')
class Login(Resource):
    @auth_ns.expect(login_model, validate=True)
    @auth_ns.doc('login')
    def post(self):
        ip = request.remote_addr or "unknown"
        """Inicia sesión y devuelve un token JWT."""
        data = api.payload
        username = data.get("username")
        password = data.get("password")

        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, username, password, role, full_name, email FROM bank.users WHERE username = %s", (username,))
        user = cur.fetchone()
        cur.close()
        conn.close()
        if user and user[2] == password:
            payload = {
                "user_id": user[0],
                "username": user[1],
                "role": user[3],
                "email": user[5]
            }
            token = create_jwt(payload)
            write_log("INFO", ip, username, "Login exitoso", 200)
            return {"message": "Login successful", "token": token}, 200
        else:
            write_log("WARNING", ip, username or "unknown", "Intento de login fallido", 401)
            api.abort(401, "Invalid credentials")

@auth_ns.route('/logout')
class Logout(Resource):
    @auth_ns.doc('logout')
    def post(self):
        ip = request.remote_addr or "unknown"
        """Invalida el token de autenticación."""
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            api.abort(401, "Authorization header missing or invalid")
        token = auth_header.split(" ")[1]
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("DELETE FROM bank.tokens WHERE token = %s", (token,))
        if cur.rowcount == 0:
            conn.commit()
            cur.close()
            conn.close()
            api.abort(401, "Invalid token")
        conn.commit()
        cur.close()
        conn.close()
        payload = verify_jwt(token)
        username = payload["username"] if payload else "unknown"
        write_log("INFO", ip, username, "Logout exitoso", 200)
        return {"message": "Logout successful"}, 200

# ---------------- OTP Endpoints ----------------

@auth_ns.route('/generate-otp')
class GenerateOTP(Resource):
    @token_required  
    @auth_ns.expect(otp_request_model, validate=True)  # Ahora no requiere user_id en body
    @auth_ns.doc('generate_otp')
    def post(self):
        """Genera y guarda un código OTP para el usuario autenticado."""
        # user_id viene del token y del contexto g
        user_id = g.user['id']

        code = generate_otp()
        expires_at = otp_expiration()

        save_otp(user_id, code, expires_at)
        ip = request.remote_addr or "unknown"
        write_log("INFO", ip, g.user["username"], "OTP generado", 200)
        return {
            "message": "OTP generado correctamente",
            "otp": code,
            "expires_at": expires_at.isoformat()
        }, 200


@auth_ns.route('/validate-otp')
class ValidateOTP(Resource):
    @token_required  # Agregar protección para obtener usuario autenticado
    @auth_ns.expect(otp_validate_model, validate=True)
    @auth_ns.doc('validate_otp')
    def post(self):
        """Valida un código OTP para el usuario autenticado."""
        data = api.payload
        user_id = g.user['id']  # Obtener del token, no del payload
        code = data.get('code')

        if not code:
            api.abort(400, "Código OTP es requerido")

        if validate_otp(user_id, code):
            ip = request.remote_addr or "unknown"
            write_log("INFO", ip, g.user["username"], "OTP válido", 200)
            return {"message": "OTP válido"}, 200
        else:
            write_log("WARNING", ip, g.user["username"], "OTP inválido o expirado", 400)
            api.abort(400, "OTP inválido o expirado")

# ---------------- Banking Operation Endpoints ----------------

@bank_ns.route('/deposit')
class Deposit(Resource):
    logging.debug("Entering....")
    @bank_ns.expect(deposit_model, validate=True)
    @bank_ns.doc('deposit')
    @token_required
    def post(self):
        """
        Realiza un depósito en la cuenta especificada.
        Se requiere el número de cuenta y el monto a depositar.
        """
        data = api.payload
        account_number = data.get("account_number")
        amount = data.get("amount", 0)
        
        if amount <= 0:
            api.abort(400, "Amount must be greater than zero")
        
        conn = get_connection()
        cur = conn.cursor()
        # Update the specified account using its account number (primary key)
        cur.execute(
            "UPDATE bank.accounts SET balance = balance + %s WHERE id = %s RETURNING balance",
            (amount, account_number)
        )
        result = cur.fetchone()
        if not result:
            conn.rollback()
            cur.close()
            conn.close()
            api.abort(404, "Account not found")
        new_balance = float(result[0])
        conn.commit()
        cur.close()
        conn.close()
        ip = request.remote_addr or "unknown"
        write_log("INFO", ip, g.user["username"], f"Depósito de ${amount} en cuenta {account_number}", 200)
        return {"message": "Deposit successful", "new_balance": new_balance}, 200

@bank_ns.route('/withdraw')
class Withdraw(Resource):
    @bank_ns.expect(withdraw_model, validate=True)
    @bank_ns.doc('withdraw')
    @token_required
    def post(self):
        ip = request.remote_addr or "unknown"
        """Realiza un retiro de la cuenta del usuario autenticado."""
        data = api.payload
        amount = data.get("amount", 0)
        if amount <= 0:
            api.abort(400, "Amount must be greater than zero")
        user_id = g.user['id']
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (user_id,))
        row = cur.fetchone()
        if not row:
            cur.close()
            conn.close()
            api.abort(404, "Account not found")
        current_balance = float(row[0])
        if current_balance < amount:
            cur.close()
            conn.close()
            write_log("WARNING", ip, g.user["username"], f"Retiro fallido por fondos insuficientes: ${amount}", 400)
            api.abort(400, "Insufficient funds")
        cur.execute("UPDATE bank.accounts SET balance = balance - %s WHERE user_id = %s RETURNING balance", (amount, user_id))
        new_balance = float(cur.fetchone()[0])
        conn.commit()
        cur.close()
        conn.close()
        write_log("INFO", ip, g.user["username"], f"Retiro de ${amount}", 200)
        return {"message": "Withdrawal successful", "new_balance": new_balance}, 200

@bank_ns.route('/transfer')
class Transfer(Resource):
    @bank_ns.expect(transfer_model, validate=True)
    @bank_ns.doc('transfer')
    @token_required
    def post(self):
        ip = request.remote_addr or "unknown"
        """Transfiere fondos desde la cuenta del usuario autenticado a otra cuenta."""
        data = api.payload
        target_username = data.get("target_username")
        amount = data.get("amount", 0)
        if not target_username or amount <= 0:
            api.abort(400, "Invalid data")
        if target_username == g.user['username']:
            api.abort(400, "Cannot transfer to the same account")
        conn = get_connection()
        cur = conn.cursor()
        # Check sender's balance
        cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (g.user['id'],))
        row = cur.fetchone()
        if not row:
            cur.close()
            conn.close()
            api.abort(404, "Sender account not found")
        sender_balance = float(row[0])
        if sender_balance < amount:
            cur.close()
            conn.close()
            api.abort(400, "Insufficient funds")
        # Find target user
        cur.execute("SELECT id FROM bank.users WHERE username = %s", (target_username,))
        target_user = cur.fetchone()
        if not target_user:
            cur.close()
            conn.close()
            write_log("WARNING", ip, g.user["username"], f"Transferencia fallida: destinatario {target_username} no encontrado", 404)
            api.abort(404, "Target user not found")
        target_user_id = target_user[0]
        try:
            cur.execute("UPDATE bank.accounts SET balance = balance - %s WHERE user_id = %s", (amount, g.user['id']))
            cur.execute("UPDATE bank.accounts SET balance = balance + %s WHERE user_id = %s", (amount, target_user_id))
            cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (g.user['id'],))
            new_balance = float(cur.fetchone()[0])
            conn.commit()
        except Exception as e:
            conn.rollback()
            cur.close()
            conn.close()
            write_log("ERROR", ip, g.user["username"], f"Error durante transferencia: {str(e)}", 500)
            api.abort(500, f"Error during transfer: {str(e)}")
        cur.close()
        conn.close()
        write_log("INFO", ip, g.user["username"], f"Transferencia de ${amount} a {target_username}", 200)
        return {"message": "Transfer successful", "new_balance": new_balance}, 200

@bank_ns.route('/credit-payment')
class CreditPayment(Resource):
    @bank_ns.expect(credit_payment_model, validate=True)
    @bank_ns.doc('credit_payment')
    @token_required
    def post(self):
        ip = request.remote_addr or "unknown"
        """
        Realiza una compra a crédito:
        - Valida, encripta y guarda la información de la tarjeta.
        - Descuenta el monto de la cuenta.
        - Aumenta la deuda de la tarjeta de crédito.
        - Usa OTP para validar la transacción, previo a haber iniciado sesión y generado un OTP.
        """
        data = api.payload
        amount = data.get("amount", 0)
        card_number = data.get("card_number")
        otp_code = data.get("otp_code")
        establishment_id = data.get("establishment_id")

        if amount <= 0:
            api.abort(400, "Amount must be greater than zero")
            
        # 1. Validar el formato de la tarjeta con Luhn 
        if not is_luhn_valid(card_number):
            api.abort(400, "Número de tarjeta inválido.")
        
        # validar OTP y establecimiento
        if not otp_code or not establishment_id:
            api.abort(400, "OTP code y establishment_id son requeridos")

        user_id = g.user['id']
        conn = get_connection()
        cur = conn.cursor()
        try:
            # Verificar OTP
            if not validate_otp(user_id, otp_code):
                write_log("WARNING", ip, g.user["username"], "Compra rechazada: OTP inválido", 400)
                api.abort(400, "OTP inválido o expirado")
            
            # Verificar establecimiento
            cur.execute("SELECT id FROM bank.establecimientos WHERE id = %s", (establishment_id,))
            if not cur.fetchone():
                write_log("WARNING", ip, g.user["username"], f"Compra rechazada: Establecimiento {establishment_id} inválido", 400)
                api.abort(400, "Establecimiento no válido o no registrado")

            # 2. Guardar la tarjeta de forma segura si es nueva
            cur.execute("SELECT id FROM bank_secure.encrypted_cards WHERE user_id = %s AND card_last_4_digits = %s", (user_id, card_number[-4:]))
            if not cur.fetchone():
                cur.execute("""
                    INSERT INTO bank_secure.encrypted_cards (user_id, encrypted_card_number, encrypted_expiry_date, encrypted_cvv, card_last_4_digits)
                    VALUES (%s, %s, %s, %s, %s)
                """, (user_id, encrypt_data(card_number), encrypt_data(data['expiry_date']), encrypt_data(data['cvv']), card_number[-4:]))
            
            # 3. Lógica original del pago
            cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (user_id,))
            account_balance = float(cur.fetchone()[0])
            if account_balance < amount:
                api.abort(400, "Fondos insuficientes en la cuenta")

            cur.execute("UPDATE bank.accounts SET balance = balance - %s WHERE user_id = %s", (amount, user_id))
            cur.execute("UPDATE bank.credit_cards SET balance = balance + %s WHERE user_id = %s", (amount, user_id))
            
            cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (user_id,))
            new_account_balance = float(cur.fetchone()[0])
            cur.execute("SELECT balance FROM bank.credit_cards WHERE user_id = %s", (user_id,))
            new_credit_balance = float(cur.fetchone()[0])
            
            conn.commit()
            write_log("INFO", ip, g.user["username"], f"Compra a crédito por ${amount} en establecimiento {establishment_id}", 200)

        except HTTPException as http_err:
            conn.rollback()
            raise http_err
        except Exception as e:
            write_log("ERROR", ip, g.user["username"], f"Error procesando compra: {str(e)}", 500)
            logging.exception("Error procesando compra")
            conn.rollback()
            api.abort(500, "Error interno inesperado. Contacta al administrador.")
        finally:
            cur.close()
            conn.close()

        return {           
            "message": "Compra con tarjeta de crédito exitosa. Tarjeta validada y guardada de forma segura.",
            "account_balance": new_account_balance,
            "credit_card_debt": new_credit_balance
        }, 200

@bank_ns.route('/pay-credit-balance')
class PayCreditBalance(Resource):
    @bank_ns.expect(pay_credit_balance_model, validate=True)
    @bank_ns.doc('pay_credit_balance')
    @token_required
    def post(self):
        ip = request.remote_addr or "unknown"
        """
        Realiza un abono a la deuda de la tarjeta:
        - Descuenta el monto (o el máximo posible) de la cuenta.
        - Reduce la deuda de la tarjeta de crédito.
        """
        data = api.payload
        amount = data.get("amount", 0)
        if amount <= 0:
            api.abort(400, "Amount must be greater than zero")
        user_id = g.user['id']
        conn = get_connection()
        cur = conn.cursor()
        # Check account funds
        cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (user_id,))
        row = cur.fetchone()
        if not row:
            cur.close()
            conn.close()
            api.abort(404, "Account not found")
        account_balance = float(row[0])
        if account_balance < amount:
            cur.close()
            conn.close()
            write_log("WARNING", ip, g.user["username"], f"Intento de pago fallido: fondos insuficientes (${amount})", 400)
            api.abort(400, "Insufficient funds in account")
        # Get current credit card debt
        cur.execute("SELECT balance FROM bank.credit_cards WHERE user_id = %s", (user_id,))
        row = cur.fetchone()
        if not row:
            cur.close()
            conn.close()
            api.abort(404, "Credit card not found")
        credit_debt = float(row[0])
        payment = min(amount, credit_debt)
        try:
            cur.execute("UPDATE bank.accounts SET balance = balance - %s WHERE user_id = %s", (payment, user_id))
            cur.execute("UPDATE bank.credit_cards SET balance = balance - %s WHERE user_id = %s", (payment, user_id))
            cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (user_id,))
            new_account_balance = float(cur.fetchone()[0])
            cur.execute("SELECT balance FROM bank.credit_cards WHERE user_id = %s", (user_id,))
            new_credit_debt = float(cur.fetchone()[0])
            conn.commit()
            write_log("INFO", ip, g.user["username"], f"Pago de deuda por ${payment}", 200)
        except Exception as e:
            conn.rollback()
            cur.close()
            conn.close()
            write_log("ERROR", ip, g.user["username"], f"Error procesando pago de deuda: {str(e)}", 500)
            api.abort(500, f"Error processing credit balance payment: {str(e)}")
        cur.close()
        conn.close()
        return {
            "message": "Credit card debt payment successful",
            "account_balance": new_account_balance,
            "credit_card_debt": new_credit_debt
        }, 200

@app.before_first_request
def initialize_db():
    init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)

