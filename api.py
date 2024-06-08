import os
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import timedelta
from bd import obtenerconexion
import uuid
import bcrypt

app = Flask(__name__)

# Configuración de JWT
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'supersecretkey')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
jwt = JWTManager(app)

# Configurar logging
log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
if not os.path.exists(log_dir):
    os.mkdir(log_dir)
handler = RotatingFileHandler(os.path.join(log_dir, 'app.log'), maxBytes=10000, backupCount=1)
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
app.logger.addHandler(handler)

@app.route('/api/login', methods=['POST'])
def login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)

    if not username or not password:
        app.logger.warning('Bad username or password provided')
        return jsonify({"msg": "Bad username or password"}), 400

    connection = obtenerconexion()
    if connection is None:
        app.logger.error('Error connecting to the database')
        return jsonify({"msg": "Error connecting to the database"}), 500

    try:
        with connection.cursor() as cursor:
            sql = "SELECT usuario_id, claveUsuario FROM USUARIO WHERE username = %s"
            cursor.execute(sql, (username,))
            user = cursor.fetchone()

        if user:
            app.logger.info(f"User found: {user}")
            print(f"User found: {user}")
            stored_password = user['claveUsuario']
            app.logger.info(f"Stored password: {stored_password}")
            print(f"Stored password: {stored_password}")

            # Verificar la contraseña encriptada
            if bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
                access_token = create_access_token(identity={'id': user['usuario_id'], 'username': username})
                app.logger.info(f'User {username} logged in successfully')
                return jsonify(access_token=access_token), 200
            else:
                app.logger.warning('Incorrect password')
                return jsonify({"msg": "Incorrect password"}), 401
        else:
            app.logger.warning('User not found')
            return jsonify({"msg": "User not found"}), 401
    finally:
        connection.close()

@app.route('/api/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    app.logger.info(f'Protected endpoint accessed by user {current_user}')
    return jsonify(logged_in_as=current_user), 200

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    required_fields = ['username', 'claveUsuario', 'tipo_usuario', 'fecha_registro', 'numDocumento', 'imgUsuario', 'emailUsuario', 'tipoUsuario', 'estadoTokenUsuario']

    # Verificar que todos los campos requeridos estén en los datos recibidos
    for field in required_fields:
        if field not in data:
            app.logger.warning(f'Missing field: {field}')
            return jsonify({"msg": f"Missing field: {field}"}), 400

    connection = obtenerconexion()
    if connection is None:
        app.logger.error('Error connecting to the database')
        return jsonify({"msg": "Error connecting to the database"}), 500

    try:
        # Encriptar la contraseña del usuario
        hashed_password = bcrypt.hashpw(data['claveUsuario'].encode('utf-8'), bcrypt.gensalt())

        # Generar un token aleatorio para el usuario
        token_usuario = str(uuid.uuid4())

        with connection.cursor() as cursor:
            sql = """
                INSERT INTO USUARIO (username, claveUsuario, tipo_usuario, fecha_registro, numDocumento, imgUsuario, emailUsuario, tipoUsuario, tokenUuario, estadoTokenUsuario)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            cursor.execute(sql, (
                data['username'],
                hashed_password.decode('utf-8'),
                data['tipo_usuario'],
                data['fecha_registro'],
                data['numDocumento'],
                data['imgUsuario'],
                data['emailUsuario'],
                data['tipoUsuario'],
                token_usuario,
                data['estadoTokenUsuario']
            ))
            connection.commit()
            app.logger.info(f"User {data['username']} registered successfully with token {token_usuario}")
            return jsonify({"msg": "User registered successfully", "token": token_usuario}), 201
    finally:
        connection.close()

if __name__ == '__main__':
    app.run(debug=True)
