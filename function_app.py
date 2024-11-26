import os
import azure.functions as func
import logging
import json
import mysql.connector
import jwt
from jwt.exceptions import InvalidTokenError

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64
import hashlib

app = func.FunctionApp()

@app.route(route="http_trigger", auth_level=func.AuthLevel.ANONYMOUS, methods=["POST", "OPTIONS"])
def http_trigger(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Procesando solicitud HTTP POST...')
    
    # Manejar la solicitud preflight de CORS
    if req.method == 'OPTIONS':
        return func.HttpResponse(
            "",
            headers={
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'POST, OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type, Authorization'
            },
            status_code=204
        )
    
    # Obtener el token JWT del encabezado Authorization
    auth_header = req.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header[len('Bearer '):]
    else:
        return func.HttpResponse(
            "Falta el encabezado de autorización o es inválido",
            status_code=401,
            headers={
                'Access-Control-Allow-Origin': '*'
            }
        )

    # Clave secreta utilizada en tu servicio Java para firmar el token JWT
    SECRET_KEY = os.getenv('jwt.secret')

    if not SECRET_KEY:
        logging.error('La clave secreta JWT no se ha definido en las variables de entorno.')
        return func.HttpResponse(
            "Error de configuración del servidor: falta la clave secreta JWT.",
            status_code=500,
            headers={
                'Access-Control-Allow-Origin': '*'
            }
        )

    # Verificar el token y desencriptar los datos
    try:
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        encrypted_data_base64 = decoded_token.get('data')
        
        if not encrypted_data_base64:
            return func.HttpResponse(
                "El token no contiene datos encriptados",
                status_code=400,
                headers={
                    'Access-Control-Allow-Origin': '*'
                }
            )

        # Derivar la clave AES como en Java
        key_bytes = hashlib.sha256(SECRET_KEY.encode('utf-8')).digest()
        key_bytes16 = key_bytes[:16]  # Tomar los primeros 16 bytes para AES-128

        # Decodificar y desencriptar los datos
        encrypted_data_bytes = base64.b64decode(encrypted_data_base64)
        cipher = AES.new(key_bytes16, AES.MODE_ECB)
        decrypted_data_bytes = cipher.decrypt(encrypted_data_bytes)
        decrypted_data = unpad(decrypted_data_bytes, AES.block_size).decode('utf-8')

        # Parsear los datos JSON
        data = json.loads(decrypted_data)
        user_email = data.get('email')
        user_role = data.get('role')
        user_id_from_token = data.get('id')

        logging.info(f"Datos del token: email={user_email}, role={user_role}, id={user_id_from_token}")

    except InvalidTokenError as e:
        logging.error(f"Token inválido: {str(e)}")
        return func.HttpResponse(
            "Token inválido",
            status_code=401,
            headers={
                'Access-Control-Allow-Origin': '*'
            }
        )
    except Exception as e:
        logging.error(f"Error al procesar el token JWT: {str(e)}")
        return func.HttpResponse(
            f"Error al procesar el token JWT: {str(e)}",
            status_code=500,
            headers={
                'Access-Control-Allow-Origin': '*'
            }
        )

    # Continuar con el procesamiento de la solicitud
    try:
        # Obtener detalles de conexión MySQL desde las variables de entorno
        mysql_host = os.getenv('MYSQL_HOST', 'localhost')
        mysql_database = os.getenv('MYSQL_DATABASE')
        mysql_user = os.getenv('MYSQL_USER')
        mysql_password = os.getenv('MYSQL_PASSWORD')

        if not all([mysql_database, mysql_user, mysql_password]):
            logging.error('Faltan detalles de conexión MySQL.')
            return func.HttpResponse(
                "Error: Faltan detalles de conexión MySQL.",
                status_code=500,
                headers={
                    'Access-Control-Allow-Origin': '*'
                }
            )

        # Conectar a la base de datos MySQL
        connection = mysql.connector.connect(
            host=mysql_host,
            database=mysql_database,
            user=mysql_user,
            password=mysql_password
        )

        cursor = connection.cursor(dictionary=True)

        # Analizar el cuerpo de la solicitud JSON
        try:
            req_body = req.get_json()
            is_update = req_body.get("is_update", False)
            new_data = req_body.get("new_data")  # Datos actualizados
        except ValueError:
            return func.HttpResponse(
                "JSON inválido",
                status_code=400,
                headers={
                    'Access-Control-Allow-Origin': '*'
                }
            )

        # Determinar la tabla y campos según el rol
        if user_role in ['Volunteer', 'User']:
            table_name = 'users'
            id_field = 'user_id'
            allowed_fields = ['first_name', 'last_name', 'email', 'phone_number', 'address']  # Actualiza según tus campos
        elif user_role == 'Company':
            table_name = 'companies'
            id_field = 'company_id'
            allowed_fields = ['company_name', 'email', 'phone_number', 'address']  # Actualiza según tus campos
        else:
            return func.HttpResponse(
                f"Rol desconocido: {user_role}",
                status_code=400,
                headers={
                    'Access-Control-Allow-Origin': '*'
                }
            )

        if is_update:
            # Actualizar el usuario o compañía
            if not new_data:
                return func.HttpResponse(
                    "Se requieren nuevos datos para la actualización",
                    status_code=400,
                    headers={
                        'Access-Control-Allow-Origin': '*'
                    }
                )

            # Filtrar los campos permitidos para actualizar
            filtered_new_data = {k: v for k, v in new_data.items() if k in allowed_fields}

            if not filtered_new_data:
                return func.HttpResponse(
                    "No hay campos válidos para actualizar",
                    status_code=400,
                    headers={
                        'Access-Control-Allow-Origin': '*'
                    }
                )

            update_query = f"UPDATE {table_name} SET "
            update_values = []

            # Preparar la consulta y los valores dinámicamente
            for key, value in filtered_new_data.items():
                update_query += f"{key} = %s, "
                update_values.append(value)

            # Eliminar la última coma y espacio
            update_query = update_query.rstrip(', ') + f" WHERE {id_field} = %s"
            update_values.append(user_id_from_token)

            logging.info(f'Ejecutando consulta de actualización: {update_query}')
            cursor.execute(update_query, tuple(update_values))
            connection.commit()
            logging.info(f'{table_name} actualizado exitosamente.')

        # Obtener detalles del usuario o compañía
        select_query = f"SELECT * FROM {table_name} WHERE {id_field} = %s"
        logging.info(f'Ejecutando consulta: {select_query}')
        cursor.execute(select_query, (user_id_from_token,))
        user_data = cursor.fetchone()

        # Cerrar la conexión a la base de datos
        cursor.close()
        connection.close()

        if not user_data:
            return func.HttpResponse(
                f"{user_role} no encontrado",
                status_code=404,
                headers={
                    'Access-Control-Allow-Origin': '*'
                }
            )

        # Devolver los datos del usuario o compañía
        response_key = 'user_data' if user_role in ['Volunteer', 'User'] else 'company_data'
        response_body = {
            response_key: user_data
        }

        return func.HttpResponse(
            json.dumps(response_body, default=str),
            mimetype="application/json",
            status_code=200,
            headers={
                'Access-Control-Allow-Origin': '*'
            }
        )

    except Exception as e:
        logging.error(f"Error: {str(e)}")
        return func.HttpResponse(
            f"Error: {str(e)}",
            status_code=500,
            headers={
                'Access-Control-Allow-Origin': '*'
            }
        )
