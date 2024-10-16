import os
import azure.functions as func
import logging
import json
import mysql.connector
import jwt  # Importamos PyJWT
from jwt.exceptions import InvalidTokenError

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

    # Verificar el token
    try:
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        # Puedes obtener información del usuario desde el token decodificado si lo necesitas
        user_email = decoded_token.get('sub')
    except InvalidTokenError as e:
        logging.error(f"Token inválido: {str(e)}")
        return func.HttpResponse(
            "Token inválido",
            status_code=401,
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
            user_id = req_body.get("id")
            is_update = req_body.get("is_update", False)
            new_data = req_body.get("new_data")  # Datos actualizados del usuario
        except ValueError:
            return func.HttpResponse(
                "JSON inválido",
                status_code=400,
                headers={
                    'Access-Control-Allow-Origin': '*'
                }
            )

        if not user_id:
            return func.HttpResponse(
                "Se requiere el ID de usuario",
                status_code=400,
                headers={
                    'Access-Control-Allow-Origin': '*'
                }
            )

        if is_update:
            # Actualizar el usuario
            if not new_data:
                return func.HttpResponse(
                    "Se requieren nuevos datos para la actualización",
                    status_code=400,
                    headers={
                        'Access-Control-Allow-Origin': '*'
                    }
                )

            update_query = "UPDATE users SET "
            update_values = []

            # Preparar la consulta y los valores dinámicamente
            for key, value in new_data.items():
                update_query += f"{key} = %s, "
                update_values.append(value)

            # Eliminar la última coma y espacio
            update_query = update_query.rstrip(', ') + " WHERE user_id = %s"
            update_values.append(user_id)

            logging.info(f'Ejecutando consulta de actualización: {update_query}')
            cursor.execute(update_query, tuple(update_values))
            connection.commit()
            logging.info('Usuario actualizado exitosamente.')

        # Obtener detalles del usuario
        select_query = "SELECT * FROM users WHERE user_id = %s"
        logging.info(f'Ejecutando consulta: {select_query}')
        cursor.execute(select_query, (user_id,))
        user_data = cursor.fetchone()

        # Cerrar la conexión a la base de datos
        cursor.close()
        connection.close()

        if not user_data:
            return func.HttpResponse(
                "Usuario no encontrado",
                status_code=404,
                headers={
                    'Access-Control-Allow-Origin': '*'
                }
            )

        # Devolver los datos del usuario
        response_body = {
            'user_data': user_data
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
