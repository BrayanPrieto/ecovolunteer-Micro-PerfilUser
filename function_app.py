import os
import azure.functions as func
import logging
import json
import mysql.connector

app = func.FunctionApp()

@app.route(route="http_trigger", auth_level=func.AuthLevel.ANONYMOUS, methods=["POST", "OPTIONS"])
def http_trigger(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Processing HTTP POST request...')
    
    # Handle CORS preflight request
    if req.method == 'OPTIONS':
        return func.HttpResponse(
            "",
            headers={
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'POST, OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type'
            },
            status_code=204
        )

    try:
        # Retrieve MySQL connection details from application settings
        mysql_host = os.getenv('MYSQL_HOST', 'localhost')  # Default to localhost if not provided
        mysql_database = os.getenv('MYSQL_DATABASE')
        mysql_user = os.getenv('MYSQL_USER')
        mysql_password = os.getenv('MYSQL_PASSWORD')

        if not all([mysql_database, mysql_user, mysql_password]):
            logging.error('Missing MySQL connection details.')
            return func.HttpResponse(
                "Error: Missing MySQL connection details.",
                status_code=500,
                headers={
                    'Access-Control-Allow-Origin': '*'
                }
            )

        # Connect to the MySQL database
        connection = mysql.connector.connect(
            host=mysql_host,
            database=mysql_database,
            user=mysql_user,
            password=mysql_password
        )

        cursor = connection.cursor(dictionary=True)

        # Parse the JSON request body
        try:
            req_body = req.get_json()
            user_id = req_body.get("id")
            is_update = req_body.get("is_update", False)
            new_data = req_body.get("new_data")  # Assuming this will contain the updated user data
        except ValueError:
            return func.HttpResponse(
                "Invalid JSON",
                status_code=400,
                headers={
                    'Access-Control-Allow-Origin': '*'
                }
            )

        if not user_id:
            return func.HttpResponse(
                "User ID is required",
                status_code=400,
                headers={
                    'Access-Control-Allow-Origin': '*'
                }
            )

        if is_update:
            # Update the user
            if not new_data:
                return func.HttpResponse(
                    "New data is required for update",
                    status_code=400,
                    headers={
                        'Access-Control-Allow-Origin': '*'
                    }
                )

            update_query = "UPDATE users SET "
            update_values = []

            # Prepare the query and values dynamically based on the new data provided
            for key, value in new_data.items():
                update_query += f"{key} = %s, "
                update_values.append(value)

            # Remove the last comma and space
            update_query = update_query.rstrip(', ') + " WHERE user_id = %s"
            update_values.append(user_id)

            logging.info(f'Executing update query: {update_query}')
            cursor.execute(update_query, tuple(update_values))
            connection.commit()
            logging.info('User updated successfully.')

        # Fetch user details
        select_query = "SELECT * FROM users WHERE user_id = %s"
        logging.info(f'Executing query: {select_query}')
        cursor.execute(select_query, (user_id,))
        user_data = cursor.fetchone()

        # Close the database connection
        cursor.close()
        connection.close()

        if not user_data:
            return func.HttpResponse(
                "User not found",
                status_code=404,
                headers={
                    'Access-Control-Allow-Origin': '*'
                }
            )

        # Return the updated or retrieved user data
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
