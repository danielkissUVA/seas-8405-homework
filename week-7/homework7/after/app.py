from flask import Flask, request, jsonify
import os
import subprocess
import ast
import ipaddress

app = Flask(__name__)

# Retrieve password from environment variable instead of hardcoding
PASSWORD = os.environ.get('PASSWORD', 'default_password')
# Explanation: Replaced hard coded password, previsouly PASSWORD = "supersecretpassword"

@app.route('/')
def hello():
    name = request.args.get('name', 'World')
    if not name.isalnum():
        return jsonify({"error": "Invalid name"}), 400
    return f"Hello, {name}!"

# Secure ping route with input validation and no shell=True
@app.route('/ping')
def ping():
    ip = request.args.get('ip')
    try:
        # Explanation: Added IP address validation to make sure that value provided is a valid IP address.
        ipaddress.ip_address(ip)  # Validate IP address
        # Explanation: Replaced original code "result = subprocess.check_output(f"ping -c 1 {ip}", shell=True)"
        # removed "shell=True" allowing shell command execution.
        result = subprocess.check_output(["/bin/ping", "-c", "1", ip])
        return result
    except ValueError:
        # Explanation: adding Error Handling if IP address validation fails.
        return jsonify({"error": "Invalid IP address"}), 400

# Secure calculate route using ast.literal_eval instead of eval
@app.route('/calculate')
def calculate():
    expression = request.args.get('expr')

    print(f"DEBUG: Received expression parameter: {expression!r}", flush=True)
    print(f"DEBUG: Type of expression parameter: {type(expression)}", flush=True)  # Add this line

    if expression is None:
        print("DEBUG: Expression parameter is None.", flush=True)
        return jsonify({"error": "Invalid expression"}), 400
    try:
        # Attempt to parse the string into an AST node first
        node = ast.parse(expression, mode='eval')  # Use mode='eval' for expressions
        print(f"DEBUG: Successfully parsed expression to AST node: {ast.dump(node)}")
        print(f"DEBUG: Type of parsed node body: {type(node.body)}")  # Check type of the core node


        # Now, try to evaluate the parsed node using ast.literal_eval
        # ast.literal_eval expects a node or a string.
        # We are explicitly passing the node here.
        result = ast.literal_eval(expression)  # Pass the expression node (e.g., BinOp for 2+3)

        print(f"DEBUG: Successfully evaluated result: {result!r}", flush=True)
        print(f"DEBUG: Type of evaluated result: {type(result)}", flush=True)
        return str(result)

    except (SyntaxError, ValueError) as e:
        print(f"DEBUG: ast.parse or ast.literal_eval failed on input: {expression!r}", flush=True)
        print(f"DEBUG: Error details: {e}", flush=True)
        return jsonify({"error": "Invalid expression"}), 400
    except Exception as e:
        # Catch any other unexpected errors during the process
        print(f"DEBUG: An unexpected error occurred: {e}", flush=True)
        return jsonify({"error": f"An unexpected error occurred: {e}"}), 500


if __name__ == '__main__':
    # Explanation: Limiting application to bind to localhost only, will not allow access from other IPs.
    app.run(host='127.0.0.1', port=5000)  # Bind to localhost instead of all interfaces

