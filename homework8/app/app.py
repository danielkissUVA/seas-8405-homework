
from flask import Flask, request, jsonify
import jwt
import os

host = os.getenv("FLASK_HOST", "127.0.0.1")

app = Flask(__name__)

@app.route("/")
def index():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing token"}), 401
    token = auth_header.split()[1]
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        return jsonify({"message": "Welcome!", "user": decoded})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

if __name__ == "__main__":
    app.run(host=host, port=5000)
