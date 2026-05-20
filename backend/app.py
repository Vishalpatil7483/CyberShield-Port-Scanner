# app.py

# Import required libraries
from flask import Flask, request, jsonify
from flask_cors import CORS
import socket

# Create Flask app
app = Flask(__name__)

# Enable CORS
CORS(app)

# Common ports to scan
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-ALT"
}


# Function to scan a single port
def scan_port(target, port):
    """
    Scan a single port using Python socket
    Returns OPEN or CLOSED
    """

    try:
        # Create socket object
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Fast timeout for quick scanning
        sock.settimeout(0.5)

        # Try connecting to target and port
        result = sock.connect_ex((target, port))

        # Close socket after scan
        sock.close()

        # Port is open if result is 0
        if result == 0:
            return {
                "port": port,
                "status": "OPEN",
                "service": COMMON_PORTS.get(port, "Unknown")
            }

    except socket.gaierror:
        # Invalid hostname
        raise Exception("Invalid hostname or target not found")

    except Exception as e:
        # Other socket errors
        raise Exception(str(e))

    return None


# API Endpoint
@app.route('/scan', methods=['POST'])
def scan_target():
    """
    POST /scan
    Accepts JSON:
    {
        "target": "scanme.nmap.org"
    }
    """

    try:
        # Get JSON data from request
        data = request.get_json()

        # Check if target exists
        if not data or "target" not in data:
            return jsonify({
                "error": "Target is required"
            }), 400

        target = data["target"]

        # Store scan results
        results = []

        # Scan all common ports
        for port in COMMON_PORTS.keys():
            result = scan_port(target, port)

            # Add only open ports
            if result:
                results.append(result)

        # Return JSON response
        return jsonify(results), 200

    except Exception as e:
        # Handle unexpected errors
        return jsonify({
            "error": str(e)
        }), 500


# Run Flask server
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)