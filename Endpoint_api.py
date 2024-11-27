from flask import Flask, request, jsonify
from ddos_detection import *
from system_folder import ddos_detection

app = Flask(__name__)


@app.route('/analyze', methods=['POST'])
def analyze_traffic():

    # Endpoint to receive and analyze network traffic packets.

    try:
        # Parse incoming data (assumes JSON)
        data = request.get_json()

        if not data or 'packets' not in data:
            return jsonify({'error': 'Invalid request: No packets provided'}), 400

        packets = data['packets']  # List of packet details

        # Call your DDoS detection function
        result = ddos_detection.analyze_packets(packets)  # Replace with your function's name

        # Respond with the detection result
        return jsonify({'status': 'success', 'analysis': result}), 200

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
