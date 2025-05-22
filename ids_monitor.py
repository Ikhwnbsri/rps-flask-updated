from flask import Flask, request
import logging

app = Flask(__name__)

logging.basicConfig(
    filename="security.log",
    level=logging.INFO,
    format="[%(asctime)s] %(message)s"
)

@app.route('/log_alert', methods=['POST'])
def receive_alert():
    data = request.get_json()
    alert = data.get("alert", "No alert text")
    logging.info(f"[REMOTE ALERT] {alert}")
    print(f"[REMOTE ALERT] {alert}")
    return "OK", 200

if __name__ == '__main__':
    print("[*] IDS is listening for incoming alerts...")
    app.run(host="0.0.0.0", port=8000)
