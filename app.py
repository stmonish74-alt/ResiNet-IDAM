
from flask import Flask, render_template, request, jsonify

from backend.dashboard import get_dashboard_data, get_recent_events
from backend.dataset_processor import process_dataset

from backend.intrusion_model import (
    train_intrusion_model,
    predict_intrusion
)

from backend.zero_trust import (
    initialize_zero_trust,
    evaluate_access,
    get_access_logs
)


app = Flask(__name__)

app.config["SECRET_KEY"] = "change-this-development-key"


# -----------------------------------------
# HOME PAGE
# -----------------------------------------

@app.route("/")
def home():
    return render_template("index.html")


# -----------------------------------------
# HEALTH CHECK
# -----------------------------------------

@app.route("/api/health")
def health():
    return jsonify({
        "app": "ResiNet-IDAM",
        "status": "ok",
        "message": "Flask backend is running"
    })


# -----------------------------------------
# DASHBOARD DATA
# -----------------------------------------

@app.route("/api/dashboard")
def dashboard_api():
    return jsonify(get_dashboard_data())


# -----------------------------------------
# RECENT SECURITY EVENTS
# -----------------------------------------

@app.route("/api/events")
def events_api():
    return jsonify({
        "events": get_recent_events()
    })


# -----------------------------------------
# IT DATASET UPLOAD AND PROCESSING
# -----------------------------------------

@app.route("/api/upload-dataset", methods=["POST"])
def upload_dataset():
    try:
        if "file" not in request.files:
            return jsonify({
                "status": "error",
                "error": "No file uploaded"
            }), 400

        result = process_dataset(request.files["file"])

        return jsonify({
            "status": "success",
            "message": "Dataset processed successfully",
            "data": result
        })

    except Exception as error:
        return jsonify({
            "status": "error",
            "error": str(error)
        }), 400


# -----------------------------------------
# AI MODEL TRAINING
# -----------------------------------------

@app.route("/api/train-model", methods=["POST"])
def train_model_api():
    try:
        result = train_intrusion_model()

        return jsonify(result)

    except Exception as error:
        return jsonify({
            "status": "error",
            "error": str(error)
        }), 400


# -----------------------------------------
# AI INTRUSION PREDICTION
# -----------------------------------------

@app.route("/api/predict-intrusion", methods=["POST"])
def predict_intrusion_api():
    try:
        data = request.get_json(silent=True)

        if not isinstance(data, dict) or not data:
            return jsonify({
                "status": "error",
                "error": "Provide valid network activity data."
            }), 400

        result = predict_intrusion(data)

        return jsonify({
            "status": "success",
            "data": result
        })

    except Exception as error:
        return jsonify({
            "status": "error",
            "error": str(error)
        }), 400


# -----------------------------------------
# ZERO-TRUST ACCESS EVALUATION
# -----------------------------------------

@app.route("/api/zero-trust/evaluate", methods=["POST"])
def zero_trust_evaluate_api():
    try:
        data = request.get_json(silent=True)

        if not isinstance(data, dict):
            return jsonify({
                "status": "error",
                "error": "Provide valid JSON data."
            }), 400

        result = evaluate_access(data)

        return jsonify(result)

    except Exception as error:
        return jsonify({
            "status": "error",
            "error": str(error)
        }), 400


# -----------------------------------------
# ZERO-TRUST SECURITY AUDIT LOGS
# -----------------------------------------

@app.route("/api/zero-trust/logs", methods=["GET"])
def zero_trust_logs_api():
    try:
        logs = get_access_logs()

        return jsonify({
            "status": "success",
            "total_logs": len(logs),
            "logs": logs
        })

    except Exception as error:
        return jsonify({
            "status": "error",
            "error": str(error)
        }), 500


# -----------------------------------------
# 404 ERROR HANDLER
# -----------------------------------------

@app.errorhandler(404)
def not_found(_error):
    return jsonify({
        "status": "error",
        "error": "Endpoint not found"
    }), 404


# -----------------------------------------
# START FLASK SERVER
# -----------------------------------------

if __name__ == "__main__":

    # Initialize Zero-Trust audit database
    initialize_zero_trust()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
