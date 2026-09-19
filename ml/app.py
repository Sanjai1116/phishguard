from flask import Flask, request, jsonify
from flask_cors import CORS
from pathlib import Path
import joblib
import tempfile
import os

from webpage_analyzer import analyze_webpage
from apk_analyzer import analyze_apk


app = Flask(__name__)
CORS(app)

BASE_DIR = Path(__file__).resolve().parent
MODEL_DIR = BASE_DIR / "model"

URL_MODEL_PATH = MODEL_DIR / "url_model.joblib"
TEXT_MODEL_PATH = MODEL_DIR / "text_model.joblib"

url_model = joblib.load(URL_MODEL_PATH)
text_model = joblib.load(TEXT_MODEL_PATH)


def get_risk_level(score):
    if score >= 60:
        return "High"
    elif score >= 30:
        return "Medium"
    return "Low"


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "status": "success",
        "message": "PhishGuard API is running."
    })


@app.route("/scan/url", methods=["POST"])
def scan_url():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()

    if not url:
        return jsonify({
            "status": "error",
            "message": "URL is required."
        }), 400

    prediction = url_model.predict([url])[0]

    probabilities = url_model.predict_proba([url])[0]
    classes = list(url_model.classes_)

    suspicious_probability = 0

    if "suspicious" in classes:
        suspicious_probability = probabilities[
            classes.index("suspicious")
        ]

    score = round(float(suspicious_probability) * 100, 2)

    return jsonify({
        "status": "success",
        "type": "url",
        "url": url,
        "prediction": str(prediction),
        "risk_score": score,
        "risk_level": get_risk_level(score)
    })


@app.route("/scan/text", methods=["POST"])
def scan_text():
    data = request.get_json(silent=True) or {}
    text = data.get("text", "").strip()

    if not text:
        return jsonify({
            "status": "error",
            "message": "Text is required."
        }), 400

    prediction = text_model.predict([text])[0]

    probabilities = text_model.predict_proba([text])[0]
    classes = list(text_model.classes_)

    suspicious_probability = 0

    if "suspicious" in classes:
        suspicious_probability = probabilities[
            classes.index("suspicious")
        ]

    score = round(float(suspicious_probability) * 100, 2)

    return jsonify({
        "status": "success",
        "type": "text",
        "prediction": str(prediction),
        "risk_score": score,
        "risk_level": get_risk_level(score)
    })


@app.route("/scan/webpage", methods=["POST"])
def scan_webpage():

    data = request.get_json(silent=True) or {}

    url = data.get("url", "").strip()

    if not url:
        return jsonify({
            "status": "error",
            "message": "URL is required."
        }), 400

    try:
        import requests

        response = requests.get(
            url,
            timeout=8,
            headers={
                "User-Agent": "PhishGuard-Security-Scanner/1.0"
            }
        )

        response.raise_for_status()

        html = response.text

        result = analyze_webpage(url, html)

        return jsonify({
            "status": "success",
            "type": "webpage",
            "result": result
        })

    except Exception as error:

        print("Webpage scan error:", error)

        return jsonify({
            "status": "error",
            "message": "Unable to fetch or analyse this webpage."
        }), 502

@app.route("/scan/apk", methods=["POST"])
def scan_apk():
    if "file" not in request.files:
        return jsonify({
            "status": "error",
            "message": "APK file is required."
        }), 400

    uploaded_file = request.files["file"]

    if uploaded_file.filename == "":
        return jsonify({
            "status": "error",
            "message": "No APK file selected."
        }), 400

    if not uploaded_file.filename.lower().endswith(".apk"):
        return jsonify({
            "status": "error",
            "message": "Only APK files are supported."
        }), 400

    temp_path = None

    try:
        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=".apk"
        ) as temp_file:

            uploaded_file.save(temp_file.name)
            temp_path = temp_file.name

        result = analyze_apk(temp_path)

        return jsonify({
            "status": "success",
            "type": "apk",
            "result": result
        })

    finally:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)

            
@app.route("/scan/apk-url", methods=["POST"])
def scan_apk_url():
    import requests

    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()

    if not url:
        return jsonify({
            "status": "error",
            "message": "APK URL is required."
        }), 400

    if not url.lower().startswith(("http://", "https://")):
        return jsonify({
            "status": "error",
            "message": "Please enter a valid APK URL."
        }), 400

    temp_path = None

    try:
        response = requests.get(
            url,
            timeout=15,
            headers={
                "User-Agent": "PhishGuard-Security-Scanner/1.0"
            }
        )

        response.raise_for_status()

        content_type = response.headers.get(
            "Content-Type", ""
        ).lower()

        clean_url = url.lower().split("?")[0]

        if not clean_url.endswith(".apk") and \
           "application/vnd.android.package-archive" not in content_type:
            return jsonify({
                "status": "error",
                "message": "The link does not appear to be an APK file."
            }), 400

        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=".apk"
        ) as temp_file:

            temp_file.write(response.content)
            temp_path = temp_file.name

        result = analyze_apk(temp_path)

        return jsonify({
            "status": "success",
            "type": "apk-url",
            "result": result
        })

    except Exception as error:

        print("APK URL scan error:", error)

        return jsonify({
            "status": "error",
            "message": "Unable to download or analyse the APK."
        }), 502

    finally:

        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)

if __name__ == "__main__":
    print("Starting PhishGuard API...")
    print("API URL: http://127.0.0.1:5000")

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
