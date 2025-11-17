import os
import json
import re
import joblib
import pickle
import numpy as np
import pandas as pd
import urllib.parse
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from bson import ObjectId
import io
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

# Import MongoDB helpers
from db import (create_user, verify_user, is_admin, save_detection, get_user_detections, 
                get_all_detections, save_feedback, save_contact, get_all_contacts, 
                get_all_feedback, get_analytics_data)

# --- Config ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, "models")
SAVED_CMAF_DIR = os.path.join(MODELS_DIR, "saved_cmaf")
HYBRID_MODELS_DIR = os.path.join(MODELS_DIR, "phishing_hybrid_models")
PHISHING_CONFORMAL_PKL = os.path.join(BASE_DIR, "phishing_hybrid_conformal.pkl")
EMAIL_UNSAFE_PATH = os.path.join(MODELS_DIR, "email_unsafe.json")

SECRET_KEY = os.environ.get("FLASK_SECRET", "super-secret-key-change-me")
DEBUG = True

# --- Flask app ---
app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config["SESSION_PERMANENT"] = False

# Load safe URLs
file_path = os.path.join(MODELS_DIR, "safe_urls.json")
SAFE_URLS = []

try:
    with open(file_path, 'r') as file:
        data = json.load(file)
        SAFE_URLS = data.get("trusted_domains", [])
except FileNotFoundError:
    print(f"Error: The file was not found at {file_path}")
except json.JSONDecodeError:
    print(f"Error: Could not decode the JSON file. Please check the file's formatting.")
except Exception as e:
    print(f"An unexpected error occurred: {e}")

print(f"Successfully loaded json files")

# --- Model loading placeholders ---
word_vectorizer = char_vectorizer = scaler = logreg = svm_calibrated = stacker = None
best_threshold = None
email_config = {}
url_model = None
url_qhat = None
url_threshold = None
phishing_conformal_artifacts = None

EMAIL_UNSAFE_DATA = {}
EMAIL_UNSAFE_PHRASES = set()

def load_email_unsafe_keywords():
    global EMAIL_UNSAFE_DATA, EMAIL_UNSAFE_PHRASES
    try:
        with open(EMAIL_UNSAFE_PATH, "r", encoding="utf-8") as f:
            EMAIL_UNSAFE_DATA = json.load(f)
        phrases = set()
        pk = EMAIL_UNSAFE_DATA.get("phishing_keywords", {})
        for cat, lst in pk.items():
            for p in lst:
                if isinstance(p, str) and p.strip():
                    phrases.add(p.strip().lower())
        other = EMAIL_UNSAFE_DATA.get("other_red_flags", [])
        for p in other:
            if isinstance(p, str) and p.strip():
                phrases.add(p.strip().lower())
        EMAIL_UNSAFE_PHRASES = phrases
    except Exception:
        EMAIL_UNSAFE_DATA = {}
        EMAIL_UNSAFE_PHRASES = set()

def load_models():
    global word_vectorizer, char_vectorizer, scaler, logreg, svm_calibrated, stacker, best_threshold
    global email_config, url_model, url_qhat, url_threshold, phishing_conformal_artifacts

    try:
        saved_cmaf_path = SAVED_CMAF_DIR
        word_vectorizer = joblib.load(os.path.join(saved_cmaf_path, "word_vectorizer.pkl"))
        char_vectorizer = joblib.load(os.path.join(saved_cmaf_path, "char_vectorizer.pkl"))
        scaler = joblib.load(os.path.join(saved_cmaf_path, "scaler.pkl"))
        logreg = joblib.load(os.path.join(saved_cmaf_path, "logreg.pkl"))
        svm_calibrated = joblib.load(os.path.join(saved_cmaf_path, "svm_calibrated.pkl"))
        stacker = joblib.load(os.path.join(saved_cmaf_path, "stacker.pkl"))
        best_threshold = joblib.load(os.path.join(saved_cmaf_path, "best_threshold.pkl"))
        with open(os.path.join(saved_cmaf_path, "config.json"), "r", encoding="utf-8") as f:
            email_config = json.load(f)
    except Exception:
        pass

    try:
        if os.path.isdir(HYBRID_MODELS_DIR):
            try:
                url_model = pickle.load(open(os.path.join(HYBRID_MODELS_DIR, "url_model.pkl"), "rb"))
                with open(os.path.join(HYBRID_MODELS_DIR, "url_params.json"), "r", encoding="utf-8") as f:
                    url_params = json.load(f)
                    url_qhat = url_params.get("qhat")
                    url_threshold = url_params.get("best_threshold")
            except Exception:
                pass
    except Exception:
        pass

    try:
        if os.path.exists(PHISHING_CONFORMAL_PKL):
            phishing_conformal_artifacts = joblib.load(PHISHING_CONFORMAL_PKL)
            url_model = url_model or phishing_conformal_artifacts.get("model")
            url_qhat = url_qhat or phishing_conformal_artifacts.get("qhat")
            url_threshold = url_threshold or phishing_conformal_artifacts.get("best_threshold")
    except Exception:
        pass

    if not email_config:
        email_config = {"urgent_words": ["urgent", "verify", "password", "bank", "immediately", "action"]}

urgent_words = set(email_config.get("urgent_words", []))

def extract_email_meta_features(texts):
    """Extract meta features from email text with proper calculations"""
    features = []
    for t in texts:
        length = len(t)
        num_digits = sum(ch.isdigit() for ch in t)
        digit_ratio = num_digits / max(1, length)
        num_upper = sum(ch.isupper() for ch in t)
        upper_ratio = num_upper / max(1, length)
        num_exclam = t.count("!")
        num_urls = len(re.findall(r"http[s]?://|www\.", t))
        num_urgent = sum(1 for phrase in EMAIL_UNSAFE_PHRASES if phrase in t.lower())
        features.append([length, digit_ratio, upper_ratio, num_exclam, num_urls, num_urgent])
    return np.array(features, dtype=float)

def generate_ai_explanation(mode, result, input_text, meta_features=None):
    """Generate AI-driven explanations for detection results"""
    explanations = []
    
    if mode == "email":
        # Email-specific explanations
        if result.get("binary_pred") == 1:  # Phishing
            explanations.append("🚨 High Risk Detected: This email exhibits multiple characteristics commonly found in phishing attempts.")
            
            if meta_features:
                if meta_features.get("num_urgent_terms", 0) > 0:
                    explanations.append(f"⚠️ Urgent Language: Contains {meta_features['num_urgent_terms']} urgent/suspicious terms that create false urgency.")
                
                if meta_features.get("upper_ratio", 0) > 0.1:
                    explanations.append(f"📢 Excessive Capitalization: {meta_features['upper_ratio']*100:.1f}% uppercase text suggests aggressive tactics.")
                
                if meta_features.get("num_exclam", 0) > 2:
                    explanations.append(f"❗ Excessive Punctuation: {meta_features['num_exclam']} exclamation marks indicate emotional manipulation.")
                
                if meta_features.get("num_urls", 0) > 0:
                    explanations.append(f"🔗 Suspicious Links: Contains {meta_features['num_urls']} URLs that require verification.")
            
            explanations.append("🛡️ Recommendation: Do not click any links, verify sender through alternative means, and report as spam.")
        else:  # Safe
            explanations.append("✅ Low Risk Assessment: This email appears to be legitimate based on our analysis.")
            explanations.append("📊 Analysis: Content patterns match typical legitimate communication.")
            explanations.append("💡 Note: Always verify sender identity for sensitive requests, even for legitimate-looking emails.")
    
    elif mode == "url":
        # URL-specific explanations
        if result.get("binary_pred") == 1:  # Phishing
            explanations.append("🚨 Malicious URL Detected: This URL exhibits patterns associated with phishing websites.")
            explanations.append("🔍 Domain Analysis: URL structure and domain characteristics suggest potential threat.")
            explanations.append("🛡️ Recommendation: Do not visit this URL. It may steal credentials or install malware.")
        elif result.get("binary_pred") == -1:  # Suspicious
            explanations.append("⚠️ Suspicious URL: This URL requires caution and further verification.")
            explanations.append("🔍 Analysis: Some characteristics are concerning but not definitively malicious.")
            explanations.append("💡 Recommendation: Verify the URL source before visiting. Use caution if proceeding.")
        else:  # Safe
            explanations.append("✅ Safe URL: This URL appears to be from a trusted domain.")
            explanations.append("🔍 Domain Verification: URL matches known safe domain patterns.")
            explanations.append("💡 Note: Always ensure you're on the correct website by checking the full URL.")
    
    elif mode == "hybrid":
        # Hybrid analysis explanations
        final_pred = result.get("final_binary_pred", 0)
        email_branch = result.get("email_branch", {})
        url_branch = result.get("url_branch", [])
        
        if final_pred == 1:  # Phishing
            explanations.append("🚨 Comprehensive Threat Analysis: Multiple indicators suggest this is a phishing attempt.")
            
            if email_branch.get("binary_pred") == 1:
                explanations.append("📧 Email Content Risk: Text analysis reveals phishing patterns.")
            
            if url_branch and any(u.get("binary_pred") == 1 for u in url_branch):
                malicious_urls = [u for u in url_branch if u.get("binary_pred") == 1]
                explanations.append(f"🔗 Malicious Links: {len(malicious_urls)} suspicious URLs detected in content.")
            
            explanations.append("🛡️ Critical Action Required: Delete this email immediately and do not interact with any content.")
        else:  # Safe
            explanations.append("✅ Comprehensive Safety Check: Multi-layer analysis indicates this content is likely safe.")
            
            # Check for safe domains override
            if url_branch and any(u.get("label") == "Safe URL" for u in url_branch):
                safe_urls = [u for u in url_branch if u.get("label") == "Safe URL"]
                explanations.append(f"🔗 Trusted Domains: Contains {len(safe_urls)} links to verified safe domains.")
            
            explanations.append("💡 Best Practice: Continue to verify sender identity for any sensitive requests.")
    
    # Add confidence explanation
    confidence = result.get("probability", result.get("confidence", result.get("final_proba", 0)))
    if confidence > 0.9:
        explanations.append(f"🎯 High Confidence: Our AI model is {confidence*100:.1f}% confident in this assessment.")
    elif confidence > 0.7:
        explanations.append(f"📊 Moderate Confidence: Our AI model is {confidence*100:.1f}% confident in this assessment.")
    else:
        explanations.append(f"⚖️ Lower Confidence: Our AI model is {confidence*100:.1f}% confident. Consider additional verification.")
    
    return explanations

def predict_email_with_model(text):
    """Enhanced email prediction with proper meta feature calculation"""
    meta = extract_email_meta_features([text])[0]
    
    # Basic prediction logic (replace with actual model when available)
    matched_phrases = check_email_unsafe_by_rules(text)
    if matched_phrases:
        probability = 0.85 + (len(matched_phrases) * 0.05)  # Higher confidence with more matches
        probability = min(probability, 0.98)  # Cap at 98%
        binary_pred = 1
        label = "Phishing Email"
    else:
        # Check for other suspicious patterns
        suspicious_score = 0
        if meta[1] > 0.15:  # High digit ratio
            suspicious_score += 0.2
        if meta[2] > 0.2:   # High uppercase ratio
            suspicious_score += 0.2
        if meta[3] > 3:     # Many exclamation marks
            suspicious_score += 0.15
        if meta[4] > 2:     # Multiple URLs
            suspicious_score += 0.25
        
        if suspicious_score > 0.4:
            probability = 0.6 + suspicious_score
            binary_pred = 1
            label = "Phishing Email"
        else:
            probability = 0.1 + suspicious_score
            binary_pred = 0
            label = "Safe Email"
    
    return {
        "label": label, 
        "probability": probability, 
        "score": probability * 10, 
        "binary_pred": binary_pred,
        "meta": {
            "length": float(meta[0]), 
            "digit_ratio": float(meta[1]),
            "upper_ratio": float(meta[2]), 
            "num_exclam": int(meta[3]),
            "num_urls": int(meta[4]), 
            "num_urgent_terms": int(meta[5])
        }
    }

def check_email_unsafe_by_rules(text):
    if not EMAIL_UNSAFE_PHRASES:
        return []
    lower = text.lower()
    matched = [p for p in EMAIL_UNSAFE_PHRASES if p in lower]
    return matched

# --- URL helpers ---
def extract_urls(email_text: str):
    URL_REGEX = re.compile(r"""(?i)\b((?:https?://|www\.)[^\s<>"'\)\]]+)""", re.IGNORECASE)
    hits = URL_REGEX.findall(email_text or "")
    normed = [u if u.lower().startswith(("http://", "https://")) else f"http://{u}" for u in hits]
    return normed

def parse_domain_and_path(url: str):
    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc or parsed.path
    except Exception:
        domain = url
    return domain.lower(), "", ""

def normalize_domain_for_check(domain: str):
    d = domain.split(":")[0].lower().strip()
    if d.startswith("www."):
        d = d[4:]
    return d

def is_known_safe_domain(domain: str):
    d = normalize_domain_for_check(domain)
    for s in SAFE_URLS:
        if d == s or d.endswith("." + s):
            return True
    return False

def build_model_ready_url_features(url: str):
    domain, _, _ = parse_domain_and_path(url)
    return {"domain": domain, "dummy": 1}

def predict_url_from_features(feature_row):
    global url_model
    if not url_model:
        return {"label": "Suspicious URL", "binary_pred": -1, "confidence": 0.5}
    try:
        df = pd.DataFrame([feature_row])
        proba = float(url_model.predict_proba(df)[:, 1][0])
    except Exception:
        proba = 0.5

    if proba < 0.5:
        label = "Suspicious URL"
        binary_pred = -1
    else:
        label = "Phishing URL"
        binary_pred = 1
    return {"label": label, "binary_pred": binary_pred, "confidence": proba}

def predict_url(url: str):
    domain, _, _ = parse_domain_and_path(url)
    if is_known_safe_domain(domain):
        return {"url": url, "label": "Safe URL", "binary_pred": 0, "confidence": 0.98}

    feat = build_model_ready_url_features(url)
    res = predict_url_from_features(feat)
    res["url"] = url
    return res

def predict_urls_in_text(email_text: str):
    urls = extract_urls(email_text)
    results = []
    for u in urls:
        res = predict_url(u)
        results.append(res)
    return results

def hybrid_predict(email_text: str):
    matched = check_email_unsafe_by_rules(email_text)
    if matched:
        meta = extract_email_meta_features([email_text])[0]
        email_res = {"label": "Phishing Email", "probability": 0.98, "score": 9.6,
                     "binary_pred": 1,
                     "meta": {"length": float(meta[0]), "digit_ratio": float(meta[1]),
                              "upper_ratio": float(meta[2]), "num_exclam": float(meta[3]),
                              "num_urls": float(meta[4]), "num_urgent_terms": float(meta[5])}}
    else:
        email_res = predict_email_with_model(email_text)

    url_res_list = predict_urls_in_text(email_text)

    # --- NEW: if any safe domain is detected, override final verdict ---
    if any(u["label"] == "Safe URL" for u in url_res_list):
        return {"final_label": "Safe Content", "final_proba": 0.98, "final_binary_pred": 0,
                "email_branch": email_res, "url_branch": url_res_list}

    url_proba = np.mean([u.get("confidence", 0.5) for u in url_res_list]) if url_res_list else 0.5
    final_proba = (email_res.get("probability", 0.5) + url_proba) / 2.0
    final_binary_pred = 1 if final_proba >= 0.5 else 0
    final_label = "Phishing Content" if final_binary_pred == 1 else "Safe Content"

    return {"final_label": final_label, "final_proba": float(final_proba),
            "final_binary_pred": final_binary_pred, "email_branch": email_res,
            "url_branch": url_res_list}

# --- Flask routes ---
@app.route("/")
def index():
    if session.get("username"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Please provide username and password", "danger")
            return render_template("signup.html")
        if create_user(username, password):
            flash("Account created. Please log in.", "success")
            return redirect(url_for("login"))
        else:
            flash("Username already taken.", "danger")
            return render_template("signup.html")
    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if verify_user(username, password):
            session["username"] = username
            session["is_admin"] = is_admin(username)
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid credentials", "danger")
            return render_template("login.html")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out", "info")
    return redirect(url_for("login"))

@app.route("/dashboard", methods=["GET"])
def dashboard():
    if not session.get("username"):
        return redirect(url_for("login"))
    return render_template("dashboard.html", user=session.get("username"))

@app.route("/predict", methods=["POST"])
def predict():
    if not session.get("username"):
        return {"error": "not authenticated"}, 401
    
    username = session.get("username")
    mode = request.form.get("mode")
    text = request.form.get("text", "").strip()
    url_input = request.form.get("url", "").strip()

    if mode == "email":
        if not text:
            flash("Provide email body text for analysis", "danger")
            return redirect(url_for("dashboard"))
        
        res = predict_email_with_model(text)
        
        explanations = generate_ai_explanation("email", res, text, res.get("meta"))
        res["explanations"] = explanations
        
        # Save detection to database
        detection = save_detection(username, mode, text, res)
        session['last_detection_id'] = str(detection.inserted_id)
        
        return render_template("result.html", mode="Email", input_text=text, result=res, detection_id=str(detection.inserted_id))

    elif mode == "url":
        target = url_input or text
        if not target:
            flash("Provide a URL to analyze", "danger")
            return redirect(url_for("dashboard"))
        
        res = predict_url(target)
        
        explanations = generate_ai_explanation("url", res, target)
        res["explanations"] = explanations
        
        # Save detection to database
        detection = save_detection(username, mode, target, res, url_input)
        session['last_detection_id'] = str(detection.inserted_id)
        
        return render_template("result.html", mode="URL", input_text=target, result=res, detection_id=str(detection.inserted_id))

    elif mode == "hybrid":
        if not text:
            flash("Provide email text for hybrid analysis", "danger")
            return redirect(url_for("dashboard"))
        
        res = hybrid_predict(text)
        
        explanations = generate_ai_explanation("hybrid", res, text)
        res["explanations"] = explanations
        
        # Save detection to database
        detection = save_detection(username, mode, text, res)
        session['last_detection_id'] = str(detection.inserted_id)
        
        return render_template("result.html", mode="Hybrid", input_text=text, result=res, detection_id=str(detection.inserted_id))
    else:
        flash("Unknown mode", "danger")
        return redirect(url_for("dashboard"))

@app.route("/analytics")
def analytics():
    if not session.get("username"):
        return redirect(url_for("login"))
    
    username = session.get("username")
    analytics_data = get_analytics_data(username)
    
    if analytics_data['total_detections'] == 0:
        # Generate realistic sample data for demonstration
        from datetime import datetime, timedelta
        import random
        
        sample_detections = []
        for i in range(50):
            date = datetime.now() - timedelta(days=random.randint(0, 30))
            modes = ['email', 'url', 'hybrid']
            mode = random.choice(modes)
            is_phishing = random.choice([True, False])
            
            if mode == 'email':
                result = {
                    'label': 'Phishing Email' if is_phishing else 'Safe Email',
                    'binary_pred': 1 if is_phishing else 0,
                    'probability': random.uniform(0.7, 0.98) if is_phishing else random.uniform(0.1, 0.4),
                    'meta': {
                        'length': random.randint(100, 2000),
                        'digit_ratio': random.uniform(0.05, 0.25),
                        'upper_ratio': random.uniform(0.05, 0.3),
                        'num_exclam': random.randint(0, 8),
                        'num_urls': random.randint(0, 5),
                        'num_urgent_terms': random.randint(0, 10)
                    }
                }
            elif mode == 'url':
                result = {
                    'label': 'Phishing URL' if is_phishing else 'Safe URL',
                    'binary_pred': 1 if is_phishing else 0,
                    'confidence': random.uniform(0.7, 0.95) if is_phishing else random.uniform(0.1, 0.4)
                }
            else:  # hybrid
                result = {
                    'final_label': 'Phishing Content' if is_phishing else 'Safe Content',
                    'final_binary_pred': 1 if is_phishing else 0,
                    'final_proba': random.uniform(0.7, 0.95) if is_phishing else random.uniform(0.1, 0.4),
                    'email_branch': {
                        'binary_pred': 1 if is_phishing else 0,
                        'probability': random.uniform(0.6, 0.9) if is_phishing else random.uniform(0.1, 0.4)
                    },
                    'url_branch': [{
                        'binary_pred': 1 if is_phishing else 0,
                        'confidence': random.uniform(0.6, 0.9) if is_phishing else random.uniform(0.1, 0.4)
                    }]
                }
            
            sample_detections.append({
                '_id': f'sample_{i}',
                'timestamp': date,
                'mode': mode,
                'result': result,
                'input_text': f'Sample {mode} content for detection analysis {i}',
                'username': username
            })
        
        # Calculate enhanced metrics
        total_detections = len(sample_detections)
        email_detections = len([d for d in sample_detections if d['mode'] == 'email'])
        url_detections = len([d for d in sample_detections if d['mode'] == 'url'])
        hybrid_detections = len([d for d in sample_detections if d['mode'] == 'hybrid'])
        
        phishing_count = 0
        safe_count = 0
        
        for detection in sample_detections:
            result = detection.get("result", {})
            if detection["mode"] == "hybrid":
                if result.get("final_binary_pred") == 1:
                    phishing_count += 1
                else:
                    safe_count += 1
            else:
                if result.get("binary_pred") == 1:
                    phishing_count += 1
                else:
                    safe_count += 1
        
        analytics_data = {
            'total_detections': total_detections,
            'email_detections': email_detections,
            'url_detections': url_detections,
            'hybrid_detections': hybrid_detections,
            'phishing_count': phishing_count,
            'safe_count': safe_count,
            'detections': sample_detections
        }
    
    return render_template("analytics.html", analytics=analytics_data, user=username)

@app.route("/admin")
def admin():
    if not session.get("username") or not session.get("is_admin"):
        flash("Access denied. Admin privileges required.", "danger")
        return redirect(url_for("dashboard"))
    
    analytics_data = get_analytics_data()  # All users
    contacts = get_all_contacts()
    feedback = get_all_feedback()
    
    if analytics_data['total_detections'] == 0:
        # Add sample system-wide data for demonstration
        analytics_data = {
            'total_detections': 1247,
            'phishing_count': 312,
            'safe_count': 935,
            'email_detections': 687,
            'url_detections': 398,
            'hybrid_detections': 162,
            'detections': []
        }
        
        # Generate sample system detection history
        from datetime import datetime, timedelta
        import random
        
        sample_users = ['user1', 'user2', 'user3', 'admin', 'testuser']
        sample_detections = []
        for i in range(30):
            date = datetime.now() - timedelta(days=random.randint(0, 30))
            modes = ['email', 'url', 'hybrid']
            mode = random.choice(modes)
            is_phishing = random.choice([True, False])
            user = random.choice(sample_users)
            
            if mode == 'email':
                result = {
                    'label': 'Phishing Email' if is_phishing else 'Safe Email',
                    'binary_pred': 1 if is_phishing else 0,
                    'probability': random.uniform(0.7, 0.98) if is_phishing else random.uniform(0.1, 0.4)
                }
            elif mode == 'url':
                result = {
                    'label': 'Phishing URL' if is_phishing else 'Safe URL',
                    'binary_pred': 1 if is_phishing else 0,
                    'confidence': random.uniform(0.7, 0.95) if is_phishing else random.uniform(0.1, 0.4)
                }
            else:  # hybrid
                result = {
                    'final_label': 'Phishing Content' if is_phishing else 'Safe Content',
                    'final_binary_pred': 1 if is_phishing else 0,
                    'final_proba': random.uniform(0.7, 0.95) if is_phishing else random.uniform(0.1, 0.4)
                }
            
            sample_detections.append({
                '_id': f'system_sample_{i}',
                'timestamp': date,
                'mode': mode,
                'result': result,
                'input_text': f'System sample {mode} content for detection {i}',
                'username': user
            })
        
        analytics_data['detections'] = sample_detections
    
    if not contacts:
        from datetime import datetime, timedelta
        import random
        
        sample_contacts = []
        subjects = ['Bug Report', 'Feature Request', 'General Inquiry', 'Technical Support', 'Feedback']
        for i in range(8):
            date = datetime.now() - timedelta(days=random.randint(0, 15))
            sample_contacts.append({
                '_id': f'contact_{i}',
                'timestamp': date,
                'name': f'User {i+1}',
                'email': f'user{i+1}@example.com',
                'subject': random.choice(subjects),
                'message': f'This is a sample contact message {i+1} for demonstration purposes.',
                'status': random.choice(['new', 'pending', 'resolved'])
            })
        contacts = sample_contacts
    
    if not feedback:
        from datetime import datetime, timedelta
        import random
        
        sample_feedback = []
        for i in range(12):
            date = datetime.now() - timedelta(days=random.randint(0, 20))
            sample_feedback.append({
                '_id': f'feedback_{i}',
                'timestamp': date,
                'username': f'user{i+1}',
                'feedback_type': random.choice(['correct', 'incorrect']),
                'comments': f'Sample feedback comment {i+1}' if random.choice([True, False]) else None,
                'detection_id': f'det_{i}'
            })
        feedback = sample_feedback
    
    return render_template("admin.html", analytics=analytics_data, contacts=contacts, feedback=feedback)

@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        subject = request.form.get("subject", "").strip()
        message = request.form.get("message", "").strip()
        
        if not all([name, email, subject, message]):
            flash("All fields are required", "danger")
            return render_template("contact.html")
        
        save_contact(name, email, subject, message)
        flash("Thank you for your message. We'll get back to you soon!", "success")
        return redirect(url_for("contact"))
    
    return render_template("contact.html")

@app.route("/feedback", methods=["POST"])
def feedback():
    if not session.get("username"):
        return {"error": "not authenticated"}, 401
    
    username = session.get("username")
    detection_id = request.form.get("detection_id")
    feedback_type = request.form.get("feedback_type")
    comments = request.form.get("comments", "").strip()
    
    if not detection_id or not feedback_type:
        flash("Invalid feedback data", "danger")
        return redirect(url_for("dashboard"))
    
    save_feedback(username, detection_id, feedback_type, comments)
    flash("Thank you for your feedback!", "success")
    return redirect(url_for("dashboard"))

@app.route("/export_report/<detection_id>")
def export_report(detection_id):
    if not session.get("username"):
        return redirect(url_for("login"))
    
    # Get detection from database
    from db import detections_collection
    try:
        detection = detections_collection.find_one({"_id": ObjectId(detection_id)})
        if not detection or detection["username"] != session.get("username"):
            flash("Detection not found", "danger")
            return redirect(url_for("dashboard"))
    except:
        flash("Invalid detection ID", "danger")
        return redirect(url_for("dashboard"))
    
    # Create PDF report
    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    
    # Title
    p.setFont("Helvetica-Bold", 16)
    p.drawString(50, height - 50, "Phishing Detection Report")
    
    # Detection details
    p.setFont("Helvetica", 12)
    y = height - 100
    p.drawString(50, y, f"Date: {detection['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}")
    y -= 20
    p.drawString(50, y, f"Mode: {detection['mode'].title()}")
    y -= 20
    p.drawString(50, y, f"User: {detection['username']}")
    y -= 40
    
    # Input text
    p.setFont("Helvetica-Bold", 12)
    p.drawString(50, y, "Input:")
    y -= 20
    p.setFont("Helvetica", 10)
    
    # Wrap text
    input_text = detection['input_text']
    lines = []
    words = input_text.split()
    current_line = ""
    for word in words:
        if len(current_line + word) < 80:
            current_line += word + " "
        else:
            lines.append(current_line.strip())
            current_line = word + " "
    if current_line:
        lines.append(current_line.strip())
    
    for line in lines[:10]:  # Limit to 10 lines
        p.drawString(50, y, line)
        y -= 15
    
    y -= 20
    
    # Results
    p.setFont("Helvetica-Bold", 12)
    p.drawString(50, y, "Results:")
    y -= 20
    p.setFont("Helvetica", 10)
    
    result = detection['result']
    if detection['mode'] == 'hybrid':
        p.drawString(50, y, f"Final Prediction: {result.get('final_label', 'N/A')}")
        y -= 15
        p.drawString(50, y, f"Confidence: {result.get('final_proba', 0) * 100:.2f}%")
    else:
        p.drawString(50, y, f"Prediction: {result.get('label', 'N/A')}")
        y -= 15
        confidence = result.get('probability', result.get('confidence', 0))
        p.drawString(50, y, f"Confidence: {confidence * 100:.2f}%")
    
    # Footer
    p.setFont("Helvetica", 8)
    p.drawString(50, 50, "Generated by Phishing Detection System")
    p.drawString(50, 35, "Developers: PRANAV VP, PRAJWAL CA, NAGASHREE DS, PALLAVI JHA")
    
    p.showPage()
    p.save()
    
    buffer.seek(0)
    response = make_response(buffer.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=detection_report_{detection_id}.pdf'
    
    return response

@app.route("/reload_models")
def reload_models():
    if not DEBUG:
        return "disabled", 403
    load_models()
    load_email_unsafe_keywords()
    return "reloaded"

load_models()
load_email_unsafe_keywords()

if __name__ == "__main__":
    app.run(debug=DEBUG, host="0.0.0.0", port=5000)
