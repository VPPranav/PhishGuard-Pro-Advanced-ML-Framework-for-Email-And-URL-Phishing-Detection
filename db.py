# FOR MONGODB COMPASS INTEGRATION:
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
from bson import ObjectId

# MongoDB connection
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017/")
DB_NAME = "phishing_detector"

# ✅ Create Mongo client using that URI
client = MongoClient(MONGO_URI)
db = client[DB_NAME]


# Collections
users_collection = db["users"]
detections_collection = db["detections"]
feedback_collection = db["feedback"]
contacts_collection = db["contacts"]

def create_user(username, password):
    """Insert a new user if username is not taken."""
    if users_collection.find_one({"username": username}):
        return False
    password_hash = generate_password_hash(password)
    user_data = {
        "username": username, 
        "password_hash": password_hash,
        "created_at": datetime.utcnow(),
        "is_admin": username == "admin"  # Make admin user automatically
    }
    users_collection.insert_one(user_data)
    
    if username == "admin":
        # Ensure admin user has the correct password
        admin_user = users_collection.find_one({"username": "admin"})
        if admin_user:
            # Update admin password to ppnp@123
            new_password_hash = generate_password_hash("ppnp@123")
            users_collection.update_one(
                {"username": "admin"},
                {"$set": {"password_hash": new_password_hash, "is_admin": True}}
            )
    
    return True

def verify_user(username, password):
    """Check if user exists and password matches."""
    user = users_collection.find_one({"username": username})
    if not user:
        if username == "admin" and password == "ppnp@123":
            create_admin_user()
            user = users_collection.find_one({"username": username})
    
    if not user:
        return False
    return check_password_hash(user["password_hash"], password)

def create_admin_user():
    """Create default admin user with specified credentials"""
    admin_exists = users_collection.find_one({"username": "admin"})
    if not admin_exists:
        password_hash = generate_password_hash("ppnp@123")
        admin_data = {
            "username": "admin",
            "password_hash": password_hash,
            "created_at": datetime.utcnow(),
            "is_admin": True
        }
        users_collection.insert_one(admin_data)
        print("Admin user created successfully")

def is_admin(username):
    """Check if user is admin."""
    user = users_collection.find_one({"username": username})
    return user and user.get("is_admin", False)

def save_detection(username, mode, input_text, result, url_input=None):
    """Save detection result to database."""
    detection_data = {
        "username": username,
        "mode": mode,
        "input_text": input_text,
        "url_input": url_input,
        "result": result,
        "timestamp": datetime.utcnow()
    }
    return detections_collection.insert_one(detection_data)

def get_user_detections(username, limit=None):
    """Get user's detection history."""
    query = {"username": username}
    cursor = detections_collection.find(query).sort("timestamp", -1)
    if limit:
        cursor = cursor.limit(limit)
    return list(cursor)

def get_all_detections(limit=None):
    """Get all detections for admin."""
    cursor = detections_collection.find().sort("timestamp", -1)
    if limit:
        cursor = cursor.limit(limit)
    return list(cursor)

def save_feedback(username, detection_id, feedback_type, comments=None):
    """Save user feedback on detection."""
    feedback_data = {
        "username": username,
        "detection_id": detection_id,
        "feedback_type": feedback_type,  # 'correct' or 'incorrect'
        "comments": comments,
        "timestamp": datetime.utcnow()
    }
    return feedback_collection.insert_one(feedback_data)

def save_contact(name, email, subject, message):
    """Save contact form submission."""
    contact_data = {
        "name": name,
        "email": email,
        "subject": subject,
        "message": message,
        "timestamp": datetime.utcnow(),
        "status": "new"
    }
    return contacts_collection.insert_one(contact_data)

def get_all_contacts():
    """Get all contact submissions for admin with proper serialization."""
    contacts = list(contacts_collection.find().sort("timestamp", -1))
    for contact in contacts:
        contact['_id'] = str(contact['_id'])
    return contacts

def get_all_feedback():
    """Get all feedback for admin with proper serialization."""
    feedback = list(feedback_collection.find().sort("timestamp", -1))
    for fb in feedback:
        fb['_id'] = str(fb['_id'])
    return feedback

def serialize_detection(detection):
    """Convert MongoDB detection document to JSON-serializable format"""
    if detection:
        # Convert ObjectId to string
        detection['_id'] = str(detection['_id'])
        # Ensure timestamp is properly formatted
        if 'timestamp' in detection and hasattr(detection['timestamp'], 'isoformat'):
            detection['timestamp_iso'] = detection['timestamp'].isoformat()
    return detection

def serialize_detections(detections):
    """Convert list of MongoDB detection documents to JSON-serializable format"""
    return [serialize_detection(detection.copy()) for detection in detections]

def get_analytics_data(username=None):
    """Get analytics data for user or all users with proper serialization."""
    if username:
        detections = list(detections_collection.find({"username": username}))
    else:
        detections = list(detections_collection.find())
    
    # Process analytics
    total_detections = len(detections)
    email_detections = len([d for d in detections if d["mode"] == "email"])
    url_detections = len([d for d in detections if d["mode"] == "url"])
    hybrid_detections = len([d for d in detections if d["mode"] == "hybrid"])
    
    # Count phishing vs safe
    phishing_count = 0
    safe_count = 0
    
    for detection in detections:
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
    
    serialized_detections = serialize_detections(detections)
    
    return {
        "total_detections": total_detections,
        "email_detections": email_detections,
        "url_detections": url_detections,
        "hybrid_detections": hybrid_detections,
        "phishing_count": phishing_count,
        "safe_count": safe_count,
        "detections": serialized_detections
    }

create_admin_user()































