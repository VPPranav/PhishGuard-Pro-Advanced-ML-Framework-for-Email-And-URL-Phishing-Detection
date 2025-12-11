# PhishGuard Pro - Advanced ML Framework for Email And URL Phishing Detection

A professional-grade phishing detection system built with Flask and advanced machine learning models. This system provides comprehensive email, URL, and hybrid content analysis with a modern, responsive web interface.

Here’s a preview of the Emotion Detection interface:

![Login Page](working_screenshots/login_page.png)

![Dashboard](working_screenshots/dashboard1.png)

![Analytics](working_screenshots/analytics1.png)

## 📁 Project Structure

````
PHISHGUARD_PRO_WEBAPP/
├── app.py
├── db.py
├── README.md
├── requirements.txt
│
├── datasets/
│   ├── Phishing_Email.csv
│   └── urlset.csv
│
├── models/
│   ├── phishing_hybrid_models/
│   │   ├── best_threshold.pkl
│   │   ├── char_vectorizer.pkl
│   │   ├── config.json
│   │   ├── logreg.pkl
│   │   ├── scaler.pkl
│   │   ├── stacker.pkl
│   │   ├── svm_calibrated.pkl
│   │   ├── url_model.pkl
│   │   ├── url_params.json
│   │   └── word_vectorizer.pkl
│   │
│   ├── saved_cmaf/
│   │   ├── best_threshold.pkl
│   │   ├── char_vectorizer.pkl
│   │   ├── config.json
│   │   ├── logreg.pkl
│   │   ├── scaler_for_auc.pkl
│   │   ├── scaler.pkl
│   │   ├── stacker.pkl
│   │   ├── svm_calibrated.pkl
│   │   └── word_vectorizer.pkl
│   │
│   ├── email_unsafe.json
│   ├── phishing_hybrid_conformal.pkl
│   └── safe_urls.json
│
├── notebooks/
│   ├── email_training_K.ipynb
│   ├── hybrid_fusion3.ipynb
│   └── url_model_training3.ipynb
│
├── static/
│   ├── css/
│   │   └── style.css
│   │
│   └── js/
│       ├── analytics.js
│       └── main.js
│
└── templates/
    ├── admin.html
    ├── analytics.html
    ├── base.html
    ├── contact.html
    ├── dashboard.html
    ├── login.html
    ├── result.html
    └── signup.html
````
![Complete Webapp Class-wise Dataflow](working_screenshots/phishguardpro_class_diagram1.png)

![Email Model Workflow](working_screenshots/email_model_workflow.png)

![URL Model Workflow](working_screenshots/url_development.png)

![MultiStage Detection](working_screenshots/multistage_detection.png)

# 🧠 The Notebooks Explained

This web application integrates 3 notebooks which is used for the detection of 3 types of contents uploaded by the user - email's, url's and email's with url's(hybrid).

---

## 📁 `email_training_K.ipynb`: Email Content Phishing Model

This notebook develops a highly accurate model focused on analyzing the linguistic and structural features of email bodies to detect phishing attempts.

**Goal:**  
Classify email text as *Phishing Email* or *Safe Email*.

**Features:**  
Uses **Composite Meta-data and Anomaly Features (CMAF)** — a fusion of **TF-IDF** (word and character n-grams) and manually engineered **meta-features** such as:
- Email length  
- Digit and symbol ratios  
- Number of URLs in the body  
- Presence of urgent terms like “password”, “urgent”, or “account”  

**Model:**  
A **Stacking Ensemble Classifier** combining:
- Logistic Regression  
- Calibrated Linear SVM  
with a **Ridge Classifier** as the final meta-learner.

**Performance:**  
Achieves exceptional performance with a test **AUC = 0.9980**.

**Output:**  
Exports all pipeline components — vectorizers, scaler, base models, stacker, and adaptive threshold — for integration into the fusion pipeline.

---

## 📁 `url_model_training3.ipynb`: Phishing URL Detection Model

This notebook focuses on classifying URLs by analyzing domain characteristics and linguistic patterns. It provides a crucial complementary signal for the hybrid system.

**Goal:**  
Classify a URL as *Malicious* or *Legitimate*.

**Features:**  
Builds a **Hybrid Feature Space** that combines:
- Deep character n-grams (3–5 grams) from the domain string  
- Numeric and semantic features such as domain ranking, ratio metrics, and Jaccard similarity scores  

**Model:**  
An **ElasticNet Logistic Regression Pipeline** (`LogisticRegression(penalty='elasticnet')`), chosen for efficiency and its ability to handle sparse, high-dimensional data.

**Calibration:**  
Incorporates **Conformal Prediction** to compute a nonconformity threshold (`qhat`), ensuring statistical confidence guarantees (e.g., 95% coverage).

**Output:**  
Exports the final trained model, the conformal `qhat` parameter, and an F1-optimized binary threshold to `phishing_hybrid_conformal.pkl`.

---

## 📁 `hybrid_fusion3.ipynb`: Context-Aware Late Fusion

This notebook integrates both the email and URL models to produce a unified phishing risk prediction for an email containing one or more URLs.

**Goal:**  
Combine email content and URL predictions into a single, comprehensive *Phishing Content* or *Safe Content* score.

**Strategy:**  
Implements a **Late Fusion** approach using a weighted average of the individual model probabilities or scores.

**Fusion Logic:**  
The weighting is **dynamic and context-aware**:
- If URLs are present, the URL model is given higher priority (e.g., 60% URL, 40% Email).  
- The weights adapt based on contextual meta-features such as the number of URLs, the presence of suspicious keywords, or anomaly signals.

**Explainability:**  
Integrates **SHAP** and **LIME** for post-hoc interpretability, showing which linguistic or structural features influenced the final hybrid decision.

---

![WebApp Data Flowchart](working_screenshots/phishguard_pro_webapp_dataflowchart.jpg)

## 🧩 Summary Of The Models

- **Email Model:** Detects phishing through linguistic patterns and meta-anomalies.  
- **URL Model:** Evaluates domain-level and statistical cues with conformal calibration.  
- **Hybrid Fusion:** Dynamically merges both predictions for context-sensitive detection.

---

# 🧠 Phishing Detection Datasets

This repository includes two datasets used for training and evaluating phishing detection systems — one focused on **URLs** and the other on **emails**.
Both datasets are publicly available and have been widely used in academic research and real-world phishing detection experiments.

---

## 🔗 1. PhishStorm – URL Phishing Dataset

**Source:** Aalto University (2014)
**File:** `phishstorm_urls.csv`

### 📘 Description

The **PhishStorm dataset** contains a total of **96,018 URLs**, equally divided into **48,009 legitimate** and **48,009 phishing** entries.
Each record corresponds to a unique URL (represented by its domain) and includes a comprehensive set of **engineered features** derived from the work of Marchal et al. (2014).

The dataset is primarily designed for **phishing URL classification** and **real-time streaming analytics** research.

### 📂 Structure

* The `domain` column serves as a unique identifier for each URL.
* The `label` column indicates the classification status:

  * `0` → Legitimate
  * `1` → Phishing
* The remaining columns represent **computed features** introduced in the PhishStorm paper, capturing lexical, host-based, and network-level characteristics of URLs.

### 🧩 Applications

* Phishing URL detection using ML/DL models
* Streaming and online analytics for security monitoring
* Feature engineering and correlation analysis in cybersecurity
* Benchmark dataset for hybrid URL feature-based models

### 🧾 Citation

> S. Marchal, *PhishStorm – phishing / legitimate URL dataset*, Aalto University, 2014. [Online]. Available: [https://doi.org/10.24342/f49465b2-c68a-4182-9171-075f0ed797d5](https://doi.org/10.24342/f49465b2-c68a-4182-9171-075f0ed797d5)
>
> Related publication:
> S. Marchal, J. Francois, R. State, and T. Engel, “PhishStorm: Detecting Phishing with Streaming Analytics,” *IEEE Transactions on Network and Service Management (TNSM)*, vol. 11, no. 4, pp. 458–471, 2014.

---

## 📧 2. Phishing Email Dataset

**Source:** Kaggle (S. Chakraborty, 2023)
**File:** `Phishing_Email.csv`

### 📘 Description

This dataset consists of **18,649 email samples** labeled as either **phishing** or **legitimate (ham)**.
It is a clean, English-language dataset derived from publicly available email corpora and refined for phishing detection research.

Each entry contains **email text and metadata**, providing a balanced and realistic representation of real-world email communications.

### 📂 Structure

The dataset includes fields such as:

* `Email ID` – Unique identifier for each email
* `Subject` – Subject line of the email
* `Body` – Email body text (plain or partially cleaned)
* `From` – Sender’s email address
* `To` – Receiver’s email address
* `Timestamp` – Date/time when the email was sent
* `Label` – Classification label (`1` = Phishing, `0` = Legitimate)

Some versions may also include **URLs extracted** from the body and **header fields** such as *Reply-To* or *Return-Path*.

### 🧩 Applications

* Training NLP and transformer models (e.g., BERT, RoBERTa) for phishing detection
* Metadata-based classification (sender/receiver patterns, timestamps)
* Feature extraction for hybrid models (email + URL fusion)
* Statistical and linguistic phishing pattern analysis

### 🧾 Citation

> S. Chakraborty, *Phishing Email Detection*, Kaggle, 2023.
> Available: [https://doi.org/10.34740/kaggle/dsv/6090437](https://doi.org/10.34740/kaggle/dsv/6090437)

---

## ⚖️ License & Usage of the datasets

Both datasets are intended for **academic and research purposes only**.
Users should review the original dataset licenses before redistribution or commercial use.

---

![WebApp Workflow](working_screenshots/webapp_workflow_dark.png)

## 🚀 Features Of The Webapp

### Core Detection Capabilities
- **Email Analysis**: Advanced NLP models with TF-IDF vectorization
- **URL Detection**: Machine learning-based URL pattern analysis
- **Hybrid Mode**: Combined email and URL analysis for comprehensive threat detection
- **Real-time Analysis**: Instant results with detailed confidence scores

### Professional UI/UX
- **Dark/Light Theme**: Toggle between themes with persistent preference
- **Responsive Design**: Mobile-first design that works on all devices
- **Professional Styling**: Modern, clean interface suitable for enterprise use
- **Interactive Analytics**: Visual charts and progress indicators

### Advanced Features
- **PDF Report Export**: Generate detailed detection reports
- **User Analytics**: Personal detection history and statistics
- **Admin Dashboard**: System-wide analytics and user management
- **Feedback System**: User feedback collection for model improvement
- **Contact System**: Professional contact form with inquiry management

### Database Integration
- **MongoDB Backend**: Secure user authentication and data storage
- **Detection History**: Complete audit trail of all analyses
- **Feedback Tracking**: User feedback for continuous improvement
- **Contact Management**: Inquiry tracking and support system

## 🛠️ Installation & Setup

### Prerequisites
- Python 3.8+
- MongoDB (local or cloud instance)
- Required Python packages (see requirements.txt)

### Quick Start
1. **Clone and Setup**
   \`\`\`bash
   git clone <repository-url>
   cd phishing-detector
   pip install -r requirements.txt
   \`\`\`

2. **Configure MongoDB**
   \`\`\`bash
   # Set MongoDB URI (optional, defaults to localhost)
   export MONGO_URI="mongodb://localhost:27017/"
   \`\`\`

3. **Run the Application**
   \`\`\`bash
   python app.py
   \`\`\`

4. **Access the System**
   - Open http://localhost:5000
   - Create an account or use admin credentials
   - Admin login: username=`admin`, password=`ppnp@123`


![Results](working_screenshots/results.png)

![Contact](working_screenshots/contact_page.png)

![Admin Dashboard](working_screenshots/admin_dashboard.png)   

![MongoDB Data Storage](working_screenshots/mongodb_storage.png)   

## 📊 System Architecture

### Backend Components
- **Flask Application**: Main web server and API endpoints
- **MongoDB Database**: User data, detections, feedback, and contacts
- **ML Models**: Pre-trained models for email and URL analysis
- **Report Generation**: PDF export functionality using ReportLab

### Frontend Components
- **Responsive Templates**: Jinja2 templates with modern CSS
- **Interactive JavaScript**: Theme switching and form interactions
- **Professional Styling**: Custom CSS with dark/light theme support
- **Analytics Visualization**: CSS-based charts and progress indicators

## 🔧 Configuration

### Environment Variables
- `MONGO_URI`: MongoDB connection string
- `FLASK_SECRET`: Secret key for session management

### Admin Access
- Default admin user is created automatically
- Username: `admin`
- Password: `ppnp@123`

## 📈 Analytics & Reporting

### User Analytics
- Personal detection history
- Threat detection trends
- Mode-wise analysis breakdown
- Exportable PDF reports

### Admin Dashboard
- System-wide statistics
- User feedback monitoring
- Contact inquiry management
- Performance metrics

## 🔒 Security Features

- **Secure Authentication**: Password hashing with Werkzeug
- **Session Management**: Secure session handling
- **Data Validation**: Input sanitization and validation
- **Admin Controls**: Role-based access control

## 👥 Development Team

- **PRANAV VP** 
- **PRAJWAL CA** 

## 📝 API Endpoints

### Authentication
- `POST /login` - User authentication
- `POST /signup` - User registration
- `GET /logout` - User logout

### Detection
- `POST /predict` - Perform phishing detection
- `GET /analytics` - User analytics dashboard
- `GET /export_report/<id>` - Export detection report

### Admin
- `GET /admin` - Admin dashboard (admin only)
- `GET /contact` - Contact form and inquiries
- `POST /feedback` - Submit detection feedback

## ⚙️ Project Dependencies

The project dependencies are listed in `requirements.txt` and are essential for running the phishing detection web application and model pipelines.

### 📄 `requirements.txt`

```
Flask==2.3.3
pymongo==4.5.0
werkzeug==2.3.7
numpy==1.24.3
pandas==2.0.3
scikit-learn==1.3.0
joblib==1.3.2
reportlab==4.0.4
bson
```

### 🧩 Library Usage

* **Flask** → Web framework used to build the phishing detection web application (frontend–backend integration).
* **pymongo** → Enables communication between the Flask app and **MongoDB** for storing user data, logs, or phishing reports.
* **werkzeug** → Provides security utilities and request/response handling; used internally by Flask for password hashing and routing.
* **numpy** → Used for numerical computations, array manipulation, and feature vector handling.
* **pandas** → Data manipulation and preprocessing of CSV datasets (both URLs and emails).
* **scikit-learn** → Core ML library used for training, evaluating, and scaling phishing detection models.
* **joblib** → Model and scaler serialization; used for saving and loading trained ML models efficiently.
* **reportlab** → PDF generation library used for creating downloadable phishing analysis reports.
* **bson** → Handles BSON data types (Binary JSON) when working with MongoDB object IDs and records.

---

## 🚀 Usage

1. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

2. Prepare datasets:

   * Place `phishstorm_urls.csv` and `Phishing_Email.csv` in the project’s `datasets/` directory.

3. Run the Flask application:

   ```bash
   python app.py
   ```

4. Access the phishing detection web interface at:

   ```
   http://localhost:5000
   ```

---


## 🚀 Deployment

### Production Setup
1. Set up MongoDB cluster
2. Configure environment variables
3. Use production WSGI server (Gunicorn recommended)
4. Set up reverse proxy (Nginx recommended)
5. Enable HTTPS with SSL certificates

## 📞 Support

For technical support or inquiries:
- Email: pranavvp1507@gmail.com
- Use the built-in contact form
- Check the FAQ section in the contact page

## 📄 License

This project is developed as an academic/research project. All rights reserved to the development team.

---

**PhishGuard Pro** - Professional Phishing Detection System
*Protecting organizations from email, url's and web-based threats through advanced AI*


