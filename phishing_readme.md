# PhishGuard Pro: Extension & Backend Architecture - Comprehensive Documentation

## Table of Contents

1. [Project Overview](#project-overview)
2. [Architecture Overview](#architecture-overview)
3. [FastAPI Backend - Detailed Explanation](#fastapi-backend---detailed-explanation)
4. [Chrome Extension - Detailed Explanation](#chrome-extension---detailed-explanation)
5. [Complete Request-Response Workflow](#complete-request-response-workflow)
6. [Feature Engineering Pipeline](#feature-engineering-pipeline)
7. [Setup & Installation](#setup--installation)
8. [Running the System](#running-the-system)
9. [Troubleshooting Guide](#troubleshooting-guide)
10. [Technical Deep Dive](#technical-deep-dive)

---

## Project Overview

PhishGuard Pro is an advanced machine learning-based phishing detection system that combines a **FastAPI backend server** with a **Chrome browser extension**. This comprehensive documentation explains the intricate workflow of how these two components work together to protect users from phishing attacks in real-time.

### Key Objectives

- **Real-time URL Analysis**: Detect phishing URLs as users browse the internet
- **ML-Powered Detection**: Utilize trained machine learning models to classify URLs
- **Instant User Feedback**: Provide immediate visual feedback (verdict and confidence score) to users
- **Seamless Integration**: Browser extension that works silently in the background

---

## Architecture Overview

The PhishGuard Pro system follows a **Client-Server Architecture** with the following components:

```
┌─────────────────────────────────────────────────────────────────┐
│                       CHROME BROWSER                             │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │        Chrome Extension (phishing-extension)             │  │
│  │  - popup.html   (UI/Interface)                          │  │
│  │  - popup.js     (Extension Logic)                       │  │
│  │  - manifest.json (Extension Configuration)             │  │
│  │                                                          │  │
│  │  USER INTERACTION: Click "Check This Page" button       │  │
│  └──────────────────────────────────────────────────────────┘  │
│                           ↓                                       │
│                  HTTP POST Request                               │
│              (URL sent to backend server)                        │
└─────────────────────────────────────────────────────────────────┘
                           ↓
        ┌──────────────────────────────────────────┐
        │   Network (localhost:8000 or remote)     │
        └──────────────────────────────────────────┘
                           ↓
┌──────────────────────────────────────────────────────────────────┐
│               FASTAPI BACKEND SERVER                              │
│  (phishing-extension-backend)                                    │
│                                                                   │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ main.py                                                  │   │
│  │ - FastAPI application setup                            │   │
│  │ - CORS middleware configuration                        │   │
│  │ - /predict endpoint (POST)                             │   │
│  │ - Model loading from disk                              │   │
│  └─────────────────────────────────────────────────────────┘   │
│                           ↓                                      │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ utils.py                                                 │   │
│  │ - extract_features() function                           │   │
│  │ - Takes raw URL and builds feature vector              │   │
│  │ - Returns dictionary of extracted features             │   │
│  └─────────────────────────────────────────────────────────┘   │
│                           ↓                                      │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ feature_engineering.py                                  │   │
│  │ - compute_numeric_features() function                  │   │
│  │ - Extract 11 numerical features from URL               │   │
│  │ - Jaccard similarity calculations                      │   │
│  │ - Domain/suffix extraction                             │   │
│  └─────────────────────────────────────────────────────────┘   │
│                           ↓                                      │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ Machine Learning Model                                  │   │
│  │ (phishing_model.pkl - Trained scikit-learn model)       │   │
│  │ - Stacked ensemble classifier                          │   │
│  │ - predict_proba() returns phishing probability         │   │
│  │ - Loaded using joblib.load()                           │   │
│  └─────────────────────────────────────────────────────────┘   │
│                           ↓                                      │
│              JSON Response (Verdict + Confidence)                │
│              - verdict: "phishing" / "legitimate" / "suspicious" │
│              - confidence_score: 0-100%                          │
└──────────────────────────────────────────────────────────────────┘
                           ↓
        ┌──────────────────────────────────────────┐
        │   Network (HTTP Response)                │
        └──────────────────────────────────────────┘
                           ↓
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ Chrome Extension displays results in popup              │  │
│  │ - Color-coded verdict (red/green/orange)               │  │
│  │ - Confidence score percentage                          │  │
│  │ - User sees results in real-time                       │  │
│  └──────────────────────────────────────────────────────────┘  │
│                       CHROME BROWSER                             │
└─────────────────────────────────────────────────────────────────┘
```

---

## FastAPI Backend - Detailed Explanation

### 1. **What is FastAPI?**

FastAPI is a modern, high-performance Python web framework that:
- Makes it incredibly easy to build RESTful APIs
- Automatically validates request data using Pydantic
- Provides automatic interactive API documentation (Swagger/OpenAPI)
- Supports both synchronous and asynchronous request handling
- Has built-in CORS (Cross-Origin Resource Sharing) middleware support

### 2. **Backend File Structure**

```
phishing-extension-backend/
├── main.py                      # FastAPI application entry point
├── utils.py                     # Feature extraction utilities
├── feature_engineering.py       # Advanced feature computation
├── requirements.txt             # Python dependencies
├── model/
│   └── phishing_model.pkl       # Trained scikit-learn model (loaded at startup)
└── test_urls.sh                # Script for testing the API
```

### 3. **Detailed Breakdown of main.py**

#### **3.1 Application Initialization**

```python
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import joblib
import pandas as pd
from utils import extract_features

app = FastAPI()
```

**What happens here:**
- `FastAPI()` creates a new FastAPI application instance that will serve as the web server
- The `app` object is the central hub where all API endpoints are registered
- This object will handle incoming HTTP requests and route them to appropriate functions

#### **3.2 CORS Middleware Configuration**

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
```

**Detailed Explanation:**

**CORS (Cross-Origin Resource Sharing)** is a critical security mechanism in web browsers that prevents malicious scripts from making requests to APIs they shouldn't access.

When your Chrome extension (running in the browser) tries to make a request to the backend server (localhost:8000), the browser performs a CORS check:

1. **Browser makes preflight request**: Before sending the actual request, the browser sends an `OPTIONS` request to check permissions
2. **Server responds with CORS headers**: The server must explicitly allow the request
3. **Browser either allows or blocks the request**: Based on the server's CORS headers

**Our Configuration:**
- `allow_origins=["*"]`: Allows requests from ANY origin (website/domain)
  - In production, replace with specific domain: `allow_origins=["https://myextension.com"]`
  - The `*` wildcard means: "Allow all origins" (only for development)

- `allow_methods=["*"]`: Allows all HTTP methods (GET, POST, PUT, DELETE, OPTIONS, etc.)
  - For production: `allow_methods=["POST"]` (only allow POST requests we need)

- `allow_headers=["*"]`: Allows all HTTP headers in requests
  - For production: `allow_headers=["Content-Type"]` (only Content-Type is needed)

**Why is this critical for our extension?**
Without CORS configuration, the browser would block the extension's request with:
```
Access to XMLHttpRequest at 'http://localhost:8000/predict' from origin 
'chrome-extension://...' has been blocked by CORS policy
```

#### **3.3 Model Loading**

```python
MODEL_PATH = "model/phishing_model.pkl"
loaded = joblib.load(MODEL_PATH)
model = loaded["model"] if isinstance(loaded, dict) and "model" in loaded else loaded
print("✔ Model loaded successfully.")
```

**Detailed Explanation:**

**joblib.load()** is used to deserialize Python objects saved to disk (specifically scikit-learn models).

**How this works:**

1. **Path Definition**: `MODEL_PATH` points to the serialized model file
   - This file contains all the trained parameters, weights, and metadata of the ML model
   - It was created during training phase using `joblib.dump(model, "model/phishing_model.pkl")`

2. **Loading the Model**:
   - `joblib.load()` reads the binary file and reconstructs the Python object in memory
   - The file might contain:
     - Just the model object: `model = loaded`
     - A dictionary with model and metadata: `model = loaded["model"]`
   
3. **Type Checking**:
   - The code checks if the loaded object is a dictionary
   - If yes, it extracts the "model" key
   - If no, it uses the loaded object directly
   
4. **Why load at startup?**
   - Loading during startup ensures the model is ready before any requests arrive
   - Loading for each request would be extremely slow
   - Keeping it in memory allows lightning-fast predictions

**The Model Structure:**
The saved model is a scikit-learn pipeline containing:
- **ColumnTransformer**: Processes text features (TF-IDF vectorization) and numeric features
- **Classifier**: Usually a stacked ensemble combining multiple algorithms
- **predict_proba()**: Returns probability of each class (legitimate vs. phishing)

#### **3.4 Prediction Endpoint**

```python
@app.post("/predict")
def predict(payload: dict):
    try:
        url = payload.get("url")
        if not url:
            raise HTTPException(status_code=400, detail="URL missing")

        feats = extract_features(url)
        X = pd.DataFrame([feats])
        proba = float(model.predict_proba(X)[0][1])
```

**Detailed Explanation:**

##### **@app.post("/predict") Decorator**

- `@app.post(...)` registers this function as an HTTP POST endpoint
- POST method is used (not GET) because we're sending data to the server
- The endpoint URL will be: `http://localhost:8000/predict`
- Other possible decorators: `@app.get()`, `@app.put()`, `@app.delete()`, etc.

##### **Function Parameters**

```python
def predict(payload: dict):
```

- FastAPI automatically deserializes the JSON request body into a Python dictionary
- The parameter name `payload` is arbitrary (could be `request_data`, `data`, etc.)
- FastAPI will validate that the request has valid JSON format

##### **URL Extraction and Validation**

```python
url = payload.get("url")
if not url:
    raise HTTPException(status_code=400, detail="URL missing")
```

- `payload.get("url")` safely extracts the "url" field from the request dictionary
- If "url" is missing or empty, we raise an `HTTPException` with:
  - `status_code=400`: HTTP 400 Bad Request (client error)
  - `detail="URL missing"`: Error message to return to client
- The client (extension) receives: `{"detail":"URL missing"}`

##### **Feature Extraction**

```python
feats = extract_features(url)
```

- Calls the `extract_features()` function from `utils.py` (see next section)
- Returns a dictionary with all features: `{"domain": "...", "ranking": 10000000, "mld_res": 5, ...}`
- This is the most critical step - converts raw URL into meaningful numerical features

##### **DataFrame Creation**

```python
X = pd.DataFrame([feats])
```

- Creates a pandas DataFrame with one row
- Columns are feature names, values are extracted features
- scikit-learn models expect data in this format
- Example:
```python
X = pd.DataFrame([{
    "domain": "https://example.com",
    "ranking": 10000000,
    "mld_res": 7,
    "mld.ps_res": 3,
    "card_rem": 1,
    "ratio_Rrem": 0.1,
    ...
}])
```

##### **Prediction**

```python
proba = float(model.predict_proba(X)[0][1])
```

**Breaking this down step-by-step:**

1. `model.predict_proba(X)`: Calls the model's probability prediction method
   - Input: DataFrame with features
   - Output: 2D array of shape (1, 2) because we have 2 classes (legitimate, phishing)
   - Example: `[[0.85, 0.15]]` means 85% legitimate, 15% phishing

2. `[0]`: Selects the first (and only) row of predictions
   - Result: `[0.85, 0.15]`

3. `[1]`: Selects the second element (phishing probability)
   - Result: `0.15`

4. `float()`: Converts to Python float for JSON serialization
   - Ensures compatibility when sending response

##### **Verdict Logic**

```python
if proba < 0.001:
    verdict = "legitimate"
elif proba > 0.5:
    verdict = "phishing"
else:
    verdict = "suspicious"
```

**Three-class classification system:**

- **Legitimate** (proba < 0.001): 99.9% confident it's safe
  - Extremely low phishing probability (< 0.1%)

- **Phishing** (proba > 0.5): More than 50% likely to be phishing
  - Model thinks it's phishing with high confidence

- **Suspicious** (0.001 ≤ proba ≤ 0.5): Uncertain classification
  - Falls between legitimate and phishing
  - Needs additional caution

**Why three categories?**
- Binary classification (safe/phishing) is too rigid
- Some URLs are borderline cases that don't fit neatly
- Users should be aware of uncertain cases

##### **Confidence Score Calculation**

```python
confidence_score = (
    1 - proba if verdict == "legitimate"
    else proba if verdict == "phishing"
    else abs(0.5 - proba) * 2
)
```

**Explanation:**

1. **For "legitimate" verdict**: `confidence = 1 - proba`
   - If proba = 0.01, confidence = 0.99 (99% confident it's safe)
   - The lower the phishing probability, the higher the confidence

2. **For "phishing" verdict**: `confidence = proba`
   - If proba = 0.9, confidence = 0.9 (90% confident it's phishing)
   - The higher the phishing probability, the higher the confidence

3. **For "suspicious" verdict**: `confidence = abs(0.5 - proba) * 2`
   - If proba = 0.3, confidence = abs(0.5 - 0.3) * 2 = 0.4 (40% confidence)
   - If proba = 0.6, confidence = abs(0.5 - 0.6) * 2 = 0.2 (20% confidence)
   - Scales the distance from 0.5 (uncertain boundary)

##### **Response Formatting**

```python
return {
    "url": url,
    "verdict": verdict,
    "confidence_score": round(confidence_score * 100, 2)
}
```

Returns JSON response:
```json
{
    "url": "https://example.com",
    "verdict": "legitimate",
    "confidence_score": 98.5
}
```

- `confidence_score * 100`: Converts from decimal (0.985) to percentage (98.5)
- `round(..., 2)`: Rounds to 2 decimal places
- The extension receives this JSON and displays it to the user

##### **Error Handling**

```python
except Exception as e:
    print("❌ Prediction error:", e)
    raise HTTPException(status_code=500, detail=str(e))
```

- Catches any unexpected errors during prediction
- `HTTPException(status_code=500)`: Returns HTTP 500 Internal Server Error
- Includes error message for debugging
- Extension displays: `{"detail": "Error message..."}`

---

### 4. **Detailed Breakdown of utils.py**

#### **4.1 extract_features() Function**

```python
def extract_features(url: str):
    """
    EXACT FEATURE SCHEMA as expected by your saved ColumnTransformer.
    """
    
    domain_raw = url.strip()
    
    numeric = compute_numeric_features(url)
    
    ranking_value = 10_000_000
    
    features = {
        "domain": domain_raw,
        "ranking": ranking_value,
    }
    
    features.update(numeric)
    
    return features
```

**Detailed Explanation:**

##### **Step 1: URL Cleaning**

```python
domain_raw = url.strip()
```

- `url.strip()` removes leading/trailing whitespace
- Example: `"  https://example.com  "` → `"https://example.com"`
- This ensures clean input for feature extraction

##### **Step 2: Compute Numeric Features**

```python
numeric = compute_numeric_features(url)
```

- Calls `compute_numeric_features()` (in feature_engineering.py)
- Returns dictionary of 11 numeric features
- Detailed in next section

##### **Step 3: Ranking Value**

```python
ranking_value = 10_000_000
```

- Constant value representing domain ranking
- `10_000_000` = 10 million (Python allows underscores for readability)
- This was a feature used during model training
- Fixed value for all URLs (from training schema)

##### **Step 4: Feature Dictionary Assembly**

```python
features = {
    "domain": domain_raw,
    "ranking": ranking_value,
}

features.update(numeric)
```

- Creates dictionary with "domain" and "ranking"
- `features.update(numeric)` adds all numeric features
- Final result contains all features needed by the model

**Final Feature Dictionary Example:**
```python
{
    "domain": "https://malicious-site.com",
    "ranking": 10000000,
    "mld_res": 16,                    # Domain length
    "mld.ps_res": 3,                  # Suffix length
    "card_rem": 2,                    # Digit count
    "ratio_Rrem": 0.105,              # Digit ratio
    "ratio_Arem": 0.526,              # Letter ratio
    "jaccard_RR": 1.0,
    "jaccard_RA": 0.85,
    "jaccard_AR": 0.85,
    "jaccard_AA": 1.0,
    "jaccard_ARrd": 0.625,
    "jaccard_ARrem": 0.842
}
```

---

### 5. **Detailed Breakdown of feature_engineering.py**

#### **5.1 Jaccard Similarity Function**

```python
def jaccard(a: str, b: str) -> float:
    """Compute Jaccard similarity between sets of characters."""
    A, B = set(a), set(b)
    if len(A.union(B)) == 0:
        return 0.0
    return len(A.intersection(B)) / len(A.union(B))
```

**What is Jaccard Similarity?**

Jaccard Similarity measures how similar two sets are. It's calculated as:

```
Jaccard(A, B) = |A ∩ B| / |A ∪ B|

Where:
- |A ∩ B| = Number of elements in both A and B (intersection)
- |A ∪ B| = Total number of unique elements in A and B (union)
```

**Example:**
```
String A: "phishing"
String B: "shipping"

Set A: {p, h, i, s, n, g}
Set B: {s, h, i, p, n, g}

Intersection: {p, h, i, s, n, g} = 6 elements
Union: {p, h, i, s, n, g} = 6 elements

Jaccard = 6 / 6 = 1.0 (identical sets)
```

**Why Use Jaccard for Phishing Detection?**

- Phishing URLs often try to mimic legitimate URLs
- By comparing character sets, we can detect impersonation attempts
- Different characters suggest different origins/intentions

#### **5.2 compute_numeric_features() Function**

```python
def compute_numeric_features(url: str):
    """
    Reproduces EXACT numeric feature logic used in your notebook.
    """
    
    ext = tldextract.extract(url)
    mld = ext.domain or ""
    ps = ext.suffix or ""
```

**Step 1: URL Parsing with tldextract**

- `tldextract.extract(url)` parses URL into components
- Example for `"https://subdomain.example.co.uk:8080/path?query=1"`:
  - `domain` = "example"
  - `suffix` = "co.uk"
  - `subdomain` = "subdomain"

**Why not use urllib?**
- urllib only handles basic URL parsing
- tldextract specifically handles complex TLDs (co.uk, com.br, etc.)
- Phishing detection needs accurate domain/TLD separation

#### **5.3 Feature Extraction Details**

```python
mld_res = len(mld)                                    # Domain length
mld_ps_res = len(ps)                                  # Suffix length

card_rem = sum(c.isdigit() for c in url)             # Digit count
ratio_Rrem = card_rem / (len(url) + 1)               # Digit ratio
ratio_Arem = sum(c.isalpha() for c in url) / (len(url) + 1)  # Letter ratio
```

**Feature Meanings:**

| Feature | Meaning | Phishing Insight |
|---------|---------|-----------------|
| `mld_res` | Domain name length | Phishing domains often have longer names to confuse |
| `mld_ps_res` | TLD suffix length | Some fake TLDs might have unusual lengths |
| `card_rem` | Number of digits in URL | Phishing often uses numeric IPs or encoded URLs |
| `ratio_Rrem` | Proportion of digits | Phishing URLs may have unusual digit ratios |
| `ratio_Arem` | Proportion of letters | Legitimate URLs have higher letter content |

#### **5.4 Tokenization and Jaccard Similarities**

```python
tokens_R = re.sub(r"[^a-zA-Z0-9]", "", url)         # Alphanumeric only
tokens_A = re.sub(r"[^a-zA-Z]", "", url)            # Letters only

jaccard_RR = jaccard(tokens_R, tokens_R)            # Always 1.0
jaccard_RA = jaccard(tokens_R, tokens_A)            # Alphanumeric vs Letters
jaccard_AR = jaccard(tokens_A, tokens_R)            # Letters vs Alphanumeric
jaccard_AA = jaccard(tokens_A, tokens_A)            # Always 1.0

jaccard_ARrd = jaccard(tokens_A, mld)               # Letters vs domain
jaccard_ARrem = jaccard(tokens_A, url)              # Letters vs full URL
```

**Why These Comparisons?**

- **jaccard_RA**: Ratio of alphanumeric to alphabetic characters
  - Low value = many digits in URL (suspicious)
  - High value = mostly letters (legitimate)

- **jaccard_ARrd**: How similar are letters to the domain?
  - High value = domain contains most letters from URL (normal)
  - Low value = many extra letters outside domain (suspicious)

- **jaccard_ARrem**: How similar are letters to the entire URL?
  - Measures character distribution in URL

---

## Chrome Extension - Detailed Explanation

### 1. **What is a Chrome Extension?**

A Chrome extension is a small software program that modifies the Chrome browser's functionality. It runs in a sandboxed environment with limited but specific permissions, making it secure and lightweight.

### 2. **Extension File Structure**

```
phishing-extension/
├── manifest.json      # Extension configuration & permissions
├── popup.html         # User interface (what users see)
├── popup.js          # JavaScript logic (what happens when user clicks)
├── icon16.png        # Extension icon (appears in toolbar)
└── icon48.png (optional)
```

### 3. **Detailed Breakdown of manifest.json**

```json
{
  "manifest_version": 3,
  "name": "Phishing Detector",
  "version": "1.0",
  "permissions": ["activeTab"],
  "action": {
    "default_popup": "popup.html"
  }
}
```

**Detailed Explanation:**

#### **Manifest Version**

```json
"manifest_version": 3
```

- Chrome extensions use versioned API specifications
- Manifest V3 is the latest standard (as of 2024)
- V2 is deprecated and Chrome no longer supports it
- Each version has different capabilities and security requirements

#### **Extension Metadata**

```json
"name": "Phishing Detector",
"version": "1.0"
```

- `name`: Display name in Chrome Web Store and extensions menu
- `version`: Semantic versioning (major.minor)
- Users see these in: `chrome://extensions/`

#### **Permissions**

```json
"permissions": ["activeTab"]
```

**The Permission System:**

Chrome extensions have a principle of least privilege - they only get permissions users explicitly grant.

- `activeTab`: Permission to access the URL of the currently active tab
  - Without this, we cannot read `tab.url` in popup.js
  - When user clicks extension icon, we can read the current page URL
  - This does NOT give access to page content or cookies (for security)

**What we CAN do with activeTab:**
- ✅ Get the current tab's URL
- ✅ Take screenshots of the page
- ✅ Inject scripts into the page

**What we CANNOT do:**
- ❌ Read page content without explicit permission
- ❌ Access cookies or localStorage
- ❌ Modify the page without content_scripts permission

#### **Action (Popup Configuration)**

```json
"action": {
  "default_popup": "popup.html"
}
```

- `action`: Defines what happens when user clicks extension icon
- `default_popup`: URL of HTML file to display
- Creates the popup window showing the UI
- Browser automatically manages popup lifecycle

**User Interaction Flow:**
1. User clicks PhishGuard icon in toolbar
2. Chrome displays `popup.html` in a small window
3. User sees UI with "Check This Page" button
4. User clicks button → `popup.js` runs

---

### 4. **Detailed Breakdown of popup.html**

The HTML file contains the user interface. Here's the relevant structure:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PhishGuard AI</title>
    <style>
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            width: 320px;
            background: linear-gradient(135deg, #0f172a 0%, #1e3a8a 100%);
            color: #f1f5f9;
            padding: 20px;
            display: flex;
            flex-direction: column;
            align-items: center;
            min-height: 250px;
            border-radius: 25px;
            overflow: hidden;
        }

        .header {
            display: flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 25px;
        }
        
        /* ... more styles ... */
    </style>
</head>
<body>
    <!-- UI Elements here -->
    <div id="result"></div>
    <button id="checkBtn">Check This Page</button>

    <script src="popup.js"></script>
</body>
</html>
```

**Key HTML Elements:**

1. **Meta Tags**
   - `charset="UTF-8"`: Character encoding (handles special characters)
   - `viewport`: Responsive design (though less relevant for extensions)

2. **Styling**
   - Gradient background: `#0f172a` to `#1e3a8a` (dark blue gradient)
   - Fixed width: 320px (typical popup width)
   - Flexbox layout: Center content vertically/horizontally
   - Border radius: 25px (rounded corners)

3. **UI Elements**
   - `<div id="result">`: Where prediction results are displayed
   - `<button id="checkBtn">`: Button to trigger analysis
   - `<script src="popup.js">`: Loads JavaScript logic

**Styling Breakdown:**

```css
body {
    font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    /* Uses system fonts for consistency and performance */
    
    width: 320px;
    /* Fixed width for popup window */
    
    background: linear-gradient(135deg, #0f172a 0%, #1e3a8a 100%);
    /* 45-degree gradient from dark blue to lighter blue */
    
    color: #f1f5f9;
    /* Light gray text for contrast on dark background */
    
    padding: 20px;
    /* Space around edges */
    
    display: flex;
    flex-direction: column;
    align-items: center;
    /* Centers content both horizontally and vertically */
    
    min-height: 250px;
    /* Minimum height allows content to expand */
}
```

---

### 5. **Detailed Breakdown of popup.js**

This is where the core extension logic happens.

#### **5.1 Complete Code with Annotations**

```javascript
document.getElementById("checkBtn").addEventListener("click", async () => {
```

**Explanation:**

- `document.getElementById("checkBtn")`: Finds button element with id="checkBtn"
- `.addEventListener("click", ...)`: Registers a function to run when button is clicked
- `async () => { }`: Arrow function marked as async (can use await inside)

#### **5.2 Getting the Current Tab URL**

```javascript
let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
let url = tab.url;
```

**Step-by-step Explanation:**

1. **chrome.tabs.query()**
   - Queries Chrome's tabs API
   - Returns array of tabs matching criteria
   
2. **Query Parameters**
   ```javascript
   {
       active: true,              // Currently active tab
       currentWindow: true        // In the current window (not background tabs)
   }
   ```
   
3. **Array Destructuring**
   ```javascript
   let [tab] = await chrome.tabs.query(...)
   // Equivalent to:
   let tabs = await chrome.tabs.query(...);
   let tab = tabs[0];
   ```
   - Takes first element of array
   - Extracts to variable `tab`

4. **URL Extraction**
   ```javascript
   let url = tab.url;
   // Example: "https://suspicious-bank-login.com"
   ```

**Important Note:**
- `chrome.tabs.query()` is async (returns Promise)
- Must use `await` to wait for result
- Without `await`, `tab` would be a Promise, not the actual data

#### **5.3 Sending Request to Backend**

```javascript
const res = await fetch("http://localhost:8000/predict", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url })
});
```

**Detailed Breakdown:**

##### **Fetch API**

`fetch()` is the modern way to make HTTP requests from JavaScript.

**Parameters:**

1. **URL**: `"http://localhost:8000/predict"`
   - Backend server address (running on same machine)
   - Port 8000 (FastAPI default)
   - Path `/predict` (our endpoint)
   - Why localhost? Extension is testing locally during development

2. **Request Configuration Object**

   ```javascript
   {
       method: "POST",
       headers: { "Content-Type": "application/json" },
       body: JSON.stringify({ url })
   }
   ```

   - **method**: HTTP method (POST sends data in request body)
   - **headers**: Metadata about the request
     - `Content-Type: application/json` tells server data is JSON
   - **body**: The data to send
     - `JSON.stringify({ url })` converts object to JSON string
     - Example: `{ "url": "https://example.com" }` → `'{"url":"https://example.com"}'`

##### **Request/Response Flow**

```
Extension                          Backend
   |                                  |
   |------ POST /predict ------>     |
   |  { "url": "https://..." }       |
   |                                  |
   |      [Processing...]             |
   |      [Feature Extraction]        |
   |      [ML Prediction]             |
   |                                  |
   |<----- 200 OK --------     |
   |  { "verdict": "...",             |
   |    "confidence_score": 85.5 }    |
```

#### **5.4 Handling Response**

```javascript
const data = await res.json();
if (!res.ok) {
    result.textContent = `Error: ${data.detail}`;
    return;
}
```

**Explanation:**

1. **res.json()**
   - Parses JSON response from server
   - Example: `'{"verdict":"phishing"...}'` → `{verdict: "phishing", ...}`
   - Async operation (returns Promise), so use `await`

2. **res.ok Check**
   - HTTP status codes:
     - 200-299: Success (res.ok = true)
     - 400-499: Client error (res.ok = false)
     - 500-599: Server error (res.ok = false)
   - If error, display error message and exit

3. **Error Display**
   - `result.textContent` updates the display element
   - Shows: `"Error: URL missing"` or `"Error: Internal server error"`

#### **5.5 Color-Coded Verdict Display**

```javascript
let color =
    data.verdict === "phishing" ? "red" :
    data.verdict === "legitimate" ? "green" : "orange";

result.innerHTML = `
    <div>Verdict: <span style="color:${color}; font-weight:bold;">${data.verdict.toUpperCase()}</span></div>
    <div style="margin-top:8px;">Confidence Score: <b>${data.confidence_score}%</b></div>
`;
```

**Explanation:**

1. **Ternary Operator for Color Selection**
   ```javascript
   condition ? valueIfTrue : valueIfFalse
   ```
   - "phishing" → red (danger!)
   - "legitimate" → green (safe!)
   - "suspicious" → orange (caution!)

2. **Template Literals**
   ```javascript
   `<div>Verdict: <span style="color:${color}; font-weight:bold;">${data.verdict.toUpperCase()}</span></div>`
   ```
   - Backticks allow ${variable} interpolation
   - `data.verdict.toUpperCase()`: Converts verdict to uppercase
   - Example: "phishing" → "PHISHING"

3. **HTML Rendering**
   ```javascript
   result.innerHTML = `...`
   ```
   - `innerHTML` sets HTML content (unlike textContent which treats as plain text)
   - Displays formatted verdict and confidence score
   - User sees: 
     ```
     Verdict: PHISHING (in red)
     Confidence Score: 87.5%
     ```

#### **5.6 Error Handling**

```javascript
catch (err) {
    console.error(err);
    result.textContent = "Error: Could not reach backend";
}
```

**Explanation:**

- Catches any errors in the entire try block
- Common errors:
  - Backend not running: Connection refused
  - Network issues: Connection timeout
  - Invalid JSON from server: Parse error
- Displays user-friendly message
- `console.error(err)`: Logs full error for debugging (visible in DevTools)

---

## Complete Request-Response Workflow

### **Scenario: User checks a URL for phishing**

#### **Phase 1: User Interaction** (Approximately 50-200ms)

```
1. User opens Gmail: https://mail.google.com
2. User clicks PhishGuard extension icon in toolbar
3. Extension popup appears (popup.html rendered)
4. popup.js loads and waits for click
5. User clicks "Check This Page" button
```

#### **Phase 2: Data Collection** (Approximately 10-50ms)

```
popup.js executes:
├─ chrome.tabs.query() gets current tab
├─ Extracts URL: "https://mail.google.com"
└─ Result: url = "https://mail.google.com"
```

#### **Phase 3: HTTP Request** (Approximately 5-20ms)

```
fetch() sends HTTP POST request to http://localhost:8000/predict

Request Details:
├─ Method: POST
├─ URL: http://localhost:8000/predict
├─ Headers: Content-Type: application/json
├─ Body: {"url":"https://mail.google.com"}
└─ Status: In transit...
```

#### **Phase 4: Backend Processing** (Approximately 50-200ms)

```
main.py @app.post("/predict") function executes:

Step 1: Receive Request (1ms)
├─ Extract: url = "https://mail.google.com"
└─ Validate: URL is present ✓

Step 2: Feature Extraction (10-30ms)
├─ Call extract_features(url)
└─ Extract Features:
   ├─ domain: "https://mail.google.com"
   ├─ ranking: 10000000
   ├─ mld_res: 6
   ├─ mld.ps_res: 3
   ├─ card_rem: 0
   ├─ ratio_Rrem: 0.0
   ├─ ratio_Arem: 0.7
   ├─ jaccard_RR: 1.0
   ├─ jaccard_RA: 1.0
   ├─ jaccard_AR: 1.0
   ├─ jaccard_AA: 1.0
   ├─ jaccard_ARrd: 0.857
   └─ jaccard_ARrem: 0.786

Step 3: DataFrame Creation (1ms)
├─ Convert dict to pandas DataFrame
└─ Shape: (1, 13) - one row, 13 features

Step 4: ML Prediction (20-50ms)
├─ model.predict_proba(X)
└─ Output: [[0.02, 0.98]]
   ├─ 2% probability of phishing
   └─ 98% probability of legitimate

Step 5: Verdict Logic (1ms)
├─ proba = 0.02 (< 0.001)
└─ verdict = "legitimate"

Step 6: Confidence Calculation (1ms)
├─ verdict = "legitimate"
├─ confidence = 1 - 0.02 = 0.98
├─ confidence_score = 0.98 * 100 = 98.0
└─ confidence_score (rounded) = 98.0

Step 7: Response Preparation (1ms)
└─ Return JSON:
   {
     "url": "https://mail.google.com",
     "verdict": "legitimate",
     "confidence_score": 98.0
   }
```

#### **Phase 5: HTTP Response** (Approximately 5-20ms)

```
HTTP Response from backend to extension:

Response Details:
├─ Status Code: 200 OK
├─ Headers: Content-Type: application/json
├─ Body: 
│  {
│    "url": "https://mail.google.com",
│    "verdict": "legitimate",
│    "confidence_score": 98.0
│  }
└─ In transit back to browser...
```

#### **Phase 6: Display Results** (Approximately 10-50ms)

```
popup.js processes response:

Step 1: Parse JSON (1ms)
├─ data = JSON.parse(response)
└─ Result: Object with verdict and score

Step 2: Status Check (1ms)
├─ res.ok = true (200 OK)
└─ Continue processing

Step 3: Determine Color (1ms)
├─ data.verdict = "legitimate"
└─ color = "green"

Step 4: Prepare HTML (1ms)
├─ Verdict: "LEGITIMATE" (in green, bold)
└─ Confidence Score: 98.0%

Step 5: Update DOM (5-10ms)
├─ result.innerHTML = formatted HTML
└─ User sees results!
```

#### **Total Time: ~200-500ms**

From click to display, the entire process takes less than half a second!

---

## Feature Engineering Pipeline

### **Why Features Matter**

Raw URLs are just strings. Machine learning models need numerical features to work with:

```
Input: "https://suspicious-login-site.com"
        ↓
Feature Engineering
        ↓
Output: [0.85, 0.15, 23, 3, 0, 0.0, 0.95, ...]
        ↓
ML Model
        ↓
Output: 85% phishing probability
```

### **The 13 Features Explained**

| # | Feature | Type | Range | Calculation | Phishing Indicator |
|---|---------|------|-------|-------------|-------------------|
| 1 | domain | String | N/A | Raw URL | Base for other features |
| 2 | ranking | Numeric | 10M | Constant | Historical domain trust score |
| 3 | mld_res | Numeric | 1-50+ | len(domain) | Longer = more suspicious |
| 4 | mld.ps_res | Numeric | 1-10+ | len(TLD) | Unusual TLD length = suspicious |
| 5 | card_rem | Numeric | 0-50+ | digit_count(url) | Many digits = suspicious |
| 6 | ratio_Rrem | Numeric | 0-1 | digits/length | High ratio = suspicious |
| 7 | ratio_Arem | Numeric | 0-1 | letters/length | Low ratio = suspicious |
| 8 | jaccard_RR | Numeric | 0-1 | jaccard(alphanumeric, alphanumeric) | Similarity metric |
| 9 | jaccard_RA | Numeric | 0-1 | jaccard(alphanumeric, alpha) | Character distribution |
| 10 | jaccard_AR | Numeric | 0-1 | jaccard(alpha, alphanumeric) | Character distribution |
| 11 | jaccard_AA | Numeric | 0-1 | jaccard(alpha, alpha) | Always 1.0 (baseline) |
| 12 | jaccard_ARrd | Numeric | 0-1 | jaccard(letters, domain) | Domain composition |
| 13 | jaccard_ARrem | Numeric | 0-1 | jaccard(letters, full_url) | URL composition |

### **Feature Extraction Examples**

#### **Example 1: Legitimate URL**

```
URL: "https://www.amazon.com"

Extraction:
├─ domain: "https://www.amazon.com"
├─ ranking: 10000000
├─ mld_res: 6 (len("amazon"))
├─ mld.ps_res: 3 (len("com"))
├─ card_rem: 0 (no digits)
├─ ratio_Rrem: 0.0 (0 digits / 28 total)
├─ ratio_Arem: 0.86 (24 letters / 28 total)
├─ jaccard_RR: 1.0 (identical sets)
├─ jaccard_RA: 1.0 (only letters anyway)
├─ jaccard_AR: 1.0
├─ jaccard_AA: 1.0
├─ jaccard_ARrd: 0.857 (letters vs domain)
└─ jaccard_ARrem: 0.833 (letters vs full URL)

Model sees: [legitimate characteristics]
Prediction: 2% phishing, 98% legitimate ✓
```

#### **Example 2: Phishing URL**

```
URL: "https://amaz0n-support-v3r1fy.com"

Extraction:
├─ domain: "https://amaz0n-support-v3r1fy.com"
├─ ranking: 10000000
├─ mld_res: 21 (len("amaz0n-support-v3r1fy"))
├─ mld.ps_res: 3 (len("com"))
├─ card_rem: 4 (digits: 0, 3, 1, 5)
├─ ratio_Rrem: 0.13 (4 / 30 total)
├─ ratio_Arem: 0.77 (23 / 30 total)
├─ jaccard_RR: 1.0
├─ jaccard_RA: 0.92 (many letters but also digits)
├─ jaccard_AR: 0.92
├─ jaccard_AA: 1.0
├─ jaccard_ARrd: 0.74 (letters don't match domain well)
└─ jaccard_ARrem: 0.82 (letters vs full URL)

Model sees: [phishing characteristics]
- Longer domain name (21 vs 6)
- Numbers mixed in (unusual for legitimate)
- Jaccard similarities suggest different composition
Prediction: 87% phishing, 13% legitimate ⚠️
```

---

## Setup & Installation

### **Prerequisites**

Before installing, ensure you have:
- Python 3.8 or higher
- pip (Python package installer)
- Chrome browser (for extension)
- Git (optional, for cloning)

### **Backend Setup**

#### **Step 1: Navigate to Backend Directory**

```bash
cd phishing-extension-backend
```

#### **Step 2: Create Virtual Environment**

```bash
# Create virtual environment
python -m venv venv

# Activate it (Linux/Mac)
source venv/bin/activate

# Activate it (Windows)
venv\Scripts\activate
```

**Why virtual environment?**
- Isolates project dependencies
- Prevents conflicts with system Python
- Easy to remove (just delete venv folder)
- Can run multiple projects with different versions

#### **Step 3: Install Dependencies**

```bash
pip install -r requirements.txt
```

**What gets installed:**
- `fastapi`: Web framework
- `uvicorn`: ASGI server to run FastAPI
- `joblib`: Load trained ML models
- `scikit-learn`: ML algorithms and preprocessing
- `numpy`: Numerical computing
- `pandas`: Data manipulation
- `tldextract`: URL parsing

#### **Step 4: Verify Model File**

```bash
ls -la model/
# Should show: phishing_model.pkl
```

### **Extension Setup**

#### **Step 1: Open Chrome Extensions**

```
1. Open Chrome browser
2. Go to: chrome://extensions/
3. Enable "Developer mode" (toggle in top right)
```

#### **Step 2: Load Extension**

```
1. Click "Load unpacked"
2. Navigate to: phishing-extension folder
3. Select and open the folder
4. Extension appears in list and toolbar!
```

**What you should see:**
- Extension name: "Phishing Detector"
- Extension icon in toolbar
- "Enabled" status

---

## Running the System

### **Step 1: Start Backend Server**

In terminal (phishing-extension-backend directory):

```bash
# Make sure venv is activated
source venv/bin/activate

# Start FastAPI server
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

**Output should look like:**
```
INFO:     Uvicorn running on http://0.0.0.0:8000 [ENTER or CTRL+C to quit]
INFO:     Started server process [1234]
✔ Model loaded successfully.
```

**Parameters:**
- `--reload`: Auto-restart on code changes (development only)
- `--host 0.0.0.0`: Accept requests from any address
- `--port 8000`: Server listens on port 8000

#### **Test Backend is Running**

Open browser and visit:
```
http://localhost:8000/docs
```

You should see interactive Swagger documentation of your API!

### **Step 2: Use Extension**

```
1. Navigate to any website
2. Click PhishGuard icon in toolbar
3. Click "Check This Page"
4. Wait for result (usually < 1 second)
5. See verdict and confidence score!
```

### **Step 3: Testing Different URLs**

```
Test URLs:

Legitimate:
- https://www.google.com
- https://www.amazon.com
- https://www.github.com

Suspicious (use with caution):
- https://www.amaz0n-verify.com
- https://p4y-p1l.account-confirm.com
- https://bank-s3cur1ty-v3rify.net
```

---

## Troubleshooting Guide

### **Issue 1: "Error: Could not reach backend"**

**Symptoms:**
- Extension shows error
- Backend is not running

**Solutions:**

```bash
# Check if backend is running
ps aux | grep uvicorn

# If not running, start it
cd phishing-extension-backend
source venv/bin/activate
uvicorn main:app --host 0.0.0.0 --port 8000

# If port 8000 already in use
lsof -i :8000  # See what's using port
kill -9 <PID>  # Kill the process
```

### **Issue 2: "Error: URL missing"**

**Symptoms:**
- Extension sends request but gets error
- Backend received request but URL field missing

**Possible Causes:**
- Extension code has bug
- Request body malformed

**Solution:**
- Check popup.js line sending request:
```javascript
body: JSON.stringify({ url })  // Correct
body: JSON.stringify({ "domain": url })  // Wrong
```

### **Issue 3: Model not loaded error**

**Symptoms:**
- Backend starts but: "Model failed to load"
- Backend returns: HTTP 500 error

**Solutions:**

```bash
# Verify model file exists
ls -la model/phishing_model.pkl

# If missing, need to train model (complex process)
# Model should be ~5-50MB depending on training data

# Check file isn't corrupted
file model/phishing_model.pkl  # Should show: data

# Verify joblib can read it
python -c "import joblib; joblib.load('model/phishing_model.pkl'); print('✓ OK')"
```

### **Issue 4: CORS Error in extension**

**Symptoms:**
- Browser console shows: "CORS policy blocked request"
- Extension doesn't send request at all

**Solution:**
Verify main.py has CORS middleware:
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
```

### **Issue 5: Extension not appearing in toolbar**

**Symptoms:**
- Loaded extension but no icon visible
- Can't access extension

**Solutions:**

```bash
# Check DevTools for errors
1. Open chrome://extensions/
2. Enable "Developer mode"
3. Look for error messages
4. Check "Errors" section

# Verify manifest.json is valid
# Try removing and reloading:
1. Click trash icon next to extension
2. Click "Load unpacked"
3. Select phishing-extension folder again
```

### **Issue 6: Slow predictions (>5 seconds)**

**Symptoms:**
- Extension works but very slow
- Backend processes slowly

**Possible Causes:**
- Large model file
- Feature extraction taking too long
- System resources low

**Solutions:**

```bash
# Monitor backend performance
time curl -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'

# If consistently slow:
# - Model may need optimization
# - Feature extraction may need tuning
# - System may need more RAM/CPU
```

---

## Technical Deep Dive

### **Advanced: Model Architecture**

The loaded model is typically a scikit-learn pipeline containing:

```python
Pipeline([
    ('prep', ColumnTransformer([
        ('text', Pipeline([
            ('tfidf', TfidfVectorizer(...)),
        ]), ['domain']),
        ('num', Pipeline([
            ('scaler', StandardScaler()),
        ]), ['ranking', 'mld_res', 'mld.ps_res', ...])
    ])),
    ('stacker', StackingClassifier([
        ('rf', RandomForestClassifier(...)),
        ('svm', SVC(...)),
        ('gb', GradientBoostingClassifier(...)),
    ], final_estimator=LogisticRegression(...)))
])
```

**Component Breakdown:**

1. **ColumnTransformer**: Applies different preprocessing to different column types
   - Text columns: TF-IDF vectorization
   - Numeric columns: StandardScaler normalization

2. **StackingClassifier**: Ensemble method combining multiple models
   - Level 0: Multiple base classifiers (RF, SVM, GB)
   - Level 1: Meta-classifier (Logistic Regression) learns how to combine predictions

### **Advanced: Feature Vectorization**

#### **TF-IDF Vectorization (for domain)**

```
URL: "https://evil-bank-login.com"

TF-IDF converts to:
[term1_score, term2_score, term3_score, ...]

Example:
'https' → 0.234
'evil'  → 0.789
'bank'  → 0.567
'login' → 0.912
'com'   → 0.345
```

TF-IDF scores reflect:
- **TF** (Term Frequency): How often term appears in URL
- **IDF** (Inverse Document Frequency): How rare term is across all training URLs
- High score = rare but important term (possibly phishing-related)

#### **StandardScaler (for numeric features)**

```
Original ranges:
- mld_res: 1 to 50
- ratio_Arem: 0 to 1
- card_rem: 0 to 50

StandardScaler transforms:
- Mean = 0, Standard deviation = 1
- Makes features comparable to ML algorithm
- Prevents high-magnitude features from dominating
```

### **Advanced: Confidence Score Rationale**

```python
# For legitimate URLs:
confidence = 1 - proba
# Reasoning: If proba=0.01, we're 99% confident it's legitimate

# For phishing URLs:
confidence = proba
# Reasoning: If proba=0.95, we're 95% confident it's phishing

# For suspicious URLs:
confidence = abs(0.5 - proba) * 2
# Reasoning: Distance from 0.5 (uncertain boundary)
# More distance = more confident in classification
# Max confidence = 1.0 (when proba = 0.0 or 1.0)
# Min confidence = 0.0 (when proba = 0.5, completely uncertain)
```

---

## Best Practices & Production Considerations

### **For Backend**

1. **Security**
   - Change `allow_origins=["*"]` to specific domain in production
   - Add rate limiting to prevent abuse
   - Add API authentication (API keys, OAuth)

2. **Performance**
   - Use async endpoints for I/O operations
   - Implement caching for common URLs
   - Load balance multiple server instances

3. **Logging & Monitoring**
   - Log all predictions for analytics
   - Monitor model performance over time
   - Alert on anomalies

### **For Extension**

1. **User Experience**
   - Add loading indicator while waiting for response
   - Show detailed information on click
   - Add history/cache of checked URLs

2. **Privacy**
   - Never send page content to server (only URL)
   - Store results locally, not on server
   - Add option to disable/enable checking

3. **Reliability**
   - Handle offline mode gracefully
   - Implement retry logic for failed requests
   - Cache model predictions locally

---

## Conclusion

The PhishGuard Pro system demonstrates a complete machine learning workflow integrated into a browser extension. From URL extraction to feature engineering to model prediction, every component works together seamlessly to provide real-time phishing detection.

**Key Takeaways:**
1. **Extension** → lightweight UI that captures user intent
2. **Backend** → processes features and runs ML model
3. **Communication** → HTTP + JSON for cross-component messaging
4. **Speed** → entire process < 500ms for user experience
5. **Accuracy** → ensemble models provide high confidence predictions

---

## Additional Resources

For questions or issues:
1. Check browser DevTools console for JavaScript errors
2. Check backend terminal output for server errors
3. Review FastAPI documentation: https://fastapi.tiangolo.com/
4. Review Chrome Extensions documentation: https://developer.chrome.com/docs/extensions/

Happy phishing detection! 🛡️
