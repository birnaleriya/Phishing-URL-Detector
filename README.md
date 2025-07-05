# 🔒 Phishing URL Detection using Machine Learning

This project provides an AI-powered solution to detect phishing websites in real-time using Machine Learning. It combines feature extraction, model training, and a modern, user-friendly web interface to help users stay safe from malicious links.

---

## 📌 Features

✅ Detects phishing and legitimate URLs using a trained ML model  
✅ Extracts technical features from URLs (length, domain structure, SSL, etc.)  
✅ Real-time predictions with confidence score  
✅ Modern web interface built with **Flask** and **Tailwind CSS**  
✅ Detailed downloadable security report  
✅ Responsive, mobile-friendly design  

---

## 🛠️ Tech Stack

- **Python 3.10+**  
- **Scikit-learn** (Random Forest Classifier)  
- **Pandas**, **tldextract**, **whois**, **BeautifulSoup** for feature extraction  
- **Flask** for web app backend  
- **Tailwind CSS** for frontend styling  
- **Lucide Icons** for modern UI elements  

---

## 🚀 How to Run the Project

1. **Clone the Repository**

```bash
git clone https://github.com/your-username/phishing-url-detector.git
cd phishing_detector
```

2. **Install Dependencies**

```bash
pip install -r requirements.txt
```

3. **Train the Model (if not already trained)**

```python
# Run your training notebook or script to generate model.pkl
```

4. **Run the Web Application**

```bash
python app.py
```

5. **Access the App**

Open your browser and visit: [http://127.0.0.1:5000](http://127.0.0.1:5000)

---

## 🧹 How it Works

- User enters a website URL into the web interface  
- The system extracts 48+ technical features from the URL  
- The trained Random Forest model classifies the URL as Safe, Suspicious, or Phishing  
- Displays confidence score and allows downloading a security report   

---
