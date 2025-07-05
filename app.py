from flask import Flask, render_template, request
import pickle
import pandas as pd
from feature_extraction import extract_url_features
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import whois
from datetime import datetime

app = Flask(__name__)

with open('model.pkl', 'rb') as f:
    model = pickle.load(f)

feature_names = [
    'NumDots', 'SubdomainLevel', 'PathLevel', 'UrlLength', 'NumDash', 'NumDashInHostname',
    'AtSymbol', 'TildeSymbol', 'NumUnderscore', 'NumPercent', 'NumQueryComponents',
    'NumAmpersand', 'NumHash', 'NumNumericChars', 'NoHttps', 'RandomString', 'IpAddress',
    'DomainInSubdomains', 'DomainInPaths', 'HttpsInHostname', 'HostnameLength', 'PathLength',
    'QueryLength', 'DoubleSlashInPath', 'NumSensitiveWords', 'EmbeddedBrandName',
    'PctExtHyperlinks', 'PctExtResourceUrls', 'ExtFavicon', 'InsecureForms', 'RelativeFormAction',
    'ExtFormAction', 'AbnormalFormAction', 'PctNullSelfRedirectHyperlinks',
    'FrequentDomainNameMismatch', 'FakeLinkInStatusBar', 'RightClickDisabled', 'PopUpWindow',
    'SubmitInfoToEmail', 'IframeOrFrame', 'MissingTitle', 'ImagesOnlyInForm', 'SubdomainLevelRT',
    'UrlLengthRT', 'PctExtResourceUrlsRT', 'AbnormalExtFormActionR', 'ExtMetaScriptLinkRT',
    'PctExtNullSelfRedirectHyperlinksRT'
]

def capture_screenshot(url, save_path='static/screenshot.png'):
    options = Options()
    options.headless = True
    driver = webdriver.Chrome(options=options)
    driver.set_window_size(1200, 800)
    driver.get(url)
    driver.save_screenshot(save_path)
    driver.quit()

def get_domain_age(url):
    try:
        domain_info = whois.whois(url)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        age_days = (datetime.now() - creation_date).days if creation_date else 0
        return age_days
    except:
        return 0

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    screenshot_path = None
    confidence = None
    url = ""

    if request.method == 'POST':
        url = request.form['url']
        try:
            features = extract_url_features(url)
            domain_age = get_domain_age(url)
            features.append(domain_age)  # Add domain age as new feature

            if len(features) != len(feature_names) + 1:
                result = "Feature extraction mismatch."
            else:
                features_df = pd.DataFrame([features], columns=feature_names + ['DomainAge'])
                prediction = model.predict(features_df)[0]
                proba = model.predict_proba(features_df)[0][1]

                result = "Phishing Website" if prediction == 1 else "Legitimate Website"
                confidence = f"{proba*100:.2f}%" if prediction == 1 else f"{(1-proba)*100:.2f}%"
                
                capture_screenshot(url)
                screenshot_path = 'static/screenshot.png'

        except Exception as e:
            result = f"Error: {e}"

    return render_template('index.html', result=result, url=url, screenshot=screenshot_path, confidence=confidence)

if __name__ == '__main__':
    app.run(debug=True)