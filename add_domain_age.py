import pandas as pd
import whois
import tldextract
from datetime import datetime
import time

# Load your existing dataset
data = pd.read_csv('Phishing_Legitimate_full.csv')

# Function to get domain age in days
def get_domain_age(url):
    try:
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}"
        w = whois.whois(domain)
        
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            age_days = (datetime.now() - creation_date).days
            return age_days if age_days >= 0 else 0
        else:
            return 0
    except:
        return 0  # Whois fails for some domains

# Progress tracking
total = len(data)
ages = []

print(f"Processing {total} URLs for domain age feature...")

for i, row in data.iterrows():
    url = row['URL']
    age = get_domain_age(url)
    ages.append(age)

    if i % 100 == 0:
        print(f"Processed {i}/{total} URLs")
    
    time.sleep(0.5)  # Prevent overloading WHOIS servers

# Add new column
data['DomainAge'] = ages

# Save updated dataset
data.to_csv('Phishing_Legitimate_with_age.csv', index=False)

print("Domain age feature added and dataset saved as 'Phishing_Legitimate_with_age.csv'")
