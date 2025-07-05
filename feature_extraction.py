import re
import urllib.parse
import tldextract
import requests
from bs4 import BeautifulSoup

def extract_url_features(url):
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.netloc
    path = parsed.path
    query = parsed.query

    features = []

    # Structural Features
    features.append(url.count('.'))                               
    subdomain = tldextract.extract(url).subdomain
    features.append(subdomain.count('.') + 1 if subdomain else 0) 
    features.append(path.count('/'))                              
    features.append(len(url))                                     
    features.append(url.count('-'))                               
    features.append(hostname.count('-'))                          
    features.append(1 if '@' in url else 0)                       
    features.append(1 if '~' in url else 0)                       
    features.append(url.count('_'))                               
    features.append(url.count('%'))                               
    features.append(query.count('='))                             
    features.append(url.count('&'))                               
    features.append(url.count('#'))                               
    features.append(sum(c.isdigit() for c in url))                
    features.append(1 if 'https' not in url.lower() else 0)       
    features.append(1 if re.search(r'[a-zA-Z0-9]{8,}', hostname) else 0)  
    ip_pattern = r'^(http|https)://(\d{1,3}\.){3}\d{1,3}'
    features.append(1 if re.match(ip_pattern, url) else 0)        
    features.append(1 if subdomain and hostname.split('.')[0] in subdomain else 0)  
    features.append(1 if hostname in path else 0)                 
    features.append(1 if 'https' in hostname else 0)              
    features.append(len(hostname))                                
    features.append(len(path))                                    
    features.append(len(query))                                   
    features.append(1 if '//' in path else 0)                     
    sensitive_words = ['secure', 'account', 'update', 'login', 'confirm']
    features.append(sum(1 for word in sensitive_words if word in url.lower()))  
    features.append(1 if 'brand' in url.lower() else 0)           

    
    pct_ext_links = pct_ext_resources = ext_favicon = insecure_forms = rel_form_action = ext_form_action = 0
    abnormal_form_action = pct_null_self_redirect = frequent_domain_mismatch = fake_link_status_bar = 0
    right_click_disabled = popup_window = submit_info_email = iframe_or_frame = missing_title = images_only_form = 0
    subdomain_level_rt = url_length_rt = pct_ext_resources_rt = abnormal_ext_form_action_rt = 0
    ext_meta_script_link_rt = pct_ext_null_self_redirect_rt = 0

     
    try:
        response = requests.get(url, timeout=5)
        html = response.text
        soup = BeautifulSoup(html, 'html.parser')
        domain = hostname


        total_links = len(soup.find_all('a'))
        ext_links = sum(1 for tag in soup.find_all('a', href=True) if domain not in tag['href'])
        pct_ext_links = (ext_links / total_links) * 100 if total_links else 0

        total_resources = len(soup.find_all(['script', 'img', 'link']))
        ext_resources = sum(1 for tag in soup.find_all(['script', 'img', 'link'], src=True) if domain not in tag.get('src', ''))
        pct_ext_resources = (ext_resources / total_resources) * 100 if total_resources else 0

        
        ext_favicon = 1 if soup.find('link', rel='icon', href=True) and domain not in soup.find('link', rel='icon')['href'] else 0
        insecure_forms = sum(1 for form in soup.find_all('form', action=True) if 'https' not in form['action'])
        rel_form_action = sum(1 for form in soup.find_all('form', action=True) if form['action'].startswith('/'))
        ext_form_action = sum(1 for form in soup.find_all('form', action=True) if domain not in form['action'])
        abnormal_form_action = sum(1 for form in soup.find_all('form', action=True) if form['action'] == 'about:blank')
        pct_null_self_redirect = sum(1 for a in soup.find_all('a', href=True) if a['href'] in ['#', '']) / total_links * 100 if total_links else 0
        frequent_domain_mismatch = 1 if soup.title and domain not in soup.title.text.lower() else 0
        fake_link_status_bar = 0  
        right_click_disabled = 0  
        popup_window = 0          
        submit_info_email = 1 if 'mailto:' in html.lower() else 0
        iframe_or_frame = 1 if soup.find(['iframe', 'frame']) else 0
        missing_title = 1 if not soup.title else 0
        images_only_form = 1 if soup.find('form') and not soup.find('form').find(['input', 'textarea']) else 0

       
        subdomain_level_rt = features[1]
        url_length_rt = features[3]
        pct_ext_resources_rt = pct_ext_resources
        abnormal_ext_form_action_rt = abnormal_form_action
        ext_meta_script_link_rt = ext_resources
        pct_ext_null_self_redirect_rt = pct_null_self_redirect

    except Exception:
        pass 


    features.extend([
        pct_ext_links, pct_ext_resources, ext_favicon, insecure_forms, rel_form_action,
        ext_form_action, abnormal_form_action, pct_null_self_redirect, frequent_domain_mismatch,
        fake_link_status_bar, right_click_disabled, popup_window, submit_info_email,
        iframe_or_frame, missing_title, images_only_form, subdomain_level_rt, url_length_rt,
        pct_ext_resources_rt, abnormal_ext_form_action_rt, ext_meta_script_link_rt, pct_ext_null_self_redirect_rt
    ])

    return features
