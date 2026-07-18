import re
import urllib.parse
from urllib.parse import urlparse
import tldextract
import logging
import whois
import socket
import requests
from datetime import datetime

def extract_features(url):
    """
    Extract features from a URL for phishing detection
    Returns a list of numerical features
    """
    try:
        # Parse URL
        parsed_url = urlparse(url)
        domain_info = tldextract.extract(url)
        
        features = []
        
        # 1. URL Length
        features.append(len(url))
        
        # 2. Number of dots in URL
        features.append(url.count('.'))
        
        # 3. Number of hyphens in URL
        features.append(url.count('-'))
        
        # 4. Number of underscores in URL
        features.append(url.count('_'))
        
        # 5. Number of slashes in URL
        features.append(url.count('/'))
        
        # 6. Number of question marks
        features.append(url.count('?'))
        
        # 7. Number of equals signs
        features.append(url.count('='))
        
        # 8. Number of ampersands
        features.append(url.count('&'))
        
        # 9. Number of exclamation marks
        features.append(url.count('!'))
        
        # 10. Number of spaces (encoded as %20)
        features.append(url.count('%20'))
        
        # 11. Number of percentages
        features.append(url.count('%'))
        
        # 12. Domain length
        domain = parsed_url.netloc
        features.append(len(domain))
        
        # 13. Number of subdomains
        subdomain = domain_info.subdomain
        if subdomain:
            features.append(len(subdomain.split('.')))
        else:
            features.append(0)
        
        # 14. Has IP address instead of domain (0 or 1)
        ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        features.append(1 if ip_pattern.search(domain) else 0)
        
        # 15. Uses HTTPS (0 or 1)
        features.append(1 if parsed_url.scheme == 'https' else 0)
        
        # 16. Path length
        features.append(len(parsed_url.path))
        
        # 17. Query length
        features.append(len(parsed_url.query) if parsed_url.query else 0)
        
        # 18. Fragment length
        features.append(len(parsed_url.fragment) if parsed_url.fragment else 0)
        
        # 19. Number of digits in URL
        features.append(sum(c.isdigit() for c in url))
        
        # 20. Number of letters in URL
        features.append(sum(c.isalpha() for c in url))
        
        # 21. Contains suspicious keywords (0 or 1)
        suspicious_keywords = ['secure', 'account', 'update', 'confirm', 'verify', 'login', 'signin', 'bank', 'paypal']
        contains_suspicious = any(keyword in url.lower() for keyword in suspicious_keywords)
        features.append(1 if contains_suspicious else 0)
        
        # 22. Domain contains numbers (0 or 1)
        features.append(1 if any(c.isdigit() for c in domain) else 0)
        
        # 23. Has port number (0 or 1)
        features.append(1 if parsed_url.port else 0)
        
        # 24. URL shorteners (0 or 1)
        shorteners = ['bit.ly', 'tinyurl', 'short.ly', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly']
        is_shortened = any(shortener in domain.lower() for shortener in shorteners)
        features.append(1 if is_shortened else 0)
        
        # 25. Number of special characters
        special_chars = "!@#$%^&*()_+-=[]{}|;':\",./<>?"
        features.append(sum(c in special_chars for c in url))
        
        return features
        
    except Exception as e:
        logging.error(f"Error extracting features from URL {url}: {e}")
        # Return default features if extraction fails
        return [0] * 25
    

def get_deep_analysis(url):
    """
    Fetches human-readable OSINT data: WHOIS, IP, Location, Age.
    """
    data = {
        "domain_age_days": None,
        "registrar": "Unknown",
        "creation_date": "Unknown",
        "server_ip": "Unknown",
        "server_location": "Unknown",
        "is_suspicious_age": False
    }

    try:
        # 1. Parse Domain
        parsed = urlparse(url)
        domain = parsed.netloc.split(':')[0] # Remove port if exists
        
        # 2. Get IP Address
        try:
            ip = socket.gethostbyname(domain)
            data["server_ip"] = ip
            
            # 3. Get Geolocation (Free API)
            try:
                geo_resp = requests.get(f"http://ip-api.com/json/{ip}?fields=country,isp", timeout=3)
                if geo_resp.status_code == 200:
                    geo_json = geo_resp.json()
                    data["server_location"] = f"{geo_json.get('country', 'Unknown')} ({geo_json.get('isp', '')})"
            except:
                pass
        except:
            data["server_ip"] = "Host Unreachable"

        # 4. WHOIS Lookup (The most important part)
        try:
            w = whois.whois(domain)
            
            # Handle Registrar
            data["registrar"] = w.registrar if w.registrar else "Hidden/Private"
            
            # Handle Creation Date (It can be a list or a string)
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if creation_date:
                data["creation_date"] = creation_date.strftime('%Y-%m-%d')
                
                # Calculate Age
                age = (datetime.now() - creation_date).days
                data["domain_age_days"] = age
                
                # Flag if domain is less than 30 days old (Huge Phishing Indicator)
                if age < 30:
                    data["is_suspicious_age"] = True
                    
        except Exception as e:
            logging.error(f"WHOIS lookup failed: {e}")
            data["registrar"] = "Lookup Failed"

    except Exception as e:
        logging.error(f"Deep analysis failed: {e}")

    return data
