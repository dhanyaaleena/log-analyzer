import random
from datetime import datetime, timedelta

# Parameters
num_logs = 500
anomaly_ratio = .2  # 30% anomalous to test categories better

# Sample values
normal_user_agents = ["Mozilla/5.0", "Chrome/91.0", "Safari/13.1", "Edge/18.18363"]
suspicious_user_agents = ["curl/7.68.0", "Python-urllib/3.9", "wget/1.20", "PostmanRuntime/7.28.4"]
methods = ["GET", "POST"]
urls = ["google.com", "github.com", "amazon.com", "stackoverflow.com", "facebook.com"]
suspicious_urls = [
    "g00gle-login.xyz",      # Typosquatting Google
    "facebo0k-secure.cc",    # Typosquatting Facebook
    "amaz0n-verify.tk",      # Typosquatting Amazon
    "m1crosoft-update.ga",   # Typosquatting Microsoft
    "paypa1-secure.ml",      # Typosquatting PayPal
    "secure-login12345.top", # Random-looking with numbers
    "account-verify-xyz.cf"  # Suspicious TLD
]
rare_domains = ["obscure-site.xyz", "rare-domain.net", "unusual-site.com", "strange-domain.org"]
status_codes_normal = [200, 301, 302]
status_codes_anomalous = [403, 404, 500]
actions = ["Allowed", "Blocked"]

def generate_ip(private=False):
    if private:
        return f"192.168.1.{random.randint(1, 254)}"
    else:
        return f"{random.randint(20, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

start_time = datetime.now()
log_lines = []

# Track IPs for brute force patterns
ip_403_counts = {}

for i in range(num_logs):
    timestamp = (start_time - timedelta(seconds=i * random.randint(1, 5))).strftime("%Y-%m-%d %H:%M:%S")
    is_anomalous = random.random() < anomaly_ratio

    if is_anomalous:
        # Determine anomaly type
        anomaly_type = random.choice([
            'brute_force_403',      # Multiple 403s from same IP
            'automation_detected',   # Suspicious user agent
            'suspicious_domain',     # Malware/phishing domains
            'rare_domain',          # Rarely accessed domains
            'data_exfiltration'     # Unusual data transfer
        ])
        
        source_ip = generate_ip(private=True)
        destination_ip = generate_ip()
        
        if anomaly_type == 'brute_force_403':
            # Create multiple 403s from same IP
            if source_ip not in ip_403_counts:
                ip_403_counts[source_ip] = 0
            ip_403_counts[source_ip] += 1
            
            url = random.choice(urls)  # Normal URL but 403 response
            action = "Blocked"
            method = random.choice(methods)
            status_code = 403
            user_agent = random.choice(normal_user_agents)
            bytes_sent = random.randint(0, 100)
            bytes_received = random.randint(0, 100)
            
        elif anomaly_type == 'automation_detected':
            url = random.choice(urls)
            action = "Allowed"
            method = random.choice(methods)
            status_code = random.choice(status_codes_normal)
            user_agent = random.choice(suspicious_user_agents)  # Automation tools
            bytes_sent = random.randint(200, 1000)
            bytes_received = random.randint(500, 2000)
            
        elif anomaly_type == 'suspicious_domain':
            url = random.choice(suspicious_urls)  # Malware/phishing domains
            action = "Blocked"
            method = random.choice(methods)
            status_code = random.choice(status_codes_anomalous)
            user_agent = random.choice(normal_user_agents)
            bytes_sent = random.randint(0, 200)
            bytes_received = random.randint(0, 200)
            
        elif anomaly_type == 'rare_domain':
            url = random.choice(rare_domains)  # Rare domains
            action = "Allowed"
            method = random.choice(methods)
            status_code = random.choice(status_codes_normal)
            user_agent = random.choice(normal_user_agents)
            bytes_sent = random.randint(200, 800)
            bytes_received = random.randint(500, 1500)
            
        elif anomaly_type == 'data_exfiltration':
            url = random.choice(urls)
            action = "Allowed"
            method = random.choice(methods)
            status_code = random.choice(status_codes_normal)
            user_agent = random.choice(normal_user_agents)
            # Unusually large data transfer
            bytes_sent = random.randint(50000, 200000)
            bytes_received = random.randint(100000, 500000)
    else:
        source_ip = generate_ip(private=True)
        destination_ip = generate_ip()
        url = random.choice(urls)
        action = "Allowed"
        method = random.choice(methods)
        status_code = random.choice(status_codes_normal)
        user_agent = random.choice(normal_user_agents)
        bytes_sent = random.randint(200, 5000)
        bytes_received = random.randint(500, 10000)

    # Space-separated line, tab-separated also works
    line = f"{timestamp} {source_ip} {destination_ip} {url} {action} {method} {status_code} {user_agent} {bytes_sent} {bytes_received}"
    log_lines.append(line)

# Add some additional 403s for brute force pattern
for ip, count in ip_403_counts.items():
    if count >= 2:  # If we have multiple 403s from same IP, add a few more
        for _ in range(random.randint(1, 3)):
            timestamp = (start_time - timedelta(seconds=random.randint(1, 100))).strftime("%Y-%m-%d %H:%M:%S")
            destination_ip = generate_ip()
            url = random.choice(urls)
            action = "Blocked"
            method = random.choice(methods)
            status_code = 403
            user_agent = random.choice(normal_user_agents)
            bytes_sent = random.randint(0, 100)
            bytes_received = random.randint(0, 100)
            
            line = f"{timestamp} {ip} {destination_ip} {url} {action} {method} {status_code} {user_agent} {bytes_sent} {bytes_received}"
            log_lines.append(line)

# Write to .log file
with open("synthetic_web_logs_500.log", "w") as logfile:
    logfile.write("\n".join(log_lines))

print(f"{len(log_lines)} synthetic log entries written to synthetic_web_logs_500.log")
print(f"Generated anomalies include: brute force (403s), automation tools, suspicious domains, rare domains, and data exfiltration")
