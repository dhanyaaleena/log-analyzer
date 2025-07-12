from flask import Blueprint, request, jsonify
from extensions import db
from models import LogFile, LogEntry, AnalysisResult
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
import numpy as np
import json
from datetime import datetime
from collections import defaultdict
from services.llm_service import LLMService

analysis_bp = Blueprint('analysis', __name__)

def calculate_confidence_score(anomaly_type, severity, model_scores=None, statistical_evidence=None):
    """Calculate confidence score for anomaly detection"""
    base_scores = {
        'brute_force_403': 0.85,
        'automation_detected': 0.75,
        'suspicious_domain': 0.90,
        'rare_domain': 0.60,
        'data_exfiltration': 0.80,
        'ml_anomaly': 0.70
    }
    
    confidence = base_scores.get(anomaly_type, 0.50)
    
    # Adjust based on severity
    if severity == 'high':
        confidence += 0.10
    elif severity == 'medium':
        confidence += 0.05
    
    # Adjust based on model agreement
    if model_scores:
        if model_scores.get('iso_forest') and model_scores.get('lof'):
            confidence += 0.15  # Both models agree
        elif model_scores.get('iso_forest') or model_scores.get('lof'):
            confidence += 0.05  # One model agrees
    
    # Adjust based on statistical evidence
    if statistical_evidence:
        if statistical_evidence.get('std_deviations', 0) > 3:
            confidence += 0.10
        elif statistical_evidence.get('std_deviations', 0) > 2:
            confidence += 0.05
    
    return min(confidence, 1.0)  # Cap at 1.0

def detect_security_anomalies(entries, entry_data_list):
    """Detect specific security-related anomalies with confidence scores"""
    security_anomalies = []
    
    # Group entries by source IP for pattern analysis
    ip_entries = defaultdict(list)
    for i, entry in enumerate(entries):
        src_ip = entry_data_list[i].get('src_ip', '')
        ip_entries[src_ip].append((i, entry_data_list[i]))
    
    # 1. Detect multiple 403s from same IP (brute force/scraping)
    for src_ip, ip_logs in ip_entries.items():
        if len(ip_logs) >= 3:  # Need at least 3 entries to detect pattern
            status_403_count = sum(1 for _, data in ip_logs if data.get('status_code') == '403')
            if status_403_count >= 2:  # Multiple 403s indicate brute force
                for idx, data in ip_logs:
                    if data.get('status_code') == '403':
                        confidence = calculate_confidence_score('brute_force_403', 'high', 
                                                             statistical_evidence={'pattern_count': status_403_count})
                        security_anomalies.append({
                            'type': 'brute_force_403',
                            'severity': 'high',
                            'confidence': confidence,
                            'entry_index': idx,
                            'src_ip': src_ip,
                            'pattern': f"Multiple 403 errors from {src_ip} ({status_403_count} out of {len(ip_logs)} requests)",
                            'description': f"Potential brute force attack or scraping attempt from {src_ip}",
                            'explanation': f"IP {src_ip} generated {status_403_count} 403 errors in {len(ip_logs)} requests, indicating potential brute force or scraping activity"
                        })
    
    # 2. Detect automation tools in User-Agent
    automation_indicators = ['curl', 'wget', 'python', 'postman', 'bot', 'spider', 'crawler']
    for i, data in enumerate(entry_data_list):
        user_agent = data.get('user_agent', '').lower()
        for indicator in automation_indicators:
            if indicator in user_agent:
                confidence = calculate_confidence_score('automation_detected', 'medium')
                security_anomalies.append({
                    'type': 'automation_detected',
                    'severity': 'medium',
                    'confidence': confidence,
                    'entry_index': i,
                    'src_ip': data.get('src_ip'),
                    'user_agent': data.get('user_agent'),
                    'pattern': f"Automation tool detected: {indicator}",
                    'description': f"Automated request detected with User-Agent containing '{indicator}'",
                    'explanation': f"User-Agent contains '{indicator}', indicating automated request rather than normal browser traffic"
                })
                break  # Only flag once per entry
    
    # 3. Detect connections to suspicious/rare domains
    # More realistic suspicious domain detection
    suspicious_tlds = ['.xyz', '.top', '.cc', '.tk', '.ml', '.ga', '.cf']  # Often used for malicious sites
    suspicious_patterns = [
        # Typosquatting patterns
        ('google', ['g00gle', 'go0gle', 'gogle', 'gooogle']),
        ('facebook', ['facebo0k', 'faceb00k', 'fasebook', 'facebok']),
        ('amazon', ['amaz0n', 'amazoon', 'amazn', 'amaz0n']),
        ('microsoft', ['m1crosoft', 'micros0ft', 'm1cr0s0ft', 'microsft']),
        ('paypal', ['paypa1', 'paypall', 'paypa1', 'paypa1']),
        ('apple', ['app1e', 'app1e', 'appel', 'app1e']),
    ]
    
    # Check for suspicious TLDs and patterns
    def is_suspicious_domain(domain):
        domain_lower = domain.lower()
        
        # Check for suspicious TLDs
        for tld in suspicious_tlds:
            if domain_lower.endswith(tld):
                return True, f"Suspicious TLD: {tld}"
        
        # Check for typosquatting patterns
        for legitimate, variations in suspicious_patterns:
            if legitimate in domain_lower:
                for variation in variations:
                    if variation in domain_lower:
                        return True, f"Typosquatting: {legitimate} → {variation}"
        
        # Check for suspicious subdomain patterns
        if domain_lower.count('.') > 2:  # Too many subdomains
            return True, "Excessive subdomains"
        
        # Check for random-looking domains (lots of numbers/random chars)
        if len(domain) > 20 and sum(c.isdigit() for c in domain) > len(domain) * 0.3:
            return True, "Random-looking domain with many numbers"
        
        return False, ""

    rare_domains = set()  # Track domains that appear only once
    
    # Count domain frequency
    domain_counts = defaultdict(int)
    for data in entry_data_list:
        domain = data.get('domain', '')
        domain_counts[domain] += 1
    
    # Find rare domains (appear only once)
    for domain, count in domain_counts.items():
        if count == 1:
            rare_domains.add(domain)
    
    for i, data in enumerate(entry_data_list):
        domain = data.get('domain', '')
        
        # Check for suspicious domain patterns
        is_suspicious, reason = is_suspicious_domain(domain)
        if is_suspicious:
            confidence = calculate_confidence_score('suspicious_domain', 'high')
            security_anomalies.append({
                'type': 'suspicious_domain',
                'severity': 'high',
                'confidence': confidence,
                'entry_index': i,
                'src_ip': data.get('src_ip'),
                'domain': domain,
                'pattern': f"Suspicious domain: {domain}",
                'description': f"Domain shows suspicious characteristics: {reason}",
                'explanation': f"Domain '{domain}' shows suspicious characteristics: {reason}. This could indicate a malicious or phishing site."
            })
        
        # Check for rare domains
        if domain in rare_domains:
            confidence = calculate_confidence_score('rare_domain', 'medium')
            security_anomalies.append({
                'type': 'rare_domain',
                'severity': 'medium',
                'confidence': confidence,
                'entry_index': i,
                'src_ip': data.get('src_ip'),
                'domain': domain,
                'pattern': f"Rare domain accessed: {domain}",
                'description': f"Connection to rarely accessed domain: {domain}",
                'explanation': f"Domain '{domain}' appears only once in the log, indicating unusual access pattern"
            })
    
    # 4. Detect data exfiltration (unusual data transfer patterns)
    # Calculate baseline for data transfer
    all_bytes_sent = []
    all_bytes_received = []
    
    for data in entry_data_list:
        try:
            bytes_str = data.get('bytes', '0 0')
            sent, received = map(int, bytes_str.split())
            all_bytes_sent.append(sent)
            all_bytes_received.append(received)
        except:
            all_bytes_sent.append(0)
            all_bytes_received.append(0)
    
    if all_bytes_sent and all_bytes_received:
        avg_sent = np.mean(all_bytes_sent)
        avg_received = np.mean(all_bytes_received)
        std_sent = np.std(all_bytes_sent)
        std_received = np.std(all_bytes_received)
        
        # Threshold: 2 standard deviations above mean
        sent_threshold = avg_sent + (2 * std_sent)
        received_threshold = avg_received + (2 * std_received)
        
        for i, data in enumerate(entry_data_list):
            try:
                bytes_str = data.get('bytes', '0 0')
                sent, received = map(int, bytes_str.split())
                
                if sent > sent_threshold or received > received_threshold:
                    std_deviations = max(
                        (sent - avg_sent) / std_sent if std_sent > 0 else 0,
                        (received - avg_received) / std_received if std_received > 0 else 0
                    )
                    confidence = calculate_confidence_score('data_exfiltration', 'high', 
                                                         statistical_evidence={'std_deviations': std_deviations})
                    security_anomalies.append({
                        'type': 'data_exfiltration',
                        'severity': 'high',
                        'confidence': confidence,
                        'entry_index': i,
                        'src_ip': data.get('src_ip'),
                        'domain': data.get('domain'),
                        'bytes_sent': sent,
                        'bytes_received': received,
                        'pattern': f"Unusual data transfer: {sent} sent, {received} received",
                        'description': f"Potential data exfiltration - {sent} bytes sent, {received} bytes received (threshold: {sent_threshold:.0f} sent, {received_threshold:.0f} received)",
                        'explanation': f"Data transfer of {sent} bytes sent and {received} bytes received is {std_deviations:.1f} standard deviations above normal, indicating potential data exfiltration"
                    })
            except:
                continue
    
    return security_anomalies

def analyze_feature_importance(X, model, model_name):
    """Analyze which features contributed most to anomaly detection"""
    if model_name == 'isolation_forest':
        # Use built-in feature importances if available
        if hasattr(model, 'feature_importances_'):
            return model.feature_importances_
        else:
            return np.ones(X.shape[1]) / X.shape[1]
    elif model_name == 'lof':
        # For LOF, analyze the distance to neighbors
        distances, _ = model.kneighbors(X)
        # Use the average distance as a proxy for feature importance
        return np.mean(distances, axis=0)
    return np.ones(X.shape[1]) / X.shape[1]

def generate_reasoning(entry_data, iso_score, lof_score, feature_importance, model_name, security_anomalies=None, averages=None, stds=None):
    reasons = []
    # Analyze status codes
    status_code = int(entry_data.get('status_code', 0))
    if status_code >= 400:
        reasons.append(f"Unusual status code: {status_code} (>=400)")
    elif status_code == 0:
        reasons.append("Invalid or missing status code")
    elif status_code not in [200, 301, 302]:
        reasons.append(f"Rare status code: {status_code}")
    # Analyze bytes transferred
    try:
        bytes_str = entry_data.get('bytes', '0 0')
        bytes_sent, bytes_received = map(int, bytes_str.split())
        avg_sent = averages['bytes_sent'] if averages and 'bytes_sent' in averages else None
        avg_received = averages['bytes_received'] if averages and 'bytes_received' in averages else None
        std_sent = stds['bytes_sent'] if stds and 'bytes_sent' in stds else None
        std_received = stds['bytes_received'] if stds and 'bytes_received' in stds else None
        if avg_sent is not None and std_sent is not None:
            if bytes_sent > avg_sent + 2 * std_sent:
                reasons.append(f"Bytes sent ({bytes_sent}) is much higher than normal (mean={avg_sent:.0f}, std={std_sent:.0f})")
            elif bytes_sent < avg_sent - 2 * std_sent:
                reasons.append(f"Bytes sent ({bytes_sent}) is much lower than normal (mean={avg_sent:.0f}, std={std_sent:.0f})")
        if avg_received is not None and std_received is not None:
            if bytes_received > avg_received + 2 * std_received:
                reasons.append(f"Bytes received ({bytes_received}) is much higher than normal (mean={avg_received:.0f}, std={std_received:.0f})")
            elif bytes_received < avg_received - 2 * std_received:
                reasons.append(f"Bytes received ({bytes_received}) is much lower than normal (mean={avg_received:.0f}, std={std_received:.0f})")
        if bytes_sent > 10000 or bytes_received > 10000:
            reasons.append(f"Unusually large data transfer ({bytes_sent} sent, {bytes_received} received)")
        elif bytes_sent == 0 and bytes_received == 0:
            reasons.append("No data transfer detected")
    except:
        reasons.append("Invalid bytes format")
    # Analyze domain patterns
    domain = entry_data.get('domain', '')
    if 'malware' in domain.lower() or 'suspicious' in domain.lower():
        reasons.append(f"Suspicious domain name: {domain}")
    # Analyze action
    action = entry_data.get('action', '')
    if action == 'Blocked':
        reasons.append("Request was blocked by security system")
    # Analyze user agent
    user_agent = entry_data.get('user_agent', '')
    COMMON_USER_AGENTS = [
        "Mozilla/5.0", "Chrome/91.0", "Safari/13.1", "Edge/18.18363",
        "Mozilla/4.0", "Opera/9.80", "MSIE 10.0", "Trident/7.0"
    ]
    if user_agent and all(agent not in user_agent for agent in COMMON_USER_AGENTS):
        reasons.append(f"Rare user agent: {user_agent}")
    if 'curl' in user_agent.lower() or 'wget' in user_agent.lower():
        reasons.append("Automated tool detected in user agent")
    elif 'python' in user_agent.lower():
        reasons.append("Python script detected in user agent")
    # Add security anomaly reasons
    if security_anomalies:
        for anomaly in security_anomalies:
            if anomaly['type'] == 'brute_force_403':
                reasons.append(f"Brute force pattern: {anomaly['pattern']}")
            elif anomaly['type'] == 'automation_detected':
                reasons.append(f"Automation detected: {anomaly['pattern']}")
            elif anomaly['type'] == 'suspicious_domain':
                reasons.append(f"Suspicious domain: {anomaly['pattern']}")
            elif anomaly['type'] == 'data_exfiltration':
                reasons.append(f"Data exfiltration: {anomaly['pattern']}")
    # Model-specific reasoning
    if model_name == 'isolation_forest' and iso_score == -1:
        reasons.append("Isolation Forest detected this entry as an outlier compared to normal traffic patterns.")
    if model_name == 'lof' and lof_score == -1:
        reasons.append("Local Outlier Factor detected this entry as an outlier compared to its neighbors.")
    return reasons

def getAnomalyExplanation(anomaly):
    """Extract explanation from anomaly object using fallback logic"""
    # First, try to get explanation from top level
    explanation = anomaly.get('explanation', '')
    
    # If not found, try to get from security anomalies
    if not explanation and anomaly.get('security_anomalies'):
        security_anomaly = anomaly['security_anomalies'][0]
        explanation = security_anomaly.get('explanation', '')
    
    # If still not found, try to get from ML reasoning
    if not explanation and anomaly.get('reasoning'):
        iso_reasons = anomaly.get('reasoning', {}).get('isolation_forest', {}).get('reasons', [])
        lof_reasons = anomaly.get('reasoning', {}).get('lof', {}).get('reasons', [])
        if iso_reasons:
            explanation = iso_reasons[0]
        elif lof_reasons:
            explanation = lof_reasons[0]
    
    # Final fallback
    return explanation or "No explanation available"

def to_native(obj):
    if isinstance(obj, np.generic):
        return obj.item()
    raise TypeError(f"Object of type {obj.__class__.__name__} is not JSON serializable")

def get_threat_category(anomaly_type):
    mapping = {
        'brute_force_403': 'Brute Force',
        'automation_detected': 'Automation/Bot',
        'suspicious_domain': 'Malware/Phishing',
        'rare_domain': 'Unusual Activity',
        'data_exfiltration': 'Data Exfiltration',
        'isolation_forest': 'Anomalous Behavior',
        'lof': 'Anomalous Behavior',
        'ml': 'Anomalous Behavior',
        'ml_anomaly': 'Anomalous Behavior'
    }
    return mapping.get(anomaly_type, 'Other')

def map_reason_to_category(reasons):
    for r in reasons:
        if "Bytes sent" in r or "Bytes received" in r or "large data transfer" in r:
            return "Unusual Data Volume"
        if "Unusual status code" in r or "Rare status code" in r:
            return "Unusual Status Code"
        if "Rare user agent" in r:
            return "Rare User Agent"
        if "Automated tool detected" in r or "Python script detected" in r:
            return "Automation/Bot"
        if "Suspicious domain" in r:
            return "Malware/Phishing"
        if "Request was blocked" in r:
            return "Blocked Request"
    return "Unusual Pattern"

@analysis_bp.route('/', methods=['GET'])
def analysis_index():
    return {'msg': 'Analysis endpoint placeholder'}

@analysis_bp.route('/run', methods=['POST'])
def run_analysis():
    data = request.get_json()
    file_id = data.get('file_id')
    use_llm = data.get('use_llm', True)  # Optional flag to enable LLM explanations
    
    if not file_id:
        return jsonify({'msg': 'file_id is required'}), 400
    logfile = LogFile.query.get(file_id)
    if not logfile:
        return jsonify({'msg': 'LogFile not found'}), 404
    entries = LogEntry.query.filter_by(logfile_id=file_id).all()
    if not entries:
        return jsonify({'msg': 'No log entries found for this file'}), 404
    
    # Initialize LLM service if requested
    llm_service = LLMService() if use_llm else None
    
    # Extract features for anomaly detection
    features = []
    entry_data_list = []
    for entry in entries:
        pdata = entry.parsed_data or {}
        try:
            # Extract more features for better analysis
            status_code = int(pdata.get('status_code', 0))
            bytes_str = pdata.get('bytes', '0 0')
            bytes_sent, bytes_received = map(int, bytes_str.split())
            
            features.append([
                status_code,
                bytes_sent,
                bytes_received,
                len(pdata.get('domain', '')),
                len(pdata.get('user_agent', '')),
                1 if pdata.get('action') == 'Blocked' else 0,
                1 if pdata.get('method') == 'POST' else 0,
            ])
            entry_data_list.append(pdata)
        except Exception as e:
            print(f"Error processing entry {entry.id}: {e}")
            features.append([0, 0, 0, 0, 0, 0, 0])
            entry_data_list.append(pdata)
    
    X = np.array(features)
    
    # Standardize features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # Run Isolation Forest
    iso = IsolationForest(contamination=0.1, random_state=42)
    iso_scores = iso.fit_predict(X_scaled)
    
    # Run Local Outlier Factor
    lof = LocalOutlierFactor(n_neighbors=20, contamination=0.1)
    lof_scores = lof.fit_predict(X_scaled)
    
    # Analyze feature importance
    iso_importance = analyze_feature_importance(X_scaled, iso, 'isolation_forest')
    lof_importance = analyze_feature_importance(X_scaled, lof, 'lof')
    
    # Detect security-specific anomalies
    security_anomalies = detect_security_anomalies(entries, entry_data_list)
    
    # Calculate averages for bytes sent/received
    all_bytes_sent = [int((d.get('bytes', '0 0').split()[0])) for d in entry_data_list if 'bytes' in d]
    all_bytes_received = [int((d.get('bytes', '0 0').split()[1])) for d in entry_data_list if 'bytes' in d]
    averages = {
        'bytes_sent': np.mean(all_bytes_sent) if all_bytes_sent else 0,
        'bytes_received': np.mean(all_bytes_received) if all_bytes_received else 0
    }

    # Calculate standard deviations for bytes sent/received
    std_sent = np.std(all_bytes_sent) if all_bytes_sent else 0
    std_received = np.std(all_bytes_received) if all_bytes_received else 0
    stds = {
        'bytes_sent': std_sent,
        'bytes_received': std_received
    }

    # Collect anomalies with reasoning and confidence scores
    anomalies = []
    for i, entry in enumerate(entries):
        is_anomaly = iso_scores[i] == -1 or lof_scores[i] == -1
        # Check if this entry has security anomalies
        entry_security_anomalies = [a for a in security_anomalies if a['entry_index'] == i]
        if is_anomaly or entry_security_anomalies:
            # Calculate ML model confidence
            ml_confidence = 0.0
            if iso_scores[i] == -1 and lof_scores[i] == -1:
                ml_confidence = 0.85  # Both models agree
            elif iso_scores[i] == -1 or lof_scores[i] == -1:
                ml_confidence = 0.70  # One model flags
            # Generate reasoning for each model
            iso_reasons = generate_reasoning(entry_data_list[i], iso_scores[i], lof_scores[i], iso_importance, 'isolation_forest', entry_security_anomalies, averages, stds) if iso_scores[i] == -1 else []
            lof_reasons = generate_reasoning(entry_data_list[i], iso_scores[i], lof_scores[i], lof_importance, 'lof', entry_security_anomalies, averages, stds) if lof_scores[i] == -1 else []
            model_reasons = {
                'isolation_forest': {
                    'flagged': iso_scores[i] == -1,
                    'reasons': iso_reasons,
                    'feature_importance': iso_importance.tolist()
                },
                'lof': {
                    'flagged': lof_scores[i] == -1,
                    'reasons': lof_reasons,
                    'feature_importance': lof_importance.tolist()
                }
            }
            # Calculate overall confidence score
            max_security_confidence = max([a['confidence'] for a in entry_security_anomalies]) if entry_security_anomalies else 0.0
            overall_confidence = max(ml_confidence, max_security_confidence)
            # Determine severity
            if entry_security_anomalies:
                # Use the highest severity from rule-based anomalies
                severity = max([a['severity'] for a in entry_security_anomalies], key=lambda s: {'high':3,'medium':2,'low':1}.get(s,0))
            else:
                # ML-only anomaly: set severity based on confidence or model agreement
                if iso_scores[i] == -1 and lof_scores[i] == -1:
                    severity = 'high'
                elif overall_confidence > 0.8:
                    severity = 'high'
                elif overall_confidence > 0.6:
                    severity = 'medium'
                else:
                    severity = 'low'
            # Determine the main type for this anomaly and assign a meaningful category
            if entry_security_anomalies:
                main_type = entry_security_anomalies[0]['type']
                threat_category = get_threat_category(main_type)
            elif iso_scores[i] == -1 or lof_scores[i] == -1:
                # ML-only anomaly: assign category based on reasoning
                ml_reasons = iso_reasons if iso_scores[i] == -1 else lof_reasons
                threat_category = map_reason_to_category(ml_reasons)
                main_type = 'ml'
            else:
                main_type = 'other'
                threat_category = 'Unusual Pattern'
            anomaly_data = {
                'id': entry.id,
                'timestamp': entry_data_list[i].get('timestamp'),
                'src_ip': entry_data_list[i].get('src_ip'),
                'dest_ip': entry_data_list[i].get('dest_ip'),
                'domain': entry_data_list[i].get('domain'),
                'action': entry_data_list[i].get('action'),
                'method': entry_data_list[i].get('method'),
                'status_code': entry_data_list[i].get('status_code'),
                'bytes': entry_data_list[i].get('bytes'),
                'user_agent': entry_data_list[i].get('user_agent'),
                'iso_forest': int(iso_scores[i] == -1),
                'lof': int(lof_scores[i] == -1),
                'confidence_score': overall_confidence,
                'reasoning': model_reasons,
                'security_anomalies': entry_security_anomalies,
                'severity': severity,
                'threat_category': threat_category,
                'anomaly_summary': {
                    'ml_detected': is_anomaly,
                    'security_detected': len(entry_security_anomalies) > 0,
                    'highest_severity': severity,
                    'detection_methods': ['ml'] if is_anomaly else [] + [a['type'] for a in entry_security_anomalies]
                }
            }
            anomalies.append(anomaly_data)
    
    # Generate summary report with LLM (only once, not per anomaly)
    summary_report = None
    if llm_service and anomalies:
        summary_context = {
            'num_entries': len(entries),
            'num_anomalies': len(anomalies),
            'top_anomalies': anomalies[:5],
            'security_anomalies': security_anomalies,
            'model_performance': {
                'isolation_forest_anomalies': sum(1 for a in anomalies if a['iso_forest']),
                'lof_anomalies': sum(1 for a in anomalies if a['lof']),
                'both_models_flagged': sum(1 for a in anomalies if a['iso_forest'] and a['lof'])
            },
            'anomaly_details': []
        }
        
        # Add detailed anomaly explanations
        for anomaly in anomalies[:10]:  # Top 10 anomalies with details
            anomaly_detail = {
                'type': anomaly.get('threat_category', 'Unknown'),
                'severity': anomaly.get('severity', 'Unknown'),
                'confidence': anomaly.get('confidence_score', 0),
                'src_ip': anomaly.get('src_ip', 'Unknown'),
                'domain': anomaly.get('domain', 'Unknown'),
                'timestamp': anomaly.get('timestamp', 'Unknown'),
                'explanation': getAnomalyExplanation(anomaly),
                'detection_methods': anomaly.get('anomaly_summary', {}).get('detection_methods', [])
            }
            summary_context['anomaly_details'].append(anomaly_detail)
        
        # Add security anomaly details
        security_details = []
        for sec_anomaly in security_anomalies:
            security_detail = {
                'type': sec_anomaly.get('type', 'Unknown'),
                'severity': sec_anomaly.get('severity', 'Unknown'),
                'confidence': sec_anomaly.get('confidence', 0),
                'pattern': sec_anomaly.get('pattern', 'Unknown'),
                'explanation': sec_anomaly.get('explanation', 'Unknown'),
                'src_ip': sec_anomaly.get('src_ip', 'Unknown'),
                'domain': sec_anomaly.get('domain', 'Unknown')
            }
            security_details.append(security_detail)
        summary_context['security_details'] = security_details
        
        summary_report = llm_service.generate_summary_report(summary_context)
    
    # Store analysis result in DB
    results_dict = {
        'file_id': file_id,
        'num_entries': len(entries),
        'num_anomalies': len(anomalies),
        'anomalies': anomalies,
        'security_anomalies': security_anomalies,
        'model_performance': {
            'isolation_forest_anomalies': sum(1 for a in anomalies if a['iso_forest']),
            'lof_anomalies': sum(1 for a in anomalies if a['lof']),
            'both_models_flagged': sum(1 for a in anomalies if a['iso_forest'] and a['lof'])
        },
        'summary_report': summary_report,
        'llm_enabled': use_llm
    }
    result = AnalysisResult(
        file_id=file_id,
        created_at=datetime.utcnow(),
        results=json.loads(json.dumps(results_dict, default=to_native))
    )
    db.session.add(result)
    db.session.commit()
    return jsonify(result.results)

@analysis_bp.route('/result/<int:file_id>', methods=['GET'])
def get_analysis_result(file_id):
    result = AnalysisResult.query.filter_by(file_id=file_id).order_by(AnalysisResult.created_at.desc()).first()
    if not result:
        return jsonify({'msg': 'No analysis result found for this file'}), 404
    return jsonify(result.results)

@analysis_bp.route('/dashboard/<int:file_id>', methods=['GET'])
def dashboard_metrics(file_id):
    result = AnalysisResult.query.filter_by(file_id=file_id).order_by(AnalysisResult.created_at.desc()).first()
    if not result:
        return jsonify({'msg': 'No analysis result found for this file'}), 404
    # Fetch log entries for this file
    entries = LogEntry.query.filter_by(logfile_id=file_id).all()
    if not entries:
        return jsonify({'msg': 'No log entries found for this file'}), 404
    data = result.results
    anomalies = data.get('anomalies', [])
    # Total logs
    total_logs = data.get('num_entries', 0)
    # Total anomalies
    total_anomalies = data.get('num_anomalies', len(anomalies))
    # Anomalies by type
    anomalies_by_type = {}
    for a in anomalies:
        t = a.get('anomaly_summary', {}).get('detection_methods', ['unknown'])
        for typ in t:
            anomalies_by_type[typ] = anomalies_by_type.get(typ, 0) + 1
    # Anomalies by severity
    anomalies_by_severity = {}
    for a in anomalies:
        sev = a.get('highest_severity') or a.get('severity') or 'unknown'
        anomalies_by_severity[sev] = anomalies_by_severity.get(sev, 0) + 1
    # Top source IPs
    ip_counts = {}
    for a in anomalies:
        ip = a.get('src_ip', 'unknown')
        ip_counts[ip] = ip_counts.get(ip, 0) + 1
    top_source_ips = sorted([
        {'ip': ip, 'count': count} for ip, count in ip_counts.items() if ip != 'unknown'
    ], key=lambda x: x['count'], reverse=True)[:5]
    # Top domains
    domain_counts = {}
    for a in anomalies:
        domain = a.get('domain', 'unknown')
        domain_counts[domain] = domain_counts.get(domain, 0) + 1
    top_domains = sorted([
        {'domain': d, 'count': c} for d, c in domain_counts.items() if d != 'unknown'
    ], key=lambda x: x['count'], reverse=True)[:5]
    # Anomalies over time (by date)
    from collections import Counter
    from datetime import datetime
    date_counts = Counter()
    for a in anomalies:
        ts = a.get('timestamp')
        if ts:
            try:
                date = str(ts).split(' ')[0]
                date_counts[date] += 1
            except:
                continue
    anomalies_over_time = [
        {'date': date, 'count': count} for date, count in sorted(date_counts.items())
    ]
    # Recent anomalies (last 10)
    recent_anomalies = []
    for a in sorted(anomalies, key=lambda x: x.get('timestamp', ''), reverse=True)[:10]:
        # Get explanation from security anomalies if available
        explanation = a.get('explanation', '')
        if not explanation and a.get('security_anomalies'):
            # Get explanation from the first security anomaly
            security_anomaly = a['security_anomalies'][0]
            explanation = security_anomaly.get('explanation', '')
        
        # Fallback to ML reasoning if no security explanation
        if not explanation:
            ml_reasons = a.get('reasoning', {}).get('isolation_forest', {}).get('reasons', [])
            if ml_reasons:
                explanation = ml_reasons[0]
            else:
                explanation = "No explanation available"
        
        recent_anomalies.append({
            'timestamp': a.get('timestamp'),
            'type': ','.join(a.get('anomaly_summary', {}).get('detection_methods', [])),
            'severity': a.get('highest_severity') or a.get('severity'),
            'src_ip': a.get('src_ip'),
            'domain': a.get('domain'),
            'explanation': explanation,
            'threat_category': a.get('threat_category', 'Other'),
        })
    # Timeline data with bytes sent for all log entries
    timeline_data = []
    for entry in entries:
        entry_data = entry.parsed_data or {}
        timestamp = entry_data.get('timestamp', '')
        try:
            bytes_str = entry_data.get('bytes', '0 0')
            bytes_sent, _ = map(int, bytes_str.split())
            # Find anomaly for this entry (if any)
            anomaly = next((a for a in anomalies if a.get('id') == entry.id), None)
            anomaly_type = None
            threat_category = None
            if anomaly:
                # Use the main_type logic from run_analysis
                if anomaly.get('security_anomalies') and len(anomaly['security_anomalies']) > 0:
                    anomaly_type = anomaly['security_anomalies'][0]['type']
                    threat_category = anomaly.get('threat_category', 'Unusual Pattern')
                elif anomaly.get('iso_forest') and anomaly.get('lof'):
                    anomaly_type = 'ml'
                    threat_category = anomaly.get('threat_category', 'Unusual Pattern')
                elif anomaly.get('iso_forest'):
                    anomaly_type = 'isolation_forest'
                    threat_category = anomaly.get('threat_category', 'Unusual Pattern')
                elif anomaly.get('lof'):
                    anomaly_type = 'lof'
                    threat_category = anomaly.get('threat_category', 'Unusual Pattern')
                else:
                    anomaly_type = 'other'
                    threat_category = anomaly.get('threat_category', 'Unusual Pattern')
            timeline_data.append({
                'id': entry.id,  # Add unique ID for mapping
                'timestamp': timestamp,
                'bytes_sent': bytes_sent,
                'src_ip': entry_data.get('src_ip', ''),
                'domain': entry_data.get('domain', ''),
                'status_code': entry_data.get('status_code', ''),
                'is_anomaly': anomaly is not None,
                'anomaly_type': anomaly_type,
                'threat_category': threat_category
            })
        except:
            timeline_data.append({
                'id': entry.id,  # Add unique ID for mapping
                'timestamp': timestamp,
                'bytes_sent': 0,
                'src_ip': entry_data.get('src_ip', ''),
                'domain': entry_data.get('domain', ''),
                'status_code': entry_data.get('status_code', ''),
                'is_anomaly': any(a.get('id') == entry.id for a in anomalies),
                'anomaly_type': None,
                'threat_category': None
            })
    # Sort timeline data by timestamp
    timeline_data.sort(key=lambda x: x['timestamp'])
    # Blocked vs. Allowed Actions (all log entries)
    blocked_vs_allowed = {'Blocked': 0, 'Allowed': 0, 'Other': 0}
    for entry in entries:
        action = (entry.parsed_data or {}).get('action', '').capitalize()
        if action == 'Blocked':
            blocked_vs_allowed['Blocked'] += 1
        elif action == 'Allowed':
            blocked_vs_allowed['Allowed'] += 1
        else:
            blocked_vs_allowed['Other'] += 1

    # Top Methods Used in Anomalies
    top_methods_in_anomalies = {}
    for a in anomalies:
        method = (a.get('method') or '').upper()
        if method:
            top_methods_in_anomalies[method] = top_methods_in_anomalies.get(method, 0) + 1

    # Top Status Codes in Anomalies
    top_status_codes_in_anomalies = {}
    for a in anomalies:
        status = str(a.get('status_code', ''))
        if status:
            top_status_codes_in_anomalies[status] = top_status_codes_in_anomalies.get(status, 0) + 1

    # summary_report may be a string (old) or dict (new)
    summary_report = data.get('summary_report', 'No summary report available')
    import json
    if isinstance(summary_report, str):
        try:
            # Try to parse as JSON
            summary_report_json = json.loads(summary_report)
            if 'summary' in summary_report_json and 'mitigations' in summary_report_json:
                summary_report = summary_report_json
            else:
                summary_report = {"summary": summary_report, "mitigations": []}
        except Exception:
            summary_report = {"summary": summary_report, "mitigations": []}
    dashboard_data = {
        'total_logs': total_logs,
        'total_anomalies': total_anomalies,
        'anomalies_by_type': anomalies_by_type,
        'anomalies_by_severity': anomalies_by_severity,
        'top_source_ips': top_source_ips,
        'top_domains': top_domains,
        'anomalies_over_time': anomalies_over_time,
        'recent_anomalies': recent_anomalies,
        'timeline_data': timeline_data,
        'blocked_vs_allowed': blocked_vs_allowed,
        'top_methods_in_anomalies': top_methods_in_anomalies,
        'top_status_codes_in_anomalies': top_status_codes_in_anomalies,
        'anomalies': anomalies,  # <-- Add this line
        'summary_report': summary_report
    }
    return jsonify(dashboard_data)

@analysis_bp.route('/test-reasoning', methods=['POST'])
def test_reasoning():
    """Test endpoint to demonstrate reasoning for a single log entry"""
    data = request.get_json()
    log_entry = data.get('log_entry', {})
    use_llm = data.get('use_llm', False)
    
    if not log_entry:
        return jsonify({'msg': 'log_entry is required'}), 400
    
    # Initialize LLM service if requested
    llm_service = LLMService() if use_llm else None
    
    # Generate basic reasoning
    iso_reasons = generate_reasoning(log_entry, 1, 1, [0.5, 0.3, 0.2, 0.1, 0.1, 0.1, 0.1], 'isolation_forest')
    lof_reasons = generate_reasoning(log_entry, 1, 1, [0.4, 0.4, 0.2, 0.1, 0.1, 0.1, 0.1], 'lof')
    
    model_reasons = {
        'isolation_forest': {
            'flagged': True,
            'reasons': iso_reasons,
            'feature_importance': [0.5, 0.3, 0.2, 0.1, 0.1, 0.1, 0.1]
        },
        'lof': {
            'flagged': True,
            'reasons': lof_reasons,
            'feature_importance': [0.4, 0.4, 0.2, 0.1, 0.1, 0.1, 0.1]
        }
    }
    
    # Generate LLM explanation if requested
    llm_explanation = None
    if llm_service:
        llm_explanation = llm_service.generate_anomaly_explanation(log_entry, model_reasons)
    
    return jsonify({
        'log_entry': log_entry,
        'reasoning': model_reasons,
        'llm_explanation': llm_explanation,
        'llm_enabled': use_llm
    })
