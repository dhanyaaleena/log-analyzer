import os
import requests
from typing import Dict, Optional
import google.generativeai as genai
import json

class LLMService:
    def __init__(self):
        self.api_key = os.getenv('GOOGLE_API_KEY')
        if self.api_key:
            genai.configure(api_key=self.api_key)
            self.model = genai.GenerativeModel('gemini-2.0-flash')
    
    def generate_anomaly_explanation(self, log_entry: Dict, model_reasons: Dict) -> Optional[str]:
        """Generate detailed explanation using Google Gemini if API key is available"""
        if not self.api_key:
            return None
        
        try:
            # Prepare context for Gemini
            context = f"""
            You are a security analyst. Don't be conversational. You are just generating formal reports.
            Log Entry Details:
            - Timestamp: {log_entry.get('timestamp')}
            - Source IP: {log_entry.get('src_ip')}
            - Destination IP: {log_entry.get('dest_ip')}
            - Domain: {log_entry.get('domain')}
            - Action: {log_entry.get('action')}
            - Method: {log_entry.get('method')}
            - Status Code: {log_entry.get('status_code')}
            - Bytes: {log_entry.get('bytes')}
            - User Agent: {log_entry.get('user_agent')}

            Model Analysis:
            - Isolation Forest Flagged: {model_reasons['isolation_forest']['flagged']}
            - LOF Flagged: {model_reasons['lof']['flagged']}
            - Isolation Forest Reasons: {', '.join(model_reasons['isolation_forest']['reasons'])}
            - LOF Reasons: {', '.join(model_reasons['lof']['reasons'])}

            In 2-3 sentences, briefly explain why this log entry was flagged as anomalous, including:
            1. What specific patterns or behaviors triggered the anomaly detection
            2. Potential security implications
            3. Recommended actions for investigation
            4. Confidence level in the detection
            """
            
            response = self.model.generate_content(context)
            return response.text.strip()
            
        except Exception as e:
            print(f"LLM service error: {e}")
            return None
    
    def generate_summary_report(self, analysis_results: Dict) -> Optional[dict]:
        """Generate a summary report of the analysis using Google Gemini, returning a sanitized JSON object"""
        if not self.api_key:
            return None
        try:
            # Build detailed anomaly information
            anomaly_summary = ""
            if analysis_results.get('anomaly_details'):
                anomaly_summary = "\n\nDETAILED ANOMALY ANALYSIS:\n"
                for i, anomaly in enumerate(analysis_results['anomaly_details'], 1):
                    anomaly_summary += f"\n{i}. {anomaly['type']} (Severity: {anomaly['severity']}, Confidence: {anomaly['confidence']:.1%})\n"
                    anomaly_summary += f"   Source IP: {anomaly['src_ip']}\n"
                    anomaly_summary += f"   Domain: {anomaly['domain']}\n"
                    anomaly_summary += f"   Explanation: {anomaly['explanation']}\n"
                    anomaly_summary += f"   Detection Methods: {', '.join(anomaly['detection_methods'])}\n"
            security_summary = ""
            if analysis_results.get('security_details'):
                security_summary = "\n\nSECURITY ANOMALY DETAILS:\n"
                for i, sec_anomaly in enumerate(analysis_results['security_details'], 1):
                    security_summary += f"\n{i}. {sec_anomaly['type']} (Severity: {sec_anomaly['severity']}, Confidence: {sec_anomaly['confidence']:.1%})\n"
                    security_summary += f"   Pattern: {sec_anomaly['pattern']}\n"
                    security_summary += f"   Source IP: {sec_anomaly['src_ip']}\n"
                    security_summary += f"   Domain: {sec_anomaly['domain']}\n"
                    security_summary += f"   Explanation: {sec_anomaly['explanation']}\n"
            context = f'''
You are a SOC Analyst.
ANALYSIS SUMMARY START:
- Total Log Entries: {analysis_results.get('num_entries', 0)}
- Total Anomalies Detected: {analysis_results.get('num_anomalies', 0)}
- Isolation Forest Anomalies: {analysis_results.get('model_performance', {}).get('isolation_forest_anomalies', 0)}
- LOF Anomalies: {analysis_results.get('model_performance', {}).get('lof_anomalies', 0)}
- Both Models Flagged: {analysis_results.get('model_performance', {}).get('both_models_flagged', 0)}
{anomaly_summary}
{security_summary}
ANALYSIS SUMMARY END

INSTRUCTIONS:
Respond ONLY in valid JSON format, no markdown, no explanation, no extra text.
The JSON must have:
  - "summary": a short string summarizing the overall security posture
  - "mitigations": an array of objects, each with:
      - "title": short title for the risk/mitigation
      - "summary": 1-line summary of the risk
      - "actions": array of 1-2 recommended actions
      - "examples": array of 1-2 short example scenarios or log lines
Example:
{{
  "summary": "Overall risk is moderate. Multiple brute force attempts detected.",
  "mitigations": [
    {{
      "title": "Brute Force Attempts",
      "summary": "Multiple 403 errors from same IP detected.",
      "actions": ["Block offending IPs", "Enable rate limiting"],
      "examples": ["192.168.1.10 generated 5x 403 errors", "Suspicious login attempts"]
    }}
  ]
}}
'''
            response = self.model.generate_content(context)
            text = response.text.strip()
            # Try to extract JSON from the response
            try:
                # Remove markdown code block if present
                if text.startswith('```json'):
                    text = text[7:]
                if text.startswith('```'):
                    text = text[3:]
                if text.endswith('```'):
                    text = text[:-3]
                # Try to load as JSON
                parsed = json.loads(text)
                # Basic sanitization: ensure required keys
                if 'summary' in parsed and 'mitigations' in parsed and isinstance(parsed['mitigations'], list):
                    return parsed
            except Exception as e:
                print(f"LLM JSON parse error: {e}\nRaw LLM output: {text}")
            # Fallback: return as plain text in a JSON object
            return {"summary": "LLM output could not be parsed as JSON.", "mitigations": [], "raw": text}
        except Exception as e:
            print(f"LLM service error: {e}")
            return None 