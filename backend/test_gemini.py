#!/usr/bin/env python3
"""
Test script for Google Gemini integration
"""

import os
from services.llm_service import LLMService

def test_gemini_integration():
    """Test the Gemini integration"""
    print("Testing Google Gemini Integration...")
    
    # Test without API key
    llm_service = LLMService()
    print(f"API Key available: {llm_service.api_key is not None}")
    
    # Test log entry
    test_log_entry = {
        "timestamp": "2025-07-08 21:14:53",
        "src_ip": "192.168.1.30",
        "dest_ip": "143.156.56.25",
        "domain": "malware-domain.net",
        "action": "Blocked",
        "method": "GET",
        "status_code": "500",
        "bytes": "6 29",
        "user_agent": "curl/7.68.0"
    }
    
    test_model_reasons = {
        'isolation_forest': {
            'flagged': True,
            'reasons': [
                "Suspicious domain name: malware-domain.net",
                "Request was blocked by security system",
                "High HTTP status code (500) indicating server errors"
            ],
            'feature_importance': [0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0]
        },
        'lof': {
            'flagged': True,
            'reasons': [
                "Suspicious domain name: malware-domain.net",
                "Automated tool detected in user agent"
            ],
            'feature_importance': [0.3, 0.3, 0.2, 0.1, 0.1, 0.0, 0.0]
        }
    }
    
    # Test explanation generation
    explanation = llm_service.generate_anomaly_explanation(test_log_entry, test_model_reasons)
    if explanation:
        print("✅ LLM Explanation generated successfully!")
        print(f"Explanation: {explanation[:200]}...")
    else:
        print("❌ No LLM explanation generated (likely no API key)")
    
    # Test summary report
    test_analysis_results = {
        'num_entries': 500,
        'num_anomalies': 25,
        'model_performance': {
            'isolation_forest_anomalies': 20,
            'lof_anomalies': 18,
            'both_models_flagged': 15
        },
        'anomalies': [
            {'domain': 'malware-domain.net', 'action': 'Blocked', 'src_ip': '192.168.1.30'},
            {'domain': 'suspicious-site.xyz', 'action': 'Blocked', 'src_ip': '192.168.1.45'}
        ]
    }
    
    summary = llm_service.generate_summary_report(test_analysis_results)
    if summary:
        print("✅ Summary report generated successfully!")
        print(f"Summary: {summary[:200]}...")
    else:
        print("❌ No summary report generated (likely no API key)")
    
    print("\nTo enable LLM features, set the GOOGLE_API_KEY environment variable:")
    print("export GOOGLE_API_KEY='your-google-api-key-here'")

if __name__ == "__main__":
    test_gemini_integration() 