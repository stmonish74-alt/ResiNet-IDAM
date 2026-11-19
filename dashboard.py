from datetime import datetime, timedelta


def get_dashboard_data():
    """Stage 1 demonstration data only; not live network telemetry."""
    return {
        "mode": "DEMO DATA",
        "network_events": 1284,
        "threats_detected": 23,
        "access_allowed": 96,
        "access_denied": 12,
        "risk_score": 18,
        "threat_distribution": [
            {"label": "Normal", "value": 72},
            {"label": "Suspicious", "value": 19},
            {"label": "Malicious", "value": 9}
        ],
        "traffic": [
            {"time": "00:00", "value": 18},
            {"time": "04:00", "value": 24},
            {"time": "08:00", "value": 38},
            {"time": "12:00", "value": 31},
            {"time": "16:00", "value": 55},
            {"time": "20:00", "value": 42},
            {"time": "23:00", "value": 48}
        ]
    }


def get_recent_events():
    now = datetime.now()
    rows = [
        ("Unusual outbound traffic", "Suspicious", "10.0.2.18", "Investigate"),
        ("Multiple failed login attempts", "High", "10.0.1.44", "Review"),
        ("Successful analyst sign-in", "Info", "10.0.0.12", "Allowed"),
        ("Unrecognized service request", "Medium", "10.0.3.27", "Monitor"),
        ("Policy check completed", "Info", "10.0.0.31", "Allowed"),
    ]
    return [
        {
            "time": (now - timedelta(minutes=i * 7)).strftime("%H:%M:%S"),
            "event": event,
            "severity": severity,
            "source": source,
            "action": action
        }
        for i, (event, severity, source, action) in enumerate(rows)
    ]
