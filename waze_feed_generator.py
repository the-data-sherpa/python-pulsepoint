import json
import time
from typing import List, Dict
from datetime import datetime

# Waze CCP feed generator

def build_waze_alert(incident: Dict) -> Dict:
    """Build a Waze alert object from a PulsePoint traffic collision incident."""
    # Required fields per Waze spec
    # https://support.google.com/waze/partners/answer/6088691?hl=en
    return {
        "id": incident.get("ID") or incident.get("id") or incident.get("IncidentNumber", ""),
        "type": "ACCIDENT",
        "location": {
            "x": float(incident.get("Longitude") or incident.get("coordinates", [None, None])[1]),
            "y": float(incident.get("Latitude") or incident.get("coordinates", [None, None])[0]),
        },
        "pubMillis": int(time.mktime(datetime.fromisoformat(incident["_time"]).timetuple()) * 1000) if "_time" in incident else int(time.time() * 1000),
        "street": incident.get("FullDisplayAddress") or incident.get("MedicalEmergencyDisplayAddress") or "",
        "reportDescription": incident.get("description") or "Traffic collision reported by PulsePoint",
        "confidence": 8,
        "reliability": 7
    }

def generate_waze_feed(incidents: List[Dict], output_path: str = "waze_feed.json"):
    """Generate a Waze CCP JSON feed from a list of PulsePoint incidents."""
    alerts = []
    for incident in incidents:
        # Only include traffic collisions
        if incident.get("incident_type") == "Traffic Collision":
            try:
                alert = build_waze_alert(incident)
                alerts.append(alert)
            except Exception as e:
                print(f"Error building Waze alert for incident: {e}")
    feed = {"alerts": alerts}
    with open(output_path, "w") as f:
        json.dump(feed, f, indent=2)
    print(f"Waze CCP feed written to {output_path} with {len(alerts)} alerts.") 