import json
from datetime import datetime

def save_report(data: dict, name: str):
    filename = f"report_{name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return filename
