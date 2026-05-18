import os
import sys

# Ensure Python can resolve the 'src' directory from the project root
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from src.core.supabase_client import SupabaseLogger

app = FastAPI(title="Hybrid IDS Dashboard")

# Mount static files
static_dir = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=static_dir), name="static")

db = SupabaseLogger()

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    with open(os.path.join(static_dir, "index.html"), "r") as f:
        return f.read()

@app.get("/api/alerts")
async def get_alerts():
    if db.use_sqlite:
        try:
            cursor = db.conn.cursor()
            cursor.execute("SELECT alert_type, rule_id, description, severity, src_ip, dst_ip, created_at, confidence FROM alerts ORDER BY id DESC LIMIT 50")
            rows = cursor.fetchall()
            alerts = []
            for r in rows:
                alerts.append({
                    "alert_type": r[0], "rule_id": r[1], "description": r[2],
                    "severity": r[3], "src_ip": r[4], "dst_ip": r[5],
                    "created_at": r[6], "confidence": r[7]
                })
            return {"alerts": alerts}
        except Exception as e:
            return {"error": str(e), "alerts": []}
    elif db.client:
        try:
            # Assuming the alerts table has 'id', 'alert_type', 'rule_id', 'description', 'severity', 'src_ip', 'dst_ip', 'created_at'
            res = db.client.table("alerts").select("*").order("created_at", desc=True).limit(50).execute()
            return {"alerts": res.data}
        except Exception as e:
            return {"error": str(e), "alerts": []}
            
    return {
        "alerts": [
            {"alert_type": "signature", "description": "DUMMY: No DB connection active.", "severity": "LOW", "src_ip": "127.0.0.1"}
        ]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
