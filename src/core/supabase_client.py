from supabase import create_client, Client
from src.core.config import config
import logging
import sqlite3
import datetime
import os

logging.basicConfig(level=logging.INFO)

class SupabaseLogger:
    def __init__(self):
        self.client: Client = None
        self.use_sqlite = False
        
        if config.SUPABASE_URL and config.SUPABASE_KEY:
            try:
                self.client = create_client(config.SUPABASE_URL, config.SUPABASE_KEY)
                logging.info("Connected to Supabase.")
            except Exception as e:
                logging.error(f"Supabase connection failed: {e}. Falling back to SQLite.")
                self._fallback_to_sqlite()
        else:
            logging.warning("Supabase credentials missing in .env. Falling back to local SQLite DB.")
            self._fallback_to_sqlite()

    def _fallback_to_sqlite(self):
        self.use_sqlite = True
        # Create DB in project root
        db_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "local_alerts.db"))
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT,
                alert_type TEXT,
                rule_id TEXT,
                description TEXT,
                severity TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                confidence REAL
            )
        ''')
        self.conn.commit()

    def log_alert(self, alert_data: dict):
        """
        Pushes an alert to the remote Supabase database or local SQLite backup.
        """
        if self.use_sqlite:
            try:
                cursor = self.conn.cursor()
                cursor.execute('''
                    INSERT INTO alerts (created_at, alert_type, rule_id, description, severity, src_ip, dst_ip, confidence)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    datetime.datetime.now().isoformat(),
                    alert_data.get('alert_type'),
                    alert_data.get('rule_id', ''),
                    alert_data.get('description'),
                    alert_data.get('severity'),
                    alert_data.get('src_ip'),
                    alert_data.get('dst_ip'),
                    alert_data.get('confidence', 0.0)
                ))
                self.conn.commit()
                logging.info(f"[LOCAL SQLITE] Alert logged: {alert_data.get('alert_type')}")
            except Exception as e:
                logging.error(f"SQLite log failed: {e}")
        elif self.client:
            try:
                # We assume a table named 'alerts' exists in Supabase
                response = self.client.table("alerts").insert(alert_data).execute()
                logging.info(f"Alert pushed to Supabase: {alert_data.get('alert_type')} ({alert_data.get('rule_id') or alert_data.get('description')})")
            except Exception as e:
                logging.error(f"Failed to push alert to Supabase: {e}")
