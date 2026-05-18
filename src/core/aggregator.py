import threading
import queue
import logging
from src.signature.engine import SignatureEngine
from src.anomaly.engine import AnomalyEngine
from src.core.supabase_client import SupabaseLogger

logging.basicConfig(level=logging.INFO)

class AlertAggregator:
    def __init__(self, packet_queue: queue.Queue):
        self.packet_queue = packet_queue
        self.sig_engine = SignatureEngine()
        self.anomaly_engine = AnomalyEngine()
        self.db_logger = SupabaseLogger()
        self.stop_event = threading.Event()
        self.worker_thread = None

    def start(self):
        self.stop_event.clear()
        self.worker_thread = threading.Thread(target=self._process_loop, daemon=True)
        self.worker_thread.start()

    def _process_loop(self):
        while not self.stop_event.is_set():
            try:
                features = self.packet_queue.get(timeout=1.0)
                self._analyze(features)
            except queue.Empty:
                continue
            except Exception as e:
                logging.error(f"Error in aggregator loop: {e}")

    def _analyze(self, packet_features):
        """
        Runs both engines on the packet features.
        """
        # 1. Fast Path (Signature Match)
        sig_alert = self.sig_engine.scan(packet_features)
        if sig_alert:
            self.db_logger.log_alert(sig_alert)
            return  # Drop further processing if signature matches
            
        # 2. Deep Inspection (Anomaly Match)
        anom_alert = self.anomaly_engine.evaluate(packet_features)
        if anom_alert:
            self.db_logger.log_alert(anom_alert)

    def stop(self):
        self.stop_event.set()
        if self.worker_thread:
            self.worker_thread.join(timeout=2.0)
