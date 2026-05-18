import re
import logging

logging.basicConfig(level=logging.INFO)

class SignatureEngine:
    def __init__(self, rules_file=None):
        self.rules = []
        if rules_file:
            self.load_rules(rules_file)
        else:
            self._load_default_rules()

    def _load_default_rules(self):
        """
        Loads some standard hardcoded rules for quick testing.
        """
        self.rules = [
            {
                "id": "SIG-001",
                "desc": "SQL Injection Pattern (UNION SELECT)",
                "pattern": re.compile(rb"(?i)(UNION.*SELECT|OR\s+1=1)")
            },
            {
                "id": "SIG-002",
                "desc": "Nmap Scan Footprint",
                "pattern": re.compile(rb"(?i)(Nmap)")
            },
            {
                "id": "SIG-003",
                "desc": "Log4j JNDI Exploit String",
                "pattern": re.compile(rb"(?i)(\$\{jndi:lDAP)")
            },
            {
                "id": "SIG-004",
                "desc": "Directory Traversal",
                "pattern": re.compile(rb"(?i)(\.\./\.\./|%2e%2e%2f)")
            }
        ]
        logging.info(f"Loaded {len(self.rules)} default signature rules.")

    def load_rules(self, filepath):
        """
        Loads Snort-like rules from a file (placeholder for advanced loading).
        """
        # In a real system, we'd parse Snort `.rules` files here.
        logging.warning("Custom rule loading not yet fully implemented. Using defaults.")
        self._load_default_rules()

    def scan(self, packet_features: dict) -> dict:
        """
        Scans a packet's features and payload against known signatures.
        """
        payload = packet_features.get("payload", b"")
        if not payload:
            return None
        
        for rule in self.rules:
            if rule["pattern"].search(payload):
                alert_info = {
                    "alert_type": "signature",
                    "rule_id": rule["id"],
                    "description": rule["desc"],
                    "severity": "HIGH",
                    "src_ip": packet_features.get("src_ip"),
                    "dst_ip": packet_features.get("dst_ip")
                }
                logging.warning(f"[Signature Alert] {rule['id']} - {rule['desc']} detected from {alert_info['src_ip']}")
                return alert_info
                
        return None
