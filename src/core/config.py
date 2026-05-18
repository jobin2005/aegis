import os
from dotenv import load_dotenv
from scapy.all import conf

load_dotenv()

class Config:
    # Network Settings - Auto-detect default interface
    _default_iface = getattr(conf.iface, "name", "eth0") if conf.iface else "eth0"
    SNIFF_INTERFACE = os.getenv("SNIFF_INTERFACE", _default_iface)
    PROMISCUOUS_MODE = os.getenv("PROMISCUOUS_MODE", "true").lower() == "true"
    
    # Supabase Settings
    SUPABASE_URL = os.getenv("SUPABASE_URL", "")
    SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")
    
    # ML Settings
    MODEL_PATH = os.getenv("MODEL_PATH", "models/isolation_forest.pkl")

config = Config()
