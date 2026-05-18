import os
import sys
import pandas as pd
import time
from scapy.all import sniff, IP, TCP, UDP
import logging

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(project_root)

from src.anomaly.engine import AnomalyEngine
from src.core.config import config

logging.getLogger().setLevel(logging.ERROR)

def extract_features(packet):
    if IP in packet:
        length = len(packet)
        src_port = 0
        dst_port = 0
        protocol = packet[IP].proto
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        return {"length": length, "src_port": src_port, "dst_port": dst_port, "protocol": protocol}
    return None

def capture_live_traffic(interface, duration=60, output_csv="data/live_normal_traffic.csv"):
    output_path = os.path.join(project_root, output_csv)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    print(f"[*] Sniffing LIVE traffic on '{interface}' for {duration} seconds to build a baseline...")
    print("[!] Please browse some websites or use the network normally now!")
    
    # We use sniff with a timeout to capture a finite window of live data
    packets = sniff(iface=interface, timeout=duration)
    
    print(f"[*] Capture complete! Analyzed {len(packets)} raw packets. Extracting AI features...")
    
    features_list = []
    for pkt in packets:
        feat = extract_features(pkt)
        if feat:
            features_list.append(feat)
            
    if not features_list:
        print("[!] Error: No IP packets captured! Make sure there's network activity.")
        return None
        
    df = pd.DataFrame(features_list)
    df.to_csv(output_path, index=False)
    print(f"[*] Saved realistic baseline to {output_csv}")
    return output_path

def main():
    print("===========================================")
    print("   Anomaly Engine LIVE Network Training    ")
    print("===========================================\n")
    
    # Capture 45 seconds of live traffic by default
    csv_path = capture_live_traffic(config.SNIFF_INTERFACE, duration=45)
    
    if not csv_path:
        return
        
    print("\n[*] Initializing Anomaly Engine...")
    os.chdir(project_root)
    engine = AnomalyEngine()
    
    print("[*] Training Isolation Forest model on your REAL packets...")
    engine.train(csv_path)
    print("\n[SUCCESS] Model successfully retrained on LIVE data! You can safely restart main.py.")

if __name__ == "__main__":
    main()
