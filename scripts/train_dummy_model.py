import os
import sys
import pandas as pd
import numpy as np
import logging

# Add project root to python path so we can import src
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(project_root)

from src.anomaly.engine import AnomalyEngine

# Keep ML logger quiet for the script summary
logging.getLogger().setLevel(logging.ERROR)

def generate_synthetic_data(num_samples=10000, output_csv="data/synthetic_normal_traffic.csv"):
    output_path = os.path.join(project_root, output_csv)
    print(f"[*] Generating {num_samples} samples of synthetic 'normal' traffic...")
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    # Normal traffic parameters mimicking typical HTTP/HTTPS and DNS behavior
    data = {
        "length": np.random.normal(loc=400, scale=300, size=num_samples).astype(int),
        "src_port": np.random.randint(10000, 65535, size=num_samples), # Ephemeral out ports
        "dst_port": np.random.choice([80, 443, 22, 53], size=num_samples, p=[0.45, 0.45, 0.05, 0.05]), 
        "protocol": np.random.choice([6, 17], size=num_samples, p=[0.85, 0.15]) # Mostly TCP (6)
    }
    
    # Make sure length doesn't go below 40 bytes (standard IP+TCP headers) or above MTU 1500
    data["length"] = np.clip(data["length"], 40, 1500)
    
    df = pd.DataFrame(data)
    df.to_csv(output_path, index=False)
    print(f"[*] Saved synthetic normal baseline to {output_csv}")
    return output_path

def main():
    print("===========================================")
    print("      Anomaly Engine Baseline Training     ")
    print("===========================================\n")
    
    csv_path = generate_synthetic_data()
    
    print(f"\n[*] Initializing Anomaly Engine...")
    os.chdir(project_root)  # Ensure model saves to the right relative path
    engine = AnomalyEngine()
    
    print("[*] Training Isolation Forest model. This may take a few seconds...")
    engine.train(csv_path)
    print("[*] Training Complete! Model saved to 'models/isolation_forest.pkl'\n")
    
    print("--- Testing the AI Model ---\n")
    
    # Test 1: Standard HTTPS packet
    normal_packet = {
        "length": 800,
        "src_port": 54321,
        "dst_port": 443,
        "protocol": 6,   # TCP
        "src_ip": "192.168.1.50",
        "dst_ip": "8.8.8.8"
    }
    
    # Test 2: Huge packet on a weird protocol and unusual port
    anomalous_packet = {
        "length": 9500,  # Jumbo frame size / unrealistic for standard web
        "src_port": 80,
        "dst_port": 4444, # Common reverse shell port
        "protocol": 1,    # ICMP instead of TCP/UDP
        "src_ip": "10.0.0.5",
        "dst_ip": "192.168.1.100"
    }
    
    res_normal = engine.evaluate(normal_packet)
    if res_normal:
        print("[FAIL] Normal web traffic was flagged as anomalous!")
    else:
        print("[SUCCESS] Normal web traffic was ignored (Passed AI check).")
        
    res_anomaly = engine.evaluate(anomalous_packet)
    if res_anomaly:
        print("[SUCCESS] AI caught the anomaly! Alert details generated:")
        print(f"         ➜ {res_anomaly['description']} (Confidence: {res_anomaly['confidence']:.2f})")
    else:
        print("[FAIL] The anomalous traffic bypassed the AI completely.")

if __name__ == "__main__":
    main()
