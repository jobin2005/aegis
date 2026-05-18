import time
import queue
import logging
from src.ingestion.sniffer import NetworkSniffer
from src.core.aggregator import AlertAggregator
from src.core.config import config

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(name)s: %(message)s')

def main():
    print("=======================================")
    print("      Hybrid IDS (Scapy + ML)          ")
    print("=======================================")
    
    packet_queue = queue.Queue(maxsize=10000)
    
    # Initialize Engine Aggregator
    aggregator = AlertAggregator(packet_queue)
    
    # Initialize Sniffer
    sniffer = NetworkSniffer(interface=config.SNIFF_INTERFACE, packet_queue=packet_queue)
    
    try:
        logging.info("Starting Aggregator engine...")
        aggregator.start()
        
        logging.info("Starting Sniffer...")
        sniffer.start()
        
        logging.info("System is running. Press Ctrl+C to stop.")
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        logging.info("Keyboard interrupt received. Shutting down...")
    finally:
        sniffer.stop()
        aggregator.stop()
        logging.info("Shutdown complete.")

if __name__ == "__main__":
    main()
