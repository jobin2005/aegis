import threading
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
import time
import logging

logging.basicConfig(level=logging.INFO)

class NetworkSniffer:
    def __init__(self, interface="eth0", packet_queue=None):
        """
        Initializes the packet sniffer.
        :param interface: The network interface to sniff on.
        :param packet_queue: A thread-safe queue to place extracted features.
        """
        self.interface = interface
        self.packet_queue = packet_queue
        self.stop_event = threading.Event()
        self.sniff_thread = None

    def _packet_handler(self, packet):
        """
        Extracts metadata and payload from a raw packet.
        """
        if IP in packet:
            features = {
                "timestamp": time.time(),
                "src_ip": packet[IP].src,
                "dst_ip": packet[IP].dst,
                "protocol": packet[IP].proto,
                "length": len(packet),
                "src_port": 0,
                "dst_port": 0,
                "tcp_flags": "",
                "payload": b""
            }
            
            if TCP in packet:
                features["src_port"] = packet[TCP].sport
                features["dst_port"] = packet[TCP].dport
                features["tcp_flags"] = str(packet[TCP].flags)
            elif UDP in packet:
                features["src_port"] = packet[UDP].sport
                features["dst_port"] = packet[UDP].dport
                
            if packet.haslayer(Raw):
                features["payload"] = packet.getlayer(Raw).load

            if self.packet_queue:
                self.packet_queue.put(features)

    def start(self):
        """
        Starts the sniffing loop in a background thread.
        """
        logging.info(f"Starting sniffer on interface {self.interface}")
        self.stop_event.clear()
        self.sniff_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.sniff_thread.start()

    def _sniff_loop(self):
        # Using stop_filter to cleanly exit the sniff loop when instructed
        sniff(
            iface=self.interface, 
            prn=self._packet_handler, 
            store=False, 
            stop_filter=lambda x: self.stop_event.is_set()
        )

    def stop(self):
        """
        Stops the sniffer.
        """
        logging.info("Stopping sniffer...")
        self.stop_event.set()
        if self.sniff_thread:
            self.sniff_thread.join(timeout=2.0)
