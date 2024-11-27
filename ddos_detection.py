import joblib
import pandas as pd
import numpy as np
from scapy.all import sniff, IP
import ipaddress
from collections import defaultdict, deque
import threading
import time
from datetime import datetime
import logging
import socket
import queue
from ddos_mitigation import *


mitigation_system = DDoSMitigation()

class DDoSDetectionSystem:
    def __init__(self, model_path, monitoring_interval=60, queue_maxlen=1000):
        
        # Loading the trained model
        self.model = joblib.load('model_v3.joblib')
        
        # Initialize monitoring parameters
        self.monitoring_interval = monitoring_interval
        self.packet_queue = deque(maxlen=queue_maxlen)
        self.traffic_stats = defaultdict(int)
        self.unique_ips = set()
        
        # Setup logging
        self.setup_logging()
        
        # Thread-safe queue for processing
        self.processing_queue = queue.Queue()
        
        # Flag for controlling the monitoring thread
        self.is_running = False
        
    def setup_logging(self):
        """Configure logging system"""
        logging.basicConfig(
            filename='ddos_detection.log',
            format='%(asctime)s - %(levelname)s - %(message)s',
            level=logging.INFO
        )
        self.logger = logging.getLogger(__name__)
        
    def packet_callback(self, packet):        
        if IP in packet:
            # Add packet to processing queue
            self.processing_queue.put(packet) ##
            
            
    def extract_features(self, packets):
        stats = {
            'packet_count': len(packets),
            'unique_ips': len(set(pkt[IP].src for pkt in packets)),
            'avg_packet_size': np.mean([len(pkt) for pkt in packets]),
            'tcp_ratio': sum(1 for pkt in packets if pkt.haslayer('TCP')) / len(packets),
            'udp_ratio': sum(1 for pkt in packets if pkt.haslayer('UDP')) / len(packets),
            'icmp_ratio': sum(1 for pkt in packets if pkt.haslayer('ICMP')) / len(packets),

            'packet_rate': len(packets) / self.monitoring_interval,
            # 'entropy': self.calculate_ip_entropy(packets),
            # 'syn_ratio': self.calculate_syn_ratio(packets),
            # 'size_variance': np.var([len(pkt) for pkt in packets]),
            'port_diversity': len(set(pkt[IP].dport for pkt in packets if hasattr(pkt[IP], 'dport')))
        }
        
        return pd.DataFrame([stats])
        
    
    def predict_ddos(self, features):
        try:
            prediction = self.model.predict(features)
            return bool(prediction[0])
        except Exception as e:
            self.logger.error(f"Prediction error: {str(e)}")
            return False
            
            
    def trigger_mitigation(self, is_attack):
       if is_attack:
            mitigation_system.identify_suspicious_ips()
            mitigation_system.block_ip()
            mitigation_system.apply_rate_limiting()
            mitigation_system.log_mitigation_action


            self.logger.warning("DDoS Attack Detected! Initiating mitigation...")
        
       # Block suspicious IPs
       #     suspicious_ips = self.identify_suspicious_ips()
       #     self.block_ips(suspicious_ips)
        # Log mitigation actions
        #    self.logger.warning(f"Blocking IPs: {suspicious_ips}")

# Add mitigation by blocking IP addresses and rate limiting
#NB!!! INCOMPLETE
# consider having the mitigation strategies be different .py files if possible

            
    def process_packets(self):
        while self.is_running:
            current_packets = []
            
            # Collect packets for the monitoring interval
            start_time = time.time()
            while time.time() - start_time < self.monitoring_interval:
                try:
                    packet = self.processing_queue.get(timeout=1)
                    current_packets.append(packet)
                except queue.Empty:
                    continue
                    
            if current_packets:
                # Extract features and make prediction
                features = self.extract_features(current_packets)
                is_attack = self.predict_ddos(features)
                
                # Logging results
                self.logger.info(
                    f"Analysis complete - Packets analyzed: {len(current_packets)}, "
                    f"Attack detected: {is_attack}"
                )
                
                # Trigger mitigation if attack detected
                self.trigger_mitigation(is_attack)
                
                
    def start_monitoring(self, interface="eth0"):
# NB!!!! The interface might change later
            
        self.is_running = True
        
        processing_thread = threading.Thread(target=self.process_packets)
        processing_thread.daemon = True
        processing_thread.start()
        
        self.logger.info(f"Starting DDoS detection monitoring on interface: {interface}")
        
        try:
            # Start packet capture
            sniff(
                iface=interface,
                prn=self.packet_callback,
                store=0
            )
        except Exception as e:
            self.logger.error(f"Error in packet capture: {str(e)}")
            self.stop_monitoring()
            
    #stopping the system
    def stop_monitoring(self):
        """Stop the DDoS detection monitoring system"""
        self.is_running = False
        self.logger.info("Stopping DDoS detection monitoring")

