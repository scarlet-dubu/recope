import iptables
from collections import Counter
import threading
import time
import elasticsearch
from datetime import datetime

class DDoSMitigation():
    def __init__(self, rate_limit_threshold=1000, block_threshold=100):
        self.rate_limit_threshold = rate_limit_threshold
        self.block_threshold = block_threshold
        self.blocked_ips = set()
        self.ip_counter = Counter()
        self.lock = threading.Lock()
        
    def identify_suspicious_ips(self, packets):
        """Identify IPs showing suspicious behavior"""
        suspicious_ips = set()
        ip_counts = Counter(pkt[IP].src for pkt in packets)
        
        for ip, count in ip_counts.items():
            if count > self.block_threshold:
                suspicious_ips.add(ip)
                
            # Check for SYN flood
            syn_count = sum(1 for pkt in packets 
                          if pkt[IP].src == ip and pkt.haslayer('TCP') 
                          and pkt['TCP'].flags & 0x02)
            if syn_count > self.block_threshold / 2:
                suspicious_ips.add(ip)
                
        return suspicious_ips
        
    def block_ip(self, ip):
        """Block an IP using iptables"""
        try:
            if ip not in self.blocked_ips:
                iptables.add_rule(
                    'INPUT',
                    {'src': ip},
                    'DROP'
                )
                self.blocked_ips.add(ip)
                self.log_mitigation_action(ip, 'blocked')
        except Exception as e:
            self.logger.error(f"Failed to block IP {ip}: {str(e)}")
            
    def apply_rate_limiting(self, ip):
        """Apply rate limiting to specific IP"""
        try:
            iptables.add_rule(
                'INPUT',
                {
                    'src': ip,
                    'limit': f'{self.rate_limit_threshold}/second',
                    'limit-burst': str(self.rate_limit_threshold * 2)
                },
                'ACCEPT'
            )
            self.log_mitigation_action(ip, 'rate_limited')
        except Exception as e:
            self.logger.error(f"Failed to rate limit IP {ip}: {str(e)}")
            
    def log_mitigation_action(self, ip, action):
        """Log mitigation actions to Elasticsearch"""
        doc = {
            'timestamp': datetime.utcnow(),
            'ip_address': ip,
            'action': action,
            'type': 'mitigation'
        }
        self.es.index(index='ddos-mitigation', body=doc)
        
    def unblock_ip(self, ip, duration=3600):
        """Unblock IP after specified duration"""
        def delayed_unblock():
            time.sleep(duration)
            try:
                iptables.delete_rule(
                    'INPUT',
                    {'src': ip},
                    'DROP'
                )
                self.blocked_ips.remove(ip)
                self.log_mitigation_action(ip, 'unblocked')
            except Exception as e:
                self.logger.error(f"Failed to unblock IP {ip}: {str(e)}")
                
        thread = threading.Thread(target=delayed_unblock)
        thread.daemon = True
        thread.start()
