import os
import psutil
import time
import socket
import json
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import logging
import argparse
import threading
import pickle
from datetime import datetime

def display_banner():
    """Display the VRJ banner when the program starts"""
    banner = """
██╗   ██╗██████╗      ██╗
██║   ██║██╔══██╗     ██║
██║   ██║██████╔╝     ██║
╚██╗ ██╔╝██╔══██╗██   ██║
 ╚████╔╝ ██║  ██║╚█████╔╝
  ╚═══╝  ╚═╝  ╚═╝ ╚════╝ 
                         
CryptoGuardML - Advanced Cryptojacking Detection Tool
    """
    print(banner)
    print("=" * 60)
    print("  Machine Learning-based Cryptojacking Detection System")
    print("=" * 60)
    print()

class CryptojackingDetector:
    def __init__(self, model_path=None, training_mode=False, sensitivity=0.95):
        self.sensitivity = sensitivity
        self.training_mode = training_mode
        self.model_path = model_path
        self.model = None
        self.scaler = None
        self.data = []
        self.detection_threshold = 0.5
        self.known_mining_ports = [3333, 5555, 7777, 8888, 9999, 14444, 14433]
        self.known_mining_domains = ["pool.minexmr.com", "xmr.pool.minergate.com", "pool.supportxmr.com"]
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler("cryptojacking_detector.log"),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger("CryptoGuardML")
        
        if model_path and os.path.exists(model_path) and not training_mode:
            self.load_model()
        elif not training_mode:
            self.logger.warning("No model found, starting in automatic training mode first")
            self.training_mode = True
    
    def load_model(self):
        """Load the trained model and scaler from disk"""
        try:
            with open(self.model_path, 'rb') as f:
                saved_data = pickle.load(f)
                self.model = saved_data['model']
                self.scaler = saved_data['scaler']
                self.logger.info("Model loaded successfully")
        except Exception as e:
            self.logger.error(f"Error loading model: {e}")
            self.training_mode = True
    
    def save_model(self):
        """Save the trained model and scaler to disk"""
        if self.model is None or self.scaler is None:
            self.logger.error("Cannot save model - model or scaler is None")
            return False
            
        try:
            with open(self.model_path or "cryptojacking_model.pkl", 'wb') as f:
                pickle.dump({
                    'model': self.model,
                    'scaler': self.scaler
                }, f)
            self.logger.info(f"Model saved to {self.model_path or 'cryptojacking_model.pkl'}")
            return True
        except Exception as e:
            self.logger.error(f"Error saving model: {e}")
            return False
    
    def collect_system_metrics(self):
        """Collect system metrics for CPU, memory and network"""
        metrics = {}
        
        # CPU metrics
        metrics['cpu_percent'] = psutil.cpu_percent(interval=1)
        metrics['cpu_count'] = psutil.cpu_count()
        
        per_cpu = psutil.cpu_percent(interval=1, percpu=True)
        metrics['cpu_std_dev'] = np.std(per_cpu)
        metrics['cpu_max'] = max(per_cpu)
        
        # Memory metrics
        memory = psutil.virtual_memory()
        metrics['memory_percent'] = memory.percent
        metrics['memory_available_gb'] = memory.available / (1024**3)
        
        # Network metrics
        net_io = psutil.net_io_counters()
        metrics['net_bytes_sent'] = net_io.bytes_sent
        metrics['net_bytes_recv'] = net_io.bytes_recv
        
        # Save current time for calculating rates on next collection
        metrics['timestamp'] = time.time()
        
        if hasattr(self, 'last_metrics'):
            time_diff = metrics['timestamp'] - self.last_metrics['timestamp']
            metrics['net_bytes_sent_rate'] = (metrics['net_bytes_sent'] - self.last_metrics['net_bytes_sent']) / time_diff
            metrics['net_bytes_recv_rate'] = (metrics['net_bytes_recv'] - self.last_metrics['net_bytes_recv']) / time_diff
        else:
            metrics['net_bytes_sent_rate'] = 0
            metrics['net_bytes_recv_rate'] = 0
        
        self.last_metrics = metrics.copy()
        
        # Check for suspicious connections
        metrics['suspicious_connections'] = self.check_suspicious_connections()
        
        return metrics
    
    def check_suspicious_connections(self):
        """Check for connections to known mining pools or on suspicious ports"""
        suspicious_count = 0
        
        try:
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    # Check if connection is using a known mining port
                    if conn.raddr.port in self.known_mining_ports:
                        suspicious_count += 1
                        self.logger.warning(f"Suspicious connection detected to {conn.raddr.ip}:{conn.raddr.port}")
                    
                    # Try to resolve IP to hostname
                    try:
                        hostname = socket.gethostbyaddr(conn.raddr.ip)[0]
                        for domain in self.known_mining_domains:
                            if domain in hostname:
                                suspicious_count += 2
                                self.logger.warning(f"Connection to known mining domain detected: {hostname}")
                    except:
                        pass
        except:
            pass
            
        return suspicious_count
    
    def train_model(self, data_points=1000):
        """Train the anomaly detection model"""
        self.logger.info(f"Starting model training with {len(self.data)} data points")
        
        if len(self.data) < data_points:
            self.logger.warning(f"Not enough data for training. Have {len(self.data)}, need {data_points}")
            return False
            
        # Convert to DataFrame
        df = pd.DataFrame(self.data)
        
        # Select features for model training
        features = [
            'cpu_percent', 'cpu_std_dev', 'cpu_max',
            'memory_percent', 'memory_available_gb',
            'net_bytes_sent_rate', 'net_bytes_recv_rate',
            'suspicious_connections'
        ]
        
        X = df[features].values
        
        # Normalize features
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)
        
        # Train isolation forest model
        self.model = IsolationForest(
            contamination=1.0 - self.sensitivity,
            random_state=42,
            n_estimators=100
        )
        self.model.fit(X_scaled)
        
        self.logger.info("Model training completed")
        
        # Save the model
        if self.save_model():
            self.training_mode = False
            return True
        
        return False
    
    def predict(self, metrics):
        """Make prediction using the trained model"""
        if self.model is None or self.scaler is None:
            return 0
            
        features = [
            metrics['cpu_percent'], metrics['cpu_std_dev'], metrics['cpu_max'],
            metrics['memory_percent'], metrics['memory_available_gb'],
            metrics['net_bytes_sent_rate'], metrics['net_bytes_recv_rate'],
            metrics['suspicious_connections']
        ]
        
        X = np.array(features).reshape(1, -1)
        X_scaled = self.scaler.transform(X)
        
        # Get anomaly score (-1 for anomalies, 1 for normal)
        result = self.model.predict(X_scaled)[0]
        score = self.model.score_samples(X_scaled)[0]
        
        # Convert to threat level (0 to 1, where 1 is highest threat)
        # Lower score means more anomalous
        threat_level = 1 - (score - self.model.offset_) / abs(self.model.offset_)
        threat_level = max(0, min(1, threat_level))
        
        return threat_level
    
    def check_process_patterns(self):
        """Check running processes for cryptomining patterns"""
        suspicious_processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cpu_percent']):
            try:
                # Skip processes with low CPU usage
                if proc.info['cpu_percent'] < 10:
                    continue
                    
                # Check for known miner names or command patterns
                name = proc.info['name'].lower() if proc.info['name'] else ""
                cmdline = " ".join(proc.info['cmdline']).lower() if proc.info['cmdline'] else ""
                
                suspicious_keywords = [
                    'xmrig', 'minergate', 'cryptonight', 'stratum+tcp',
                    'monero', 'eth_submitLogin', 'dwarfpool', 'nanopool',
                    'nicehash', 'minerd', 'cpuminer', 'coinhive'
                ]
                
                for keyword in suspicious_keywords:
                    if keyword in name or keyword in cmdline:
                        self.logger.warning(f"Suspicious mining process detected: PID {proc.info['pid']}, Name: {name}")
                        suspicious_processes.append({
                            'pid': proc.info['pid'],
                            'name': name,
                            'cmdline': cmdline,
                            'cpu_percent': proc.info['cpu_percent']
                        })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
                
        return suspicious_processes
    
    def run(self, interval=5, training_duration=3600):
        """Main monitoring loop"""
        self.logger.info("Starting cryptojacking detector")
        start_time = time.time()
        
        try:
            while True:
                # Collect system metrics
                metrics = self.collect_system_metrics()
                self.data.append(metrics)
                
                # Keep data to a reasonable size
                if len(self.data) > 10000:
                    self.data = self.data[-10000:]
                
                if self.training_mode:
                    elapsed_time = time.time() - start_time
                    self.logger.info(f"Training mode: {len(self.data)}/{training_duration/interval} samples collected. Time elapsed: {elapsed_time:.0f}s/{training_duration}s")
                    
                    if elapsed_time >= training_duration:
                        if self.train_model():
                            self.logger.info("Switching to detection mode")
                        else:
                            self.logger.warning("Training failed, continuing to collect data")
                            start_time = time.time()  # Reset timer for more training
                else:
                    # Make prediction
                    threat_level = self.predict(metrics)
                    
                    # Check for suspicious processes
                    suspicious_processes = self.check_process_patterns()
                    
                    # Log information
                    log_message = (
                        f"Threat level: {threat_level:.2f}, "
                        f"CPU: {metrics['cpu_percent']}%, "
                        f"Memory: {metrics['memory_percent']}%, "
                        f"Net: ↑{metrics['net_bytes_sent_rate']/1024:.1f}KB/s ↓{metrics['net_bytes_recv_rate']/1024:.1f}KB/s"
                    )
                    
                    if threat_level > self.detection_threshold:
                        self.logger.warning(log_message)
                        self.logger.warning(f"ALERT: Potential cryptojacking activity detected! Threat level: {threat_level:.2f}")
                        
                        # Log suspicious processes if any
                        if suspicious_processes:
                            for proc in suspicious_processes:
                                self.logger.warning(f"Suspicious process: PID {proc['pid']}, Name: {proc['name']}, CPU: {proc['cpu_percent']}%")
                                
                        # Save the detection data
                        detection_data = {
                            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            'threat_level': threat_level,
                            'metrics': metrics,
                            'suspicious_processes': suspicious_processes
                        }
                        
                        with open(f"detection_{int(time.time())}.json", 'w') as f:
                            json.dump(detection_data, f, indent=2, default=str)
                    else:
                        self.logger.info(log_message)
                
                time.sleep(interval)
                
        except KeyboardInterrupt:
            self.logger.info("Detector stopped by user")
        except Exception as e:
            self.logger.error(f"Error in detector: {e}")

def main():
    # Display the VRJ banner
    display_banner()
    
    parser = argparse.ArgumentParser(description="CryptoGuardML - Machine Learning-based Cryptojacking Detector")
    parser.add_argument("--train", action="store_true", help="Start in training mode")
    parser.add_argument("--model", default="cryptojacking_model.pkl", help="Path to model file")
    parser.add_argument("--interval", type=int, default=5, help="Monitoring interval in seconds")
    parser.add_argument("--training-time", type=int, default=3600, help="Training duration in seconds")
    parser.add_argument("--sensitivity", type=float, default=0.95, help="Detection sensitivity (0.9-0.99)")
    parser.add_argument("--threshold", type=float, default=0.7, help="Alert threshold (0.0-1.0)")
    
    args = parser.parse_args()
    
    detector = CryptojackingDetector(
        model_path=args.model,
        training_mode=args.train,
        sensitivity=args.sensitivity
    )
    
    detector.detection_threshold = args.threshold
    detector.run(interval=args.interval, training_duration=args.training_time)

if __name__ == "__main__":
    main()