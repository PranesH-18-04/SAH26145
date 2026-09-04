import asyncio
import json
import random
import uuid
import time
from datetime import datetime
from fastapi import WebSocket
from typing import List, Dict

from models.schemas import TrafficPacket, ThreatAnalysis, Alert
from services.ml_engine import ml_engine
from services.database import save_alert

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        
    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
        
    async def broadcast(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception as e:
                print(f"Failed to send message: {e}")

manager = ConnectionManager()

def generate_mock_packet() -> dict:
    """Simulates unidirectional network traffic adhering to strict realism constraints."""
    # Realistic internal ranges (RFC 1918) and plausible external actors
    internal_ips = [f"10.0.5.{random.randint(1, 254)}" for _ in range(4)]
    external_ips = [f"45.33.{random.randint(1, 254)}.{random.randint(1, 254)}", 
                    f"185.12.{random.randint(1, 254)}.{random.randint(1, 254)}"]
    
    source_ip = random.choice(internal_ips + external_ips)
    dest_ip = "10.0.1.100" # Internal server
    
    dest_port = random.choice([80, 443, 22, 53, 3306])
    
    # Strict Protocol and Flag Realism
    if dest_port == 53:
        protocol = "UDP"
        flags = "-"
    elif dest_port == 22:
        protocol = "TCP"
        flags = random.choice(["PSH,ACK", "ACK", "SYN"])
    elif dest_port in [80, 443, 3306]:
        protocol = "TCP"
        flags = random.choice(["ACK", "SYN", "FIN,ACK", "RST", "PSH,ACK"])
    else:
        protocol = "UDP"
        flags = "-"
    
    packet_size = random.randint(40, 1500)
    if random.random() < 0.05:
        packet_size = random.randint(1500, 45000)
        
    flow_duration = random.uniform(0.001, 5.0)
    if random.random() < 0.05:
        flow_duration = random.uniform(10.0, 30.0)
        
    epoch = time.time()
    # Format: HH:MM:SS.mmm
    formatted_time = datetime.fromtimestamp(epoch).strftime("%H:%M:%S.%f")[:-3]
        
    return {
        "id": str(uuid.uuid4()),
        "timestamp_epoch": epoch,
        "timestamp_formatted": formatted_time,
        "source_ip": source_ip,
        "dest_ip": dest_ip,
        "source_port": random.randint(1024, 65535),
        "dest_port": dest_port,
        "protocol": protocol,
        "packet_size": packet_size,
        "flow_duration": flow_duration,
        "flags": flags
    }

async def traffic_generator():
    """Background task to generate traffic and stream alerts."""
    while True:
        packet_dict = generate_mock_packet()
        
        # Analyze packet through ML Engine
        analysis_result = ml_engine.analyze_packet(packet_dict)
        
        packet_obj = TrafficPacket(**packet_dict)
        analysis_obj = ThreatAnalysis(
            packet_id=packet_dict['id'],
            threat_score=analysis_result['threat_score'],
            severity=analysis_result['severity'],
            category=analysis_result['category'],
            threat_type=analysis_result['threat_type'],
            explanation=analysis_result['explanation'],
            feature_contributions=analysis_result['feature_contributions']
        )
        
        alert_obj = Alert(
            id=str(uuid.uuid4()),
            packet=packet_obj,
            analysis=analysis_obj,
            acknowledged=False
        )
        
        save_alert(alert_obj.model_dump())
        
        await manager.broadcast(alert_obj.model_dump_json())
        await asyncio.sleep(random.uniform(0.2, 1.5))
