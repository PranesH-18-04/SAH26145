from fastapi import APIRouter, Body
from typing import List
from models.schemas import ThreatSummary, TrafficPacket, ThreatAnalysis, Alert
import uuid
import time
from datetime import datetime
from services.ml_engine import ml_engine
from services.websocket_manager import manager

router = APIRouter()

@router.get("/summary", response_model=ThreatSummary)
async def get_traffic_summary():
    return ThreatSummary(
        total_packets=105432,
        safe_packets=104000,
        suspicious_packets=1200,
        malicious_packets=232,
        top_threat_types=["Data Exfiltration", "DDoS", "Unauthorized Tunneling"]
    )

@router.post("/simulate")
async def simulate_attack(attack_type: str = Body(..., embed=True)):
    epoch = time.time()
    formatted_time = datetime.fromtimestamp(epoch).strftime("%H:%M:%S.%f")[:-3]
    
    packet_dict = {
        "id": str(uuid.uuid4()),
        "timestamp_epoch": epoch,
        "timestamp_formatted": formatted_time,
        "source_ip": "185.12.33.200",
        "dest_ip": "10.0.1.100",
        "source_port": 45123,
        "dest_port": 80,
        "protocol": "TCP",
        "packet_size": 500,
        "flow_duration": 1.0,
        "flags": "ACK"
    }

    if attack_type == "DDoS":
        packet_dict["packet_size"] = 64
        packet_dict["flow_duration"] = 0.05
        packet_dict["flags"] = "SYN"
    elif attack_type == "Exfiltration":
        packet_dict["packet_size"] = 45000
        packet_dict["flow_duration"] = 25.0
    elif attack_type == "Tunneling":
        packet_dict["dest_port"] = 53
        packet_dict["protocol"] = "UDP"
        packet_dict["flags"] = "-"
        packet_dict["flow_duration"] = 60.0
        packet_dict["packet_size"] = 800

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
    
    await manager.broadcast(alert_obj.model_dump_json())
    return {"message": f"{attack_type} simulated and broadcasted"}
