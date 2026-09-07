from fastapi import APIRouter, UploadFile, File
from fastapi.responses import JSONResponse
import uuid
import time
from datetime import datetime
from scapy.all import rdpcap, IP, TCP, UDP
import os
import tempfile

from services.ml_engine import ml_engine
from models.schemas import TrafficPacket, ThreatAnalysis, Alert
from services.websocket_manager import manager

router = APIRouter()

@router.post("/upload")
async def upload_pcap(file: UploadFile = File(...)):
    if not file.filename.endswith('.pcap'):
        return JSONResponse(status_code=400, content={"message": "File must be a .pcap file"})
    
    # Save temporarily
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = tmp.name

    try:
        packets = rdpcap(tmp_path)
        processed_alerts = []
        
        for pkt in packets:
            if IP not in pkt:
                continue
                
            ip_layer = pkt[IP]
            source_ip = ip_layer.src
            dest_ip = ip_layer.dst
            
            packet_size = len(pkt)
            flow_duration = 0.05 # Mocked for individual packets, as actual flows require state tracking
            
            protocol = "OTHER"
            dest_port = 0
            flags = "-"
            
            if TCP in pkt:
                protocol = "TCP"
                dest_port = pkt[TCP].dport
                flags = str(pkt[TCP].flags)
            elif UDP in pkt:
                protocol = "UDP"
                dest_port = pkt[UDP].dport
                
            epoch = time.time()
            formatted_time = datetime.fromtimestamp(epoch).strftime("%H:%M:%S.%f")[:-3]
            
            packet_dict = {
                "id": str(uuid.uuid4()),
                "timestamp_epoch": epoch,
                "timestamp_formatted": formatted_time,
                "source_ip": source_ip,
                "dest_ip": dest_ip,
                "source_port": pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0),
                "dest_port": dest_port,
                "protocol": protocol,
                "packet_size": packet_size,
                "flow_duration": flow_duration,
                "flags": flags,
                "ack_completeness_ratio": 0.0,
                "half_duplex_burst_score": 0.0,
                "handshake_stub_flag": 0,
                "retransmission_blindness_index": 0.0
            }
            
            analysis_result = ml_engine.analyze_packet(packet_dict)
            
            packet_obj = TrafficPacket(**packet_dict)
            analysis_obj = ThreatAnalysis(
                packet_id=packet_dict['id'],
                threat_score=analysis_result['threat_score'],
                raw_threat_score=analysis_result['raw_threat_score'],
                decay_factor=analysis_result['decay_factor'],
                occurrence_count=analysis_result['occurrence_count'],
                signature=analysis_result['signature'],
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
            
            # Broadcast live to the dashboard!
            await manager.broadcast(alert_obj.model_dump_json())
            processed_alerts.append(alert_obj.model_dump())
            
    finally:
        os.unlink(tmp_path)
        
    return {"message": f"Successfully processed {len(processed_alerts)} packets from PCAP", "alerts_streamed": len(processed_alerts)}
