from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
from enum import Enum

class ProtocolEnum(str, Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"

class SeverityLevel(str, Enum):
    LOG_ONLY = "LOG_ONLY"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    CRITICAL = "CRITICAL"

class TrafficPacket(BaseModel):
    id: str
    timestamp_epoch: float
    timestamp_formatted: str
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: ProtocolEnum
    packet_size: int
    flow_duration: float
    flags: str

class FeatureContribution(BaseModel):
    feature_name: str
    contribution_score: float
    description: str

class ThreatAnalysis(BaseModel):
    packet_id: str
    threat_score: float
    raw_threat_score: float
    decay_factor: float
    occurrence_count: int
    signature: str
    severity: SeverityLevel
    category: str
    threat_type: Optional[str] = None
    explanation: str
    model_used: str = "Random Forest Classifier + Isolation Forest Hybrid"
    feature_contributions: List[FeatureContribution]

class Alert(BaseModel):
    id: str
    packet: TrafficPacket
    analysis: ThreatAnalysis
    acknowledged: bool = False

class ThreatSummary(BaseModel):
    total_packets: int
    safe_packets: int
    suspicious_packets: int
    malicious_packets: int
    top_threat_types: List[str]
