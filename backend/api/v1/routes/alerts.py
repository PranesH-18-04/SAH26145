from fastapi import APIRouter
from typing import List

router = APIRouter()

# Mock database
alerts_db = []

@router.get("/")
async def get_alerts():
    return alerts_db

@router.post("/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: str):
    # Mock update
    return {"status": "success", "message": f"Alert {alert_id} acknowledged."}

from fastapi import HTTPException
from services.database import get_alert_by_id
from services.gemini_service import gemini_service

@router.get("/{alert_id}/insight")
async def get_alert_insight(alert_id: str):
    alert = get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
        
    # Extract features to pass to Gemini
    protocol = alert.get('protocol', 'Unknown')
    severity = alert.get('severity', 'LOW')
    explanation = alert.get('explanation', '')
    
    features = {
        "packet_size": alert.get("packet_size"),
        "ack_completeness_ratio": alert.get("ack_completeness_ratio"),
        "half_duplex_burst_score": alert.get("half_duplex_burst_score"),
        "retransmission_blindness_index": alert.get("retransmission_blindness_index")
    }
    
    insight_data = gemini_service.get_insight(
        rule_based_explanation=explanation,
        severity=severity,
        protocol=protocol,
        features=features
    )
    
    return insight_data
