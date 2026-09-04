import { useState, useEffect } from 'react';

export interface FeatureContribution {
  feature_name: string;
  contribution_score: number;
  description: string;
}

export interface ThreatAnalysis {
  packet_id: string;
  threat_score: number;
  raw_threat_score: number;
  decay_factor: number;
  occurrence_count: number;
  signature: string;
  severity: 'LOG_ONLY' | 'LOW' | 'MEDIUM' | 'CRITICAL';
  category: 'Safe' | 'Suspicious' | 'Malicious';
  threat_type?: string;
  explanation: string;
  model_used: string;
  feature_contributions: FeatureContribution[];
}

export interface TrafficPacket {
  id: string;
  timestamp_epoch: number;
  timestamp_formatted: string;
  source_ip: string;
  dest_ip: string;
  source_port: number;
  dest_port: number;
  protocol: string;
  packet_size: number;
  flow_duration: number;
  flags: string;
}

export interface AuditLogEntry {
  timestamp_formatted: string;
  user_role: string;
  action: string;
}

export interface Alert {
  id: string;
  packet: TrafficPacket;
  analysis: ThreatAnalysis;
  status: 'NEW' | 'ACKNOWLEDGED' | 'INVESTIGATING' | 'RESOLVED' | 'FALSE_POSITIVE';
  audit_trail: AuditLogEntry[];
}

export function useWebSocket(url: string, httpUrl: string) {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [isConnected, setIsConnected] = useState(false);

  useEffect(() => {
    // Load persisted history first
    fetch(`${httpUrl}/api/v1/history`)
      .then(res => res.json())
      .then(data => {
        if (Array.isArray(data)) {
          // Map DB rows back to Alert objects
          const parsedHistory = data.map((row: any) => ({
            id: row.id,
            packet: {
              id: row.id,
              timestamp_epoch: row.timestamp_epoch,
              timestamp_formatted: row.timestamp_formatted,
              source_ip: row.source_ip,
              dest_ip: row.dest_ip,
              source_port: 0,
              dest_port: row.dest_port,
              protocol: row.protocol,
              packet_size: row.packet_size,
              flow_duration: 0,
              flags: "-"
            },
            analysis: {
              packet_id: row.id,
              threat_score: row.threat_score,
              raw_threat_score: row.raw_threat_score || row.threat_score,
              decay_factor: row.decay_factor || 1.0,
              occurrence_count: row.occurrence_count || 1,
              signature: row.signature || "unknown",
              severity: row.severity,
              category: row.category,
              threat_type: row.threat_type,
              explanation: row.explanation,
              model_used: "Random Forest Classifier + Isolation Forest Hybrid",
              feature_contributions: []
            },
            acknowledged: false,
            status: 'NEW' as 'NEW',
            audit_trail: []
          }));
          setAlerts(parsedHistory);
        }
      })
      .catch(err => console.error('Failed to load history', err));

    const ws = new WebSocket(url);

    ws.onopen = () => {
      console.log('Connected to WebSocket');
      setIsConnected(true);
    };

    ws.onmessage = (event) => {
      const data: Alert = JSON.parse(event.data);
      // Ensure we sort strictly by the backend epoch timestamp if they arrive slightly out of order
      // Using unshift behavior by placing data at the front, then slicing.
      setAlerts((prev) => {
        const next = [data, ...prev].slice(0, 100);
        return next.sort((a, b) => b.packet.timestamp_epoch - a.packet.timestamp_epoch);
      });
    };

    ws.onclose = () => {
      console.log('Disconnected from WebSocket');
      setIsConnected(false);
      setTimeout(() => setIsConnected(false), 3000); 
    };

    return () => {
      ws.close();
    };
  }, [url]);

  return { alerts, isConnected };
}
