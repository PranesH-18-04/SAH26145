import { useState, useEffect } from 'react';

export interface FeatureContribution {
  feature_name: string;
  contribution_score: number;
  description: string;
}

export interface ThreatAnalysis {
  packet_id: string;
  threat_score: number;
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

export function useWebSocket(url: string) {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [isConnected, setIsConnected] = useState(false);

  useEffect(() => {
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
