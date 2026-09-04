import { Alert } from '../hooks/useWebSocket';
import { AlertTriangle, ShieldCheck, HelpCircle, Info } from 'lucide-react';


interface Props {
  alerts: Alert[];
  onSelectRow: (alert: Alert) => void;
  selectedId?: string;
}

export default function LiveTrafficTable({ alerts, onSelectRow, selectedId }: Props) {
  if (alerts.length === 0) {
    return (
      <div className="h-full flex flex-col items-center justify-center text-gray-500">
        <div className="animate-pulse flex space-x-4">
          <div className="h-2 bg-gray-700 rounded w-24"></div>
          <div className="h-2 bg-gray-700 rounded w-24"></div>
        </div>
        <p className="mt-4">Listening for unidirectional traffic...</p>
      </div>
    );
  }

  // Proper SOC IP Masking (Masks only the last octet)
  const maskIp = (ip: string) => {
    const parts = ip.split('.');
    if (parts.length === 4) {
      return `${parts[0]}.${parts[1]}.${parts[2]}.***`;
    }
    return ip;
  };

  return (
    <div className="flex flex-col h-full">
      <div className="flex justify-between items-center px-4 py-2 border-b border-gray-800/50 bg-gray-900 group relative">
        <div className="flex items-center gap-2 text-xs text-gray-400 font-mono cursor-help">
          <Info size={14} className="text-gray-500" />
          Live Replay Engine (Pre-Deployment Validation)
        </div>
        <div className="absolute top-10 left-4 w-72 p-3 bg-gray-800 border border-gray-700 rounded-md text-xs text-gray-300 shadow-xl opacity-0 group-hover:opacity-100 pointer-events-none transition-opacity z-50">
          <strong>Why simulated data?</strong><br />
          Direct live connection to hardware data-diodes is not feasible in the hackathon environment. This engine simulates realistic unidirectional flow vectors (PCAP proxy) to validate the ML pipeline.
        </div>
      </div>
      
      <div className="overflow-auto flex-1 pr-2">
        <table className="w-full text-sm text-left">
          <thead className="text-xs text-gray-400 uppercase bg-gray-800/50 sticky top-0 z-10">
            <tr>
              <th className="px-4 py-3">Time</th>
              <th className="px-4 py-3">Source IP</th>
              <th className="px-4 py-3">Dest Port</th>
              <th className="px-4 py-3">Protocol</th>
              <th className="px-4 py-3">Size (B)</th>
              <th className="px-4 py-3">Confidence</th>
              <th className="px-4 py-3">Severity</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800/50">
            {alerts.map((alert) => {
              const { severity, threat_score } = alert.analysis;
              
              let rowClass = 'hover:bg-gray-800/50 cursor-pointer transition-colors';
              if (alert.id === selectedId) {
                rowClass += ' bg-gray-800/80 ring-1 ring-inset ring-gray-600';
              }
              if (severity === 'CRITICAL') rowClass += ' border-l-2 border-threat-red';
              else if (severity === 'MEDIUM' || severity === 'LOW') rowClass += ' border-l-2 border-threat-amber';
              else rowClass += ' border-l-2 border-transparent';

              return (
                <tr
                  key={alert.id}
                  className={rowClass}
                  onClick={() => onSelectRow(alert)}
                >
                  <td className="px-4 py-3 text-gray-400 font-mono text-xs whitespace-nowrap">
                    {alert.packet.timestamp_formatted}
                  </td>
                  <td className="px-4 py-3 font-mono">{maskIp(alert.packet.source_ip)}</td>
                  <td className="px-4 py-3 font-mono">{alert.packet.dest_port}</td>
                  <td className="px-4 py-3">
                    <span className="text-xs">{alert.packet.protocol} {alert.packet.flags !== '-' && <span className="text-gray-500">[{alert.packet.flags}]</span>}</span>
                  </td>
                  <td className="px-4 py-3 font-mono">{alert.packet.packet_size}</td>
                  <td className="px-4 py-3 font-mono text-xs">{(threat_score * 100).toFixed(1)}%</td>
                  <td className="px-4 py-3">
                    {severity === 'CRITICAL' && <span className="inline-flex items-center gap-1.5 px-2 py-1 rounded-sm bg-threat-red/10 text-threat-red border border-threat-red/20 text-xs"><AlertTriangle size={12} /> Critical</span>}
                    {severity === 'MEDIUM' && <span className="inline-flex items-center gap-1.5 px-2 py-1 rounded-sm bg-orange-500/10 text-orange-500 border border-orange-500/20 text-xs"><AlertTriangle size={12} /> High</span>}
                    {severity === 'LOW' && <span className="inline-flex items-center gap-1.5 px-2 py-1 rounded-sm bg-threat-amber/10 text-threat-amber border border-threat-amber/20 text-xs"><HelpCircle size={12} /> Suspicious</span>}
                    {severity === 'LOG_ONLY' && <span className="inline-flex items-center gap-1.5 px-2 py-1 rounded-sm bg-signal-teal/10 text-signal-teal border border-signal-teal/20 text-xs"><ShieldCheck size={12} /> Safe</span>}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
