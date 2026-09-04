import { Alert } from '../hooks/useWebSocket';
import { AlertTriangle, ShieldCheck, HelpCircle, Eye, EyeOff } from 'lucide-react';
import { useState } from 'react';

interface Props {
  alerts: Alert[];
  onSelectRow: (alert: Alert) => void;
  selectedId?: string;
}

export default function LiveTrafficTable({ alerts, onSelectRow, selectedId }: Props) {
  const [isAdmin, setIsAdmin] = useState(false);

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

  const maskIp = (ip: string) => {
    if (isAdmin) return ip;
    const parts = ip.split('.');
    if (parts.length === 4) {
      return `${parts[0]}.${parts[1]}.${parts[2]}.***`;
    }
    return ip;
  };

  return (
    <div className="flex flex-col h-full">
      <div className="flex justify-between items-center px-4 py-2 border-b border-gray-800/50 bg-gray-900">
        <div className="text-xs text-gray-400 font-mono">
          Data Source: Synthetic Simulation Engine v1
        </div>
        <button
          onClick={() => setIsAdmin(!isAdmin)}
          className="flex items-center gap-2 px-3 py-1 text-xs rounded-md bg-gray-800 hover:bg-gray-700 transition-colors border border-gray-700"
          title="Toggle Demo Mode: Admin/Viewer (Masks IPs)"
        >
          {isAdmin ? <Eye size={14} className="text-signal-teal" /> : <EyeOff size={14} className="text-gray-400" />}
          <span>{isAdmin ? 'Role: Admin' : 'Role: Viewer'}</span>
        </button>
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
              <th className="px-4 py-3">Severity</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800/50">
            {alerts.map((alert) => {
              const { severity } = alert.analysis;
              
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
                  <td className="px-4 py-3">
                    {severity === 'CRITICAL' && <span className="inline-flex items-center gap-1.5 px-2 py-1 rounded-sm bg-threat-red/10 text-threat-red border border-threat-red/20 text-xs"><AlertTriangle size={12} /> Critical (&gt;90%)</span>}
                    {severity === 'MEDIUM' && <span className="inline-flex items-center gap-1.5 px-2 py-1 rounded-sm bg-orange-500/10 text-orange-500 border border-orange-500/20 text-xs"><AlertTriangle size={12} /> High (75-90%)</span>}
                    {severity === 'LOW' && <span className="inline-flex items-center gap-1.5 px-2 py-1 rounded-sm bg-threat-amber/10 text-threat-amber border border-threat-amber/20 text-xs"><HelpCircle size={12} /> Suspicious (50-75%)</span>}
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
