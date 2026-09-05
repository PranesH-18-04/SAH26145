import { useState } from 'react';
import { Activity, ShieldAlert } from 'lucide-react';
import { useWebSocket, Alert } from '../hooks/useWebSocket';
import LiveTrafficTable from './LiveTrafficTable';
import AIExplanationPanel from './AIExplanationPanel';
import AnalyticsCharts from './AnalyticsCharts';
import ModelPerformancePanel from './ModelPerformancePanel';
import ConfidenceDecayTracker from './ConfidenceDecayTracker';

export default function Dashboard() {
  const wsUrl = import.meta.env.VITE_API_URL.replace(/^http/, "ws");
<<<<<<< HEAD
  const httpUrl = import.meta.env.VITE_API_URL.replace(/^ws/, "http");
  const { alerts, isConnected } = useWebSocket(`${wsUrl}/ws/traffic`, httpUrl);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);

  // Statistics
  const totalAnalyzed = alerts.length;
  const maliciousCount = alerts.filter(a => a.analysis.category === 'Malicious').length;
  const suspiciousCount = alerts.filter(a => a.analysis.category === 'Suspicious').length;

  return (
    <div className="space-y-6">
      {/* Top Stats Row */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <StatCard
          icon={<Activity className="text-signal-teal" />}
          label="Packets Analyzed (Session)"
          value={totalAnalyzed.toLocaleString()}
          color="border-signal-teal/50"
        />
        <StatCard
          icon={<ShieldAlert className={maliciousCount > 0 ? "text-threat-red animate-pulse" : "text-gray-600"} />}
          label="Malicious Flows"
          value={maliciousCount.toLocaleString()}
          color={maliciousCount > 0 ? "border-threat-red" : "border-gray-800"}
        />
        <StatCard
          icon={<ShieldAlert className={suspiciousCount > 0 ? "text-threat-amber" : "text-gray-600"} />}
          label="Suspicious Flows"
          value={suspiciousCount.toLocaleString()}
          color={suspiciousCount > 0 ? "border-threat-amber" : "border-gray-800"}
        />
        <div className="glass-panel p-4 flex flex-col justify-center border-l-4 border-gray-600 gap-2">
          <div className="text-xs text-gray-400 font-mono mb-1">Simulate Attack (Demo)</div>
          <div className="flex gap-2">
            <button onClick={() => fetch(`${wsUrl.replace('ws', 'http')}/api/v1/traffic/simulate`, { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({attack_type: 'DDoS'}) })} className="flex-1 text-[10px] bg-gray-800 hover:bg-threat-red/20 border border-gray-700 rounded py-1 transition-colors">DDoS</button>
            <button onClick={() => fetch(`${wsUrl.replace('ws', 'http')}/api/v1/traffic/simulate`, { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({attack_type: 'Exfiltration'}) })} className="flex-1 text-[10px] bg-gray-800 hover:bg-threat-red/20 border border-gray-700 rounded py-1 transition-colors">Exfil</button>
            <button onClick={() => fetch(`${wsUrl.replace('ws', 'http')}/api/v1/traffic/simulate`, { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({attack_type: 'Tunneling'}) })} className="flex-1 text-[10px] bg-gray-800 hover:bg-threat-red/20 border border-gray-700 rounded py-1 transition-colors">Tunnel</button>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Live Traffic (2/3 width) */}
        <div className="lg:col-span-2 space-y-6">
          <div className="glass-panel p-4 h-[400px] flex flex-col">
            <h2 className="text-lg font-semibold mb-4 flex items-center gap-2 font-mono uppercase tracking-wider text-gray-300">
              <span className={`w-2 h-2 rounded-full ${isConnected ? 'bg-signal-teal animate-pulse' : 'bg-threat-red'}`}></span>
              Live Traffic Stream
            </h2>
            <div className="flex-1 overflow-hidden">
              <LiveTrafficTable
                alerts={alerts}
                onSelectRow={setSelectedAlert}
                selectedId={selectedAlert?.id}
              />
            </div>
          </div>

          <div className="glass-panel p-4 h-[300px]">
            <h2 className="text-lg font-semibold mb-4">Traffic Anomaly Distribution</h2>
            <AnalyticsCharts alerts={alerts} />
          </div>
        </div>

        {/* Right Column: AI Explainability & Models (1/3 width) */}
        <div className="lg:col-span-1 space-y-6">
          <div className="glass-panel p-4 min-h-[400px]">
            <h2 className="text-lg font-semibold mb-4">AI Insight & Explainability</h2>
            <AIExplanationPanel alert={selectedAlert} />
          </div>
          <ConfidenceDecayTracker alerts={alerts} />
          <ModelPerformancePanel />
        </div>
      </div>
    </div>
  );
}

function StatCard({ icon, label, value, color }: { icon: React.ReactNode, label: string, value: string, color: string }) {
  return (
    <div className={`glass-panel p-4 flex items-center gap-4 border-l-4 ${color}`}>
      <div className="p-3 bg-gray-800/50 rounded-lg">
        {icon}
      </div>
      <div>
        <div className="text-sm text-gray-400">{label}</div>
        <div className="text-2xl font-bold">{value}</div>
      </div>
    </div>
  );
}
