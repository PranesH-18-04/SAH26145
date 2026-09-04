import { Alert } from '../hooks/useWebSocket';
import { TrendingDown } from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';

interface Props {
  alerts: Alert[];
}

export default function ConfidenceDecayTracker({ alerts }: Props) {
  // Find the signature with the most occurrences that has triggered decay
  const decayAlerts = alerts.filter(a => a.analysis.decay_factor < 1.0);
  
  if (decayAlerts.length === 0) {
    return (
      <div className="glass-panel p-4 h-[250px] flex flex-col justify-center items-center text-gray-500">
        <TrendingDown size={24} className="mb-2 opacity-50" />
        <p className="text-sm">No repeated anomaly signatures detected yet.</p>
        <p className="text-xs mt-1">Waiting for repeated benign events...</p>
      </div>
    );
  }

  // Get the most frequent signature
  const signatureCounts = decayAlerts.reduce((acc, curr) => {
    acc[curr.analysis.signature] = (acc[curr.analysis.signature] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);
  
  const topSignature = Object.keys(signatureCounts).reduce((a, b) => signatureCounts[a] > signatureCounts[b] ? a : b);
  
  // Extract the history for this signature
  const history = alerts
    .filter(a => a.analysis.signature === topSignature)
    .sort((a, b) => a.packet.timestamp_epoch - b.packet.timestamp_epoch);

  const chartData = history.map(a => ({
    occurrence: a.analysis.occurrence_count,
    rawConfidence: Number((a.analysis.raw_threat_score * 100).toFixed(1)),
    decayedConfidence: Number((a.analysis.threat_score * 100).toFixed(1))
  }));

  return (
    <div className="glass-panel p-4 h-[250px] flex flex-col">
      <h2 className="text-lg font-semibold mb-2 flex items-center gap-2 text-gray-200">
        <TrendingDown size={18} className="text-signal-teal" />
        Confidence Decay Tracker
      </h2>
      <div className="text-xs text-gray-400 mb-4 font-mono truncate" title={topSignature}>
        Tracking Signature: {topSignature}
      </div>
      
      <div className="flex-1 min-h-0">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={chartData} margin={{ top: 5, right: 5, left: -20, bottom: 0 }}>
            <XAxis dataKey="occurrence" stroke="#4b5563" fontSize={10} tickFormatter={(val) => `#${val}`} />
            <YAxis stroke="#4b5563" fontSize={10} domain={[0, 100]} tickFormatter={(val) => `${val}%`} />
            <Tooltip 
              contentStyle={{ backgroundColor: '#111827', borderColor: '#374151', fontSize: '12px' }}
              labelFormatter={(label) => `Occurrence #${label}`}
            />
            <Line type="monotone" dataKey="rawConfidence" name="Raw Base Score" stroke="#9ca3af" strokeDasharray="3 3" strokeWidth={2} dot={false} />
            <Line type="monotone" dataKey="decayedConfidence" name="Decayed Final Score" stroke="#0d9488" strokeWidth={2} activeDot={{ r: 4 }} />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
