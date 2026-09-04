import { Alert } from '../hooks/useWebSocket';
import { ShieldAlert, Info, TrendingDown, Target, Activity } from 'lucide-react';

interface Props {
  alert: Alert | null;
}

export default function AIExplanationPanel({ alert }: Props) {
  if (!alert) {
    return (
      <div className="h-full flex flex-col items-center justify-center text-gray-500 bg-gray-900/50 rounded-lg border border-gray-800">
        <Target className="mb-4 opacity-50" size={48} />
        <p>Select a packet to view AI explanation</p>
      </div>
    );
  }

  const { analysis, packet } = alert;
  const isMalicious = analysis.severity === 'CRITICAL';
  const isSuspicious = analysis.severity === 'MEDIUM' || analysis.severity === 'LOW';

  return (
    <div className="h-full flex flex-col bg-gray-900/50 rounded-lg border border-gray-800 overflow-hidden">
      <div className="p-4 border-b border-gray-800 bg-gray-800/20">
        <h3 className="font-semibold flex items-center gap-2">
          <Activity size={18} className="text-signal-teal" />
          AI Insight & Explainability
        </h3>
        <p className="text-xs text-gray-400 mt-1">Model: {analysis.model_used}</p>
      </div>

      <div className="p-4 flex-1 overflow-auto space-y-6">
        
        {/* Threat Score Card */}
        <div className={`p-4 rounded-lg border ${isMalicious ? 'bg-threat-red/5 border-threat-red/20' : isSuspicious ? 'bg-threat-amber/5 border-threat-amber/20' : 'bg-signal-teal/5 border-signal-teal/20'}`}>
          <div className="flex justify-between items-start mb-2">
            <div>
              <div className="text-sm text-gray-400 uppercase tracking-wider mb-1">Threat Confidence</div>
              <div className="text-3xl font-mono font-semibold">
                {(analysis.threat_score * 100).toFixed(1)}%
              </div>
            </div>
            {(isMalicious || isSuspicious) ? (
              <ShieldAlert size={32} className={isMalicious ? 'text-threat-red' : 'text-threat-amber'} />
            ) : (
              <Info size={32} className="text-signal-teal" />
            )}
          </div>
          <div className="text-sm mt-3 pt-3 border-t border-gray-800/50">
            <span className="text-gray-400">Classification: </span>
            <span className="font-medium text-gray-200">
              {analysis.threat_type || 'Benign Baseline Traffic'}
            </span>
          </div>
        </div>

        {/* Feature Contributions (SHAP) */}
        {analysis.feature_contributions && analysis.feature_contributions.length > 0 && (
          <div>
            <h4 className="text-sm font-semibold text-gray-300 mb-3 flex items-center gap-2">
              <TrendingDown size={16} /> Key Feature Contributions
            </h4>
            <div className="space-y-3">
              {analysis.feature_contributions.map((feature, idx) => (
                <div key={idx} className="bg-gray-800/30 p-3 rounded border border-gray-700/50">
                  <div className="flex justify-between items-center mb-1">
                    <span className="text-sm font-medium">{feature.feature_name}</span>
                    <span className="text-xs font-mono px-2 py-0.5 rounded bg-threat-red/10 text-threat-red">
                      +{(feature.contribution_score * 100).toFixed(0)}%
                    </span>
                  </div>
                  <p className="text-xs text-gray-400">{feature.description}</p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Natural Language Explanation */}
        <div>
          <h4 className="text-sm font-semibold text-gray-300 mb-2">Analysis Rationale</h4>
          <p className="text-sm text-gray-400 leading-relaxed bg-gray-800/20 p-3 rounded border border-gray-800/50">
            {analysis.explanation}
          </p>
        </div>

        {/* Packet Details */}
        <div>
          <h4 className="text-sm font-semibold text-gray-300 mb-2">Raw Extracted Features</h4>
          <div className="grid grid-cols-2 gap-2 text-sm">
            <div className="bg-gray-800/30 p-2 rounded">
              <span className="text-gray-500 block text-xs mb-1">Protocol</span>
              <span className="font-mono">{packet.protocol} {packet.flags !== '-' && `[${packet.flags}]`}</span>
            </div>
            <div className="bg-gray-800/30 p-2 rounded">
              <span className="text-gray-500 block text-xs mb-1">Dest Port</span>
              <span className="font-mono">{packet.dest_port}</span>
            </div>
            <div className="bg-gray-800/30 p-2 rounded">
              <span className="text-gray-500 block text-xs mb-1">Size</span>
              <span className="font-mono">{packet.packet_size} B</span>
            </div>
            <div className="bg-gray-800/30 p-2 rounded">
              <span className="text-gray-500 block text-xs mb-1">Duration</span>
              <span className="font-mono">{packet.flow_duration.toFixed(3)}s</span>
            </div>
          </div>
        </div>

      </div>
    </div>
  );
}
