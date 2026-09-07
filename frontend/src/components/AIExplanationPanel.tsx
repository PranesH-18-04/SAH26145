import { useState, useEffect } from 'react';
import { Alert } from '../hooks/useWebSocket';
import { ShieldAlert, Info, TrendingDown, Target, Activity, Sparkles, Loader2 } from 'lucide-react';

interface Props {
  alert: Alert | null;
}

export default function AIExplanationPanel({ alert }: Props) {
  const [insightData, setInsightData] = useState<{insight: string, action: string, source: string} | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    if (!alert) return;
    setIsLoading(true);
    setInsightData(null);
    
    const apiUrl = (import.meta.env.VITE_API_URL || '').replace(/^ws/, "http");
    
    fetch(`${apiUrl}/api/v1/alerts/${alert.id}/insight`)
      .then(res => {
        if (!res.ok) throw new Error("API response not ok");
        return res.json();
      })
      .then(data => {
        setInsightData(data);
      })
      .catch(err => {
        console.error("Failed to fetch insight", err);
        setInsightData({
          insight: alert.analysis.explanation,
          action: "Investigate source IP and review traffic logs.",
          source: "rule-based"
        });
      })
      .finally(() => {
        setIsLoading(false);
      });
  }, [alert?.id]);

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

        {/* Confidence Decay Tracker Badge */}
        {analysis.decay_factor < 1.0 && (
          <div className="bg-gray-800/50 p-3 rounded border border-gray-700 flex flex-col gap-2">
            <h4 className="text-xs font-semibold text-gray-400">Exponential Frequency Decay Applied</h4>
            <div className="flex justify-between items-center text-xs">
              <span className="text-gray-400">Raw Model Confidence:</span>
              <span className="text-gray-200 font-mono">{(analysis.raw_threat_score * 100).toFixed(1)}%</span>
            </div>
            <div className="flex justify-between items-center text-xs">
              <span className="text-gray-400">Decayed Confidence (Occurrence #{analysis.occurrence_count}):</span>
              <span className="text-signal-teal font-bold font-mono">{(analysis.threat_score * 100).toFixed(1)}%</span>
            </div>
          </div>
        )}

        {/* Natural Language Explanation (Gemini) */}
        <div>
          <div className="flex justify-between items-end mb-2">
            <h4 className="text-sm font-semibold text-gray-300">Analysis Rationale</h4>
            {insightData?.source === 'gemini' && (
               <span className="text-[10px] uppercase font-semibold text-purple-400 bg-purple-900/30 border border-purple-500/30 px-2 py-0.5 rounded flex items-center gap-1">
                 <Sparkles size={10} /> Gemini Enriched
               </span>
            )}
            {insightData?.source === 'rule-based' && (
               <span className="text-[10px] uppercase font-semibold text-gray-400 bg-gray-800/50 border border-gray-700 px-2 py-0.5 rounded">
                 Rule-Based
               </span>
            )}
          </div>
          
          <div className="text-sm text-gray-400 leading-relaxed bg-gray-800/20 p-3 rounded border border-gray-800/50 whitespace-pre-wrap relative min-h-[80px]">
            {isLoading ? (
              <div className="absolute inset-0 flex items-center justify-center">
                <Loader2 size={24} className="text-signal-teal animate-spin" />
              </div>
            ) : insightData ? (
              <div className="space-y-3">
                <p>{insightData.insight}</p>
                {insightData.action && (
                  <div className="pt-2 border-t border-gray-700/50">
                    <span className="text-gray-300 font-semibold block mb-1">Recommended Action:</span>
                    <span className="text-threat-amber">{insightData.action}</span>
                  </div>
                )}
              </div>
            ) : (
              <p>{analysis.explanation}</p>
            )}
          </div>
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
