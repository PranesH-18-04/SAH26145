import { Target } from 'lucide-react';

export default function ModelPerformancePanel() {
  return (
    <div className="glass-panel p-4 h-[300px] flex flex-col overflow-y-auto">
      <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
        <Target size={18} className="text-signal-teal" />
        Offline Model Validation Metrics
      </h2>
      
      <div className="grid grid-cols-3 gap-4 mb-4">
        <div className="bg-gray-800/50 p-3 rounded text-center border border-gray-700">
          <div className="text-xs text-gray-400">Precision</div>
          <div className="text-xl font-bold text-gray-200">90.2%</div>
        </div>
        <div className="bg-gray-800/50 p-3 rounded text-center border border-gray-700">
          <div className="text-xs text-gray-400">Recall</div>
          <div className="text-xl font-bold text-gray-200">90.3%</div>
        </div>
        <div className="bg-gray-800/50 p-3 rounded text-center border border-gray-700">
          <div className="text-xs text-gray-400">F1-Score</div>
          <div className="text-xl font-bold text-gray-200">0.9021</div>
        </div>
      </div>

      <div className="mb-2 text-sm font-semibold text-gray-300">Confusion Matrix</div>
      <div className="bg-gray-900 border border-gray-800 rounded p-2 overflow-x-auto text-xs">
        <table className="w-full text-center">
          <thead>
            <tr className="text-gray-500 border-b border-gray-800">
              <th className="text-left font-normal py-1">Actual \ Pred</th>
              <th className="font-normal">Safe</th>
              <th className="font-normal">DDoS</th>
              <th className="font-normal">Exfil</th>
              <th className="font-normal">Tunnel</th>
            </tr>
          </thead>
          <tbody className="text-gray-300">
            <tr><td className="text-left text-gray-500">Safe</td><td className="text-signal-teal font-bold bg-signal-teal/10">1133</td><td>37</td><td>8</td><td>20</td></tr>
            <tr><td className="text-left text-gray-500">DDoS</td><td>47</td><td className="text-signal-teal font-bold bg-signal-teal/10">367</td><td>0</td><td>1</td></tr>
            <tr><td className="text-left text-gray-500">Exfil</td><td>17</td><td>1</td><td className="text-signal-teal font-bold bg-signal-teal/10">180</td><td>14</td></tr>
            <tr><td className="text-left text-gray-500">Tunnel</td><td>47</td><td>0</td><td>2</td><td className="text-signal-teal font-bold bg-signal-teal/10">126</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  );
}
