import { Shield, ShieldCheck, ShieldAlert } from 'lucide-react';
import { SafetyMode } from '../types';

interface SafetyModeSelectorProps {
  mode: SafetyMode;
  onModeChange: (mode: SafetyMode) => void;
}

const modes = [
  {
    id: 'strict' as SafetyMode,
    name: 'Strict',
    description: 'Approve all high-risk actions',
    icon: ShieldAlert,
    color: '#ef4444',
  },
  {
    id: 'balanced' as SafetyMode,
    name: 'Balanced',
    description: 'Recommended for most users',
    icon: Shield,
    color: '#3b82f6',
  },
  {
    id: 'permissive' as SafetyMode,
    name: 'Permissive',
    description: 'Trust known agents',
    icon: ShieldCheck,
    color: '#22c55e',
  },
];

export default function SafetyModeSelector({ mode, onModeChange }: SafetyModeSelectorProps) {
  return (
    <div className="safety-mode">
      <h4>Safety Mode</h4>
      <div className="mode-options">
        {modes.map((m) => (
          <div
            key={m.id}
            className={`mode-option ${mode === m.id ? 'selected' : ''}`}
            onClick={() => onModeChange(m.id)}
          >
            <div className="mode-radio" />
            <div className="mode-info">
              <h5 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <m.icon size={14} color={m.color} />
                {m.name}
              </h5>
              <p>{m.description}</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
