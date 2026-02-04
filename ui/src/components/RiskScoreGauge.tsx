import { CheckCircle, AlertCircle, AlertTriangle } from 'lucide-react';

interface RiskScoreGaugeProps {
  score: number;
  confidence?: number;
  size?: 'sm' | 'md' | 'lg';
}

export default function RiskScoreGauge({ score, confidence = 85, size = 'md' }: RiskScoreGaugeProps) {
  const sizes = {
    sm: { width: 80, stroke: 6, fontSize: 16 },
    md: { width: 100, stroke: 8, fontSize: 20 },
    lg: { width: 120, stroke: 10, fontSize: 26 },
  };

  const config = sizes[size];
  const radius = (config.width - config.stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  const progress = (score / 100) * circumference;

  const getColor = (value: number) => {
    if (value >= 70) return '#ef4444';
    if (value >= 50) return '#f97316';
    if (value >= 30) return '#eab308';
    return '#10b981';
  };

  const getLevel = (value: number) => {
    if (value >= 70) return { text: 'High', icon: AlertCircle };
    if (value >= 50) return { text: 'Medium', icon: AlertTriangle };
    if (value >= 30) return { text: 'Moderate', icon: AlertTriangle };
    return { text: 'Low', icon: CheckCircle };
  };

  const color = getColor(score);
  const level = getLevel(score);
  const Icon = level.icon;

  return (
    <div className="risk-gauge-container">
      <svg width={config.width} height={config.width} viewBox={`0 0 ${config.width} ${config.width}`}>
        {/* Background circle */}
        <circle
          cx={config.width / 2}
          cy={config.width / 2}
          r={radius}
          fill="none"
          stroke="var(--border-color)"
          strokeWidth={config.stroke}
        />
        {/* Progress arc */}
        <circle
          cx={config.width / 2}
          cy={config.width / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={config.stroke}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={circumference - progress}
          transform={`rotate(-90 ${config.width / 2} ${config.width / 2})`}
          style={{ transition: 'stroke-dashoffset 0.6s ease-out' }}
        />
        {/* Center text */}
        <text
          x="50%"
          y="50%"
          textAnchor="middle"
          dominantBaseline="middle"
          fill={color}
          fontSize={config.fontSize}
          fontWeight="700"
        >
          {score}
        </text>
      </svg>

      <span
        className="risk-gauge-label"
        style={{ background: `${color}18`, color }}
      >
        <Icon size={10} />
        {level.text} Risk
      </span>

      {confidence > 0 && (
        <span className="risk-gauge-confidence">
          {confidence.toFixed(0)}% confidence
        </span>
      )}
    </div>
  );
}
