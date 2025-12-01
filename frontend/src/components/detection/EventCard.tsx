'use client';

import React from 'react';
import { BioCard, BioCardContent } from '@/components/ui/BioCard';
import { AlertTriangle, Shield, User, Globe, Clock } from 'lucide-react';
import { PulseIndicator } from '@/components/ui/PulseIndicator';

interface EventCardProps {
    type: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    source: string;
    target: string;
    time: string;
    confidence: number;
}

export function EventCard({ type, severity, source, target, time, confidence }: EventCardProps) {
    const severityColor =
        severity === 'critical' ? 'text-bio-red border-bio-red/30 bg-bio-red/5' :
            severity === 'high' ? 'text-amber-pulse border-amber-pulse/30 bg-amber-pulse/5' :
                severity === 'medium' ? 'text-neural-purple border-neural-purple/30 bg-neural-purple/5' :
                    'text-bio-green border-bio-green/30 bg-bio-green/5';

    return (
        <BioCard className="group cursor-pointer hover:bg-white/5 transition-colors" hoverEffect={true}>
            <BioCardContent className="p-4">
                <div className="flex justify-between items-start mb-3">
                    <div className={`px-2 py-1 rounded text-xs font-bold uppercase border ${severityColor} flex items-center gap-2`}>
                        <AlertTriangle size={12} />
                        {severity}
                    </div>
                    <div className="text-xs text-text-muted font-fira-code">{time}</div>
                </div>

                <h4 className="text-lg font-bold text-white mb-4 group-hover:text-glow transition-all">{type}</h4>

                <div className="space-y-2 text-sm text-text-secondary">
                    <div className="flex items-center gap-2">
                        <Globe size={14} className="text-text-muted" />
                        <span className="font-fira-code text-xs">SRC: {source}</span>
                    </div>
                    <div className="flex items-center gap-2">
                        <User size={14} className="text-text-muted" />
                        <span className="font-fira-code text-xs">TGT: {target}</span>
                    </div>
                </div>

                <div className="mt-4 pt-4 border-t border-white/5 flex justify-between items-center">
                    <div className="flex items-center gap-2">
                        <div className="text-xs text-text-muted uppercase">AI Confidence</div>
                        <div className="h-1 w-16 bg-white/10 rounded-full overflow-hidden">
                            <div
                                className="h-full bg-neural-purple"
                                style={{ width: `${confidence}%` }}
                            />
                        </div>
                    </div>
                    <div className="text-neural-purple font-bold text-xs">{confidence}%</div>
                </div>
            </BioCardContent>
        </BioCard>
    );
}
