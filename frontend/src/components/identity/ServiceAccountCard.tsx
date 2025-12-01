'use client';

import React from 'react';
import { BioCard, BioCardContent } from '@/components/ui/BioCard';
import { Bot, Key, Activity, AlertTriangle } from 'lucide-react';

interface ServiceAccountCardProps {
    name: string;
    status: 'healthy' | 'warning' | 'critical';
    keyAge: number;
    lastActive: string;
    anomalyScore: number;
}

export function ServiceAccountCard({ name, status, keyAge, lastActive, anomalyScore }: ServiceAccountCardProps) {
    return (
        <BioCard className="group hover:bg-white/5 transition-colors" hoverEffect={true} variant={status === 'healthy' ? 'glass' : 'alert'}>
            <BioCardContent className="p-4">
                <div className="flex justify-between items-start mb-4">
                    <div className="flex items-center gap-3">
                        <div className={`p-2 rounded-lg ${status === 'healthy' ? 'bg-bio-green/10 text-bio-green' : 'bg-bio-red/10 text-bio-red'}`}>
                            <Bot size={20} />
                        </div>
                        <div>
                            <div className="font-bold text-white text-sm">{name}</div>
                            <div className="text-xs text-text-muted font-fira-code">ID: svc-{Math.floor(Math.random() * 1000)}</div>
                        </div>
                    </div>
                    {anomalyScore > 50 && (
                        <div className="animate-pulse text-bio-red">
                            <AlertTriangle size={16} />
                        </div>
                    )}
                </div>

                <div className="space-y-3">
                    <div>
                        <div className="flex justify-between text-xs mb-1">
                            <span className="text-text-secondary">Key Age</span>
                            <span className={`font-fira-code ${keyAge > 80 ? 'text-bio-red' : 'text-bio-green'}`}>{keyAge} days</span>
                        </div>
                        <div className="h-1 bg-white/10 rounded-full overflow-hidden">
                            <div
                                className={`h-full rounded-full ${keyAge > 80 ? 'bg-bio-red' : 'bg-bio-green'}`}
                                style={{ width: `${Math.min((keyAge / 90) * 100, 100)}%` }}
                            />
                        </div>
                    </div>

                    <div className="flex justify-between items-center pt-2 border-t border-white/5">
                        <div className="flex items-center gap-1 text-xs text-text-muted">
                            <Activity size={12} />
                            <span>{lastActive}</span>
                        </div>
                        <div className="text-xs font-bold text-neural-purple">
                            Score: {anomalyScore}
                        </div>
                    </div>
                </div>
            </BioCardContent>
        </BioCard>
    );
}
