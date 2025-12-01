'use client';

import React from 'react';
import { BioCard, BioCardContent } from '@/components/ui/BioCard';
import { Activity, Shield, Zap, Database } from 'lucide-react';

const vitals = [
    { label: 'Identity Health', value: '98%', icon: Activity, color: 'text-bio-green', status: 'Optimal' },
    { label: 'Threat Shield', value: 'ACTIVE', icon: Shield, color: 'text-deep-teal', status: 'Enforcing' },
    { label: 'Auto-Response', value: 'READY', icon: Zap, color: 'text-neural-purple', status: 'Standby' },
    { label: 'Data Integrity', value: '100%', icon: Database, color: 'text-bio-green', status: 'Verified' },
];

export function HealthVitals() {
    return (
        <div className="grid grid-cols-2 gap-4 h-full">
            {vitals.map((vital) => (
                <BioCard key={vital.label} className="flex flex-col justify-center group">
                    <BioCardContent>
                        <div className="flex justify-between items-start mb-4">
                            <div className={`p-2 rounded-lg bg-void-black border border-white/10 ${vital.color} group-hover:shadow-glow-bio transition-all`}>
                                <vital.icon size={20} />
                            </div>
                            <div className="text-xs font-fira-code text-text-muted uppercase">{vital.status}</div>
                        </div>
                        <div className="text-2xl font-bold text-white font-space-grotesk tracking-tight">{vital.value}</div>
                        <div className="text-xs text-text-secondary uppercase tracking-wider mt-1">{vital.label}</div>

                        {/* Heartbeat Line */}
                        <div className="w-full h-1 bg-white/5 mt-4 rounded-full overflow-hidden">
                            <div className="h-full w-1/3 bg-gradient-to-r from-transparent via-bio-green to-transparent animate-flow" />
                        </div>
                    </BioCardContent>
                </BioCard>
            ))}
        </div>
    );
}
