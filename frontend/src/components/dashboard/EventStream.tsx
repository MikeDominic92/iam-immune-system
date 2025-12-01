'use client';

import React from 'react';
import { BioCard, BioCardHeader, BioCardTitle, BioCardContent } from '@/components/ui/BioCard';
import { PulseIndicator } from '@/components/ui/PulseIndicator';

const events = [
    { id: 'EVT-001', time: '10:42:05', type: 'AUTH_SUCCESS', source: 'User: j.doe', status: 'healthy' },
    { id: 'EVT-002', time: '10:42:01', type: 'API_CALL', source: 'Svc: billing-bot', status: 'neural' },
    { id: 'EVT-003', time: '10:41:55', type: 'ANOMALY_DETECT', source: 'IP: 192.168.1.x', status: 'warning' },
    { id: 'EVT-004', time: '10:41:42', type: 'AUTO_BLOCK', source: 'Threat: Brute Force', status: 'critical' },
    { id: 'EVT-005', time: '10:41:30', type: 'KEY_ROTATION', source: 'Key: Azure-KV-01', status: 'healthy' },
];

export function EventStream() {
    return (
        <BioCard className="h-full font-fira-code text-sm">
            <BioCardHeader className="border-b border-white/5 bg-void-obsidian/80 flex justify-between items-center">
                <BioCardTitle>LIVE_EVENT_STREAM</BioCardTitle>
                <div className="flex items-center space-x-2">
                    <span className="w-2 h-2 bg-bio-green rounded-full animate-pulse"></span>
                    <span className="text-xs text-bio-green">RECEIVING</span>
                </div>
            </BioCardHeader>
            <BioCardContent className="p-0">
                <div className="h-[250px] overflow-y-auto p-4 space-y-1 scrollbar-thin scrollbar-thumb-white/10 scrollbar-track-transparent">
                    {events.map((evt) => (
                        <div key={evt.id} className="flex items-center space-x-4 p-2 hover:bg-white/5 rounded transition-colors group border-l-2 border-transparent hover:border-bio-green/50">
                            <span className="text-text-muted text-xs w-16">{evt.time}</span>
                            <PulseIndicator status={evt.status as any} animate={false} className="shrink-0" />
                            <div className="flex-1 flex justify-between">
                                <span className={`font-bold ${evt.status === 'healthy' ? 'text-bio-green' :
                                        evt.status === 'warning' ? 'text-amber-pulse' :
                                            evt.status === 'critical' ? 'text-bio-red' :
                                                'text-neural-purple'
                                    }`}>{evt.type}</span>
                                <span className="text-text-secondary text-xs group-hover:text-white transition-colors">{evt.source}</span>
                            </div>
                        </div>
                    ))}
                    <div className="text-xs text-text-muted mt-2 animate-pulse">_ Awaiting new signals...</div>
                </div>
            </BioCardContent>
        </BioCard>
    );
}
