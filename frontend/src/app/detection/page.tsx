'use client';

import React from 'react';
import { ImmuneShell } from '@/components/layout/ImmuneShell';
import { EventCard } from '@/components/detection/EventCard';
import { NeuralNetworkViz } from '@/components/detection/NeuralNetworkViz';
import { BioCard, BioCardHeader, BioCardTitle, BioCardContent } from '@/components/ui/BioCard';
import { NeuralButton } from '@/components/ui/NeuralButton';
import { Filter, ThumbsUp, ThumbsDown } from 'lucide-react';

const detectionEvents = [
    { type: 'Abnormal Data Exfiltration', severity: 'critical', source: 'User: a.smith', target: 'S3: confidential-fin', time: '10:45:22', confidence: 98 },
    { type: 'Impossible Travel', severity: 'high', source: 'IP: 45.2.x.x (Russia)', target: 'Auth: Azure AD', time: '10:44:15', confidence: 92 },
    { type: 'Privilege Escalation Attempt', severity: 'medium', source: 'Svc: backup-daemon', target: 'Role: Domain Admin', time: '10:30:05', confidence: 85 },
    { type: 'New Device Enrollment', severity: 'low', source: 'Device: iPhone 15', target: 'User: m.jones', time: '10:15:00', confidence: 65 },
];

export default function DetectionCenter() {
    return (
        <ImmuneShell>
            <div className="flex justify-between items-center mb-8">
                <div>
                    <h1 className="text-3xl font-bold text-white font-space-grotesk tracking-tight">DETECTION_CENTER</h1>
                    <p className="text-text-secondary mt-1">Real-time threat analysis and pattern matching</p>
                </div>
                <div className="flex space-x-3">
                    <NeuralButton variant="secondary">
                        <Filter className="w-4 h-4 mr-2" />
                        Filter Stream
                    </NeuralButton>
                    <NeuralButton>
                        Run Deep Scan
                    </NeuralButton>
                </div>
            </div>

            <div className="grid grid-cols-12 gap-6 h-[calc(100vh-200px)]">
                {/* Left Column: Event Stream */}
                <div className="col-span-8 flex flex-col gap-4 overflow-y-auto pr-2 scrollbar-thin scrollbar-thumb-white/10">
                    {detectionEvents.map((evt, idx) => (
                        <EventCard
                            key={idx}
                            type={evt.type}
                            severity={evt.severity as any}
                            source={evt.source}
                            target={evt.target}
                            time={evt.time}
                            confidence={evt.confidence}
                        />
                    ))}
                </div>

                {/* Right Column: Analysis & Feedback */}
                <div className="col-span-4 flex flex-col gap-6">
                    <div className="h-1/2">
                        <NeuralNetworkViz />
                    </div>

                    <BioCard className="flex-1">
                        <BioCardHeader>
                            <BioCardTitle>FEEDBACK_LOOP</BioCardTitle>
                        </BioCardHeader>
                        <BioCardContent>
                            <div className="text-sm text-text-secondary mb-4">
                                Help train the immune system. Is the selected event a true positive?
                            </div>
                            <div className="flex gap-4">
                                <button className="flex-1 py-4 bg-bio-green/10 border border-bio-green/20 rounded-xl flex flex-col items-center justify-center hover:bg-bio-green/20 transition-all group">
                                    <ThumbsUp className="w-6 h-6 text-bio-green mb-2 group-hover:scale-110 transition-transform" />
                                    <span className="text-xs font-bold text-bio-green">CONFIRM THREAT</span>
                                </button>
                                <button className="flex-1 py-4 bg-void-obsidian border border-white/10 rounded-xl flex flex-col items-center justify-center hover:bg-white/5 transition-all group">
                                    <ThumbsDown className="w-6 h-6 text-text-muted mb-2 group-hover:text-white transition-colors" />
                                    <span className="text-xs font-bold text-text-muted group-hover:text-white">FALSE POSITIVE</span>
                                </button>
                            </div>
                        </BioCardContent>
                    </BioCard>
                </div>
            </div>
        </ImmuneShell>
    );
}
