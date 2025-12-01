'use client';

import React from 'react';
import { ImmuneShell } from '@/components/layout/ImmuneShell';
import { ServiceAccountCard } from '@/components/identity/ServiceAccountCard';
import { BioCard, BioCardHeader, BioCardTitle, BioCardContent } from '@/components/ui/BioCard';
import { NeuralButton } from '@/components/ui/NeuralButton';
import { RefreshCw, ShieldCheck } from 'lucide-react';

const accounts = [
    { name: 'svc-backup-prod', status: 'healthy', keyAge: 12, lastActive: '2m ago', anomalyScore: 5 },
    { name: 'svc-deploy-pipeline', status: 'warning', keyAge: 85, lastActive: '1h ago', anomalyScore: 45 },
    { name: 'svc-legacy-api', status: 'critical', keyAge: 120, lastActive: '5s ago', anomalyScore: 92 },
    { name: 'svc-monitoring', status: 'healthy', keyAge: 5, lastActive: '10s ago', anomalyScore: 2 },
    { name: 'svc-db-sync', status: 'healthy', keyAge: 45, lastActive: '15m ago', anomalyScore: 12 },
    { name: 'svc-audit-logger', status: 'healthy', keyAge: 22, lastActive: '1m ago', anomalyScore: 8 },
];

export default function IdentityMonitor() {
    return (
        <ImmuneShell>
            <div className="flex justify-between items-center mb-8">
                <div>
                    <h1 className="text-3xl font-bold text-white font-space-grotesk tracking-tight">MACHINE_IDENTITY_MONITOR</h1>
                    <p className="text-text-secondary mt-1">Service account inventory and behavioral analysis</p>
                </div>
                <div className="flex gap-3">
                    <NeuralButton variant="primary">
                        <RefreshCw className="w-4 h-4 mr-2" />
                        Rotate Keys
                    </NeuralButton>
                </div>
            </div>

            <div className="grid grid-cols-12 gap-6 h-[calc(100vh-200px)]">
                {/* Main Grid: Service Accounts */}
                <div className="col-span-9 grid grid-cols-3 gap-4 overflow-y-auto pr-2 content-start">
                    {accounts.map((acc, i) => (
                        <ServiceAccountCard
                            key={i}
                            name={acc.name}
                            status={acc.status as any}
                            keyAge={acc.keyAge}
                            lastActive={acc.lastActive}
                            anomalyScore={acc.anomalyScore}
                        />
                    ))}
                </div>

                {/* Right Column: Stats */}
                <div className="col-span-3 flex flex-col gap-6">
                    <BioCard className="h-1/3">
                        <BioCardHeader>
                            <BioCardTitle>ROTATION_HEALTH</BioCardTitle>
                        </BioCardHeader>
                        <BioCardContent className="flex flex-col items-center justify-center h-[calc(100%-60px)]">
                            <div className="relative w-32 h-32 flex items-center justify-center">
                                <svg className="w-full h-full -rotate-90">
                                    <circle cx="64" cy="64" r="56" stroke="#18181B" strokeWidth="8" fill="none" />
                                    <circle cx="64" cy="64" r="56" stroke="#00FF88" strokeWidth="8" fill="none" strokeDasharray="351" strokeDashoffset="70" strokeLinecap="round" />
                                </svg>
                                <div className="absolute text-center">
                                    <div className="text-2xl font-bold text-white">82%</div>
                                    <div className="text-xs text-text-muted">COMPLIANT</div>
                                </div>
                            </div>
                        </BioCardContent>
                    </BioCard>

                    <BioCard className="flex-1">
                        <BioCardHeader>
                            <BioCardTitle>BOT_DETECTION</BioCardTitle>
                        </BioCardHeader>
                        <BioCardContent>
                            <div className="space-y-4">
                                <div className="p-3 bg-white/5 rounded-lg border border-white/5">
                                    <div className="flex items-center gap-2 mb-2">
                                        <ShieldCheck className="text-bio-green" size={16} />
                                        <span className="text-sm font-bold text-white">Pattern Analysis</span>
                                    </div>
                                    <p className="text-xs text-text-secondary">
                                        Behavioral fingerprinting active. 3 anomalies detected in last hour.
                                    </p>
                                </div>
                                {/* Simulated Heatmap */}
                                <div className="grid grid-cols-7 gap-1">
                                    {[...Array(28)].map((_, i) => (
                                        <div
                                            key={i}
                                            className={`h-6 rounded-sm ${Math.random() > 0.8 ? 'bg-bio-green/80' : Math.random() > 0.6 ? 'bg-bio-green/40' : 'bg-white/5'}`}
                                        />
                                    ))}
                                </div>
                            </div>
                        </BioCardContent>
                    </BioCard>
                </div>
            </div>
        </ImmuneShell>
    );
}
