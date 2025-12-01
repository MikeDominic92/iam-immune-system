'use client';

import React from 'react';
import { ImmuneShell } from '@/components/layout/ImmuneShell';
import { ActionTimeline } from '@/components/remediation/ActionTimeline';
import { BioCard, BioCardHeader, BioCardTitle, BioCardContent } from '@/components/ui/BioCard';
import { NeuralButton } from '@/components/ui/NeuralButton';
import { Shield, Zap, Lock, AlertTriangle } from 'lucide-react';

export default function RemediationConsole() {
    return (
        <ImmuneShell>
            <div className="flex justify-between items-center mb-8">
                <div>
                    <h1 className="text-3xl font-bold text-white font-space-grotesk tracking-tight">AUTO_REMEDIATION</h1>
                    <p className="text-text-secondary mt-1">Automated response actions and rollback controls</p>
                </div>
                <div className="flex items-center gap-4">
                    <div className="px-4 py-2 bg-bio-green/10 border border-bio-green/20 rounded-lg flex items-center gap-2">
                        <div className="w-2 h-2 bg-bio-green rounded-full animate-pulse" />
                        <span className="text-sm font-bold text-bio-green">SYSTEM ACTIVE</span>
                    </div>
                </div>
            </div>

            <div className="grid grid-cols-12 gap-6 h-[calc(100vh-200px)]">
                {/* Left Column: Active Rules */}
                <div className="col-span-4 flex flex-col gap-6">
                    <BioCard className="flex-1">
                        <BioCardHeader>
                            <BioCardTitle>ACTIVE_PROTOCOLS</BioCardTitle>
                        </BioCardHeader>
                        <BioCardContent className="space-y-4">
                            {[
                                { name: 'Brute Force Block', status: 'active', icon: Shield },
                                { name: 'Impossible Travel Lock', status: 'active', icon: Globe },
                                { name: 'High-Risk MFA Enforce', status: 'active', icon: Lock },
                                { name: 'Data Exfil Freeze', status: 'paused', icon: AlertTriangle },
                            ].map((rule, i) => (
                                <div key={i} className="p-4 bg-void-obsidian border border-white/10 rounded-lg flex items-center justify-between group hover:border-bio-green/30 transition-all">
                                    <div className="flex items-center gap-3">
                                        <div className={`p-2 rounded-md ${rule.status === 'active' ? 'bg-bio-green/10 text-bio-green' : 'bg-amber-pulse/10 text-amber-pulse'}`}>
                                            <rule.icon size={18} />
                                        </div>
                                        <div>
                                            <div className="text-sm font-bold text-white">{rule.name}</div>
                                            <div className="text-xs text-text-muted uppercase">{rule.status}</div>
                                        </div>
                                    </div>
                                    <div className={`w-3 h-3 rounded-full ${rule.status === 'active' ? 'bg-bio-green shadow-glow-bio' : 'bg-amber-pulse'} animate-pulse`} />
                                </div>
                            ))}
                        </BioCardContent>
                    </BioCard>
                </div>

                {/* Right Column: Timeline */}
                <div className="col-span-8">
                    <ActionTimeline />
                </div>
            </div>
        </ImmuneShell>
    );
}

import { Globe } from 'lucide-react';
