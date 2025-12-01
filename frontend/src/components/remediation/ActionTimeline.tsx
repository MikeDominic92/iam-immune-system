'use client';

import React from 'react';
import { BioCard, BioCardHeader, BioCardTitle, BioCardContent } from '@/components/ui/BioCard';
import { CheckCircle, XCircle, Clock, Shield, RotateCcw } from 'lucide-react';
import { NeuralButton } from '@/components/ui/NeuralButton';

const actions = [
    { id: 1, time: '10:42:05', action: 'Account Locked', target: 'j.doe', status: 'success', description: 'Multiple failed login attempts detected' },
    { id: 2, time: '10:41:50', action: 'Session Revoked', target: 'admin_console', status: 'success', description: 'Suspicious IP geolocation' },
    { id: 3, time: '10:35:12', action: 'Policy Enforced', target: 'S3 Bucket', status: 'failed', description: 'Failed to apply public access block' },
    { id: 4, time: '10:30:00', action: 'MFA Prompted', target: 'm.smith', status: 'success', description: 'High-risk sign-in detected' },
];

export function ActionTimeline() {
    return (
        <BioCard className="h-full">
            <BioCardHeader>
                <BioCardTitle>REMEDIATION_TIMELINE</BioCardTitle>
            </BioCardHeader>
            <BioCardContent>
                <div className="relative pl-4 border-l border-white/10 space-y-8">
                    {actions.map((action) => (
                        <div key={action.id} className="relative pl-6 group">
                            {/* Timeline Node */}
                            <div className={`absolute -left-[21px] top-1 w-3 h-3 rounded-full border-2 ${action.status === 'success' ? 'bg-bio-green border-bio-green shadow-glow-bio' : 'bg-bio-red border-bio-red shadow-glow-threat'
                                }`} />

                            <div className="flex justify-between items-start bg-white/5 p-4 rounded-lg border border-white/5 group-hover:border-white/10 transition-all">
                                <div>
                                    <div className="flex items-center gap-2 mb-1">
                                        <span className={`text-sm font-bold ${action.status === 'success' ? 'text-bio-green' : 'text-bio-red'}`}>
                                            {action.action}
                                        </span>
                                        <span className="text-xs text-text-muted font-fira-code">[{action.time}]</span>
                                    </div>
                                    <div className="text-sm text-white mb-1">Target: {action.target}</div>
                                    <div className="text-xs text-text-secondary">{action.description}</div>
                                </div>

                                <NeuralButton size="sm" variant="ghost" className="text-xs">
                                    <RotateCcw className="w-3 h-3 mr-1" />
                                    Rollback
                                </NeuralButton>
                            </div>
                        </div>
                    ))}
                </div>
            </BioCardContent>
        </BioCard>
    );
}
