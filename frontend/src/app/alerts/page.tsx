'use client';

import React from 'react';
import { ImmuneShell } from '@/components/layout/ImmuneShell';
import { BioCard, BioCardHeader, BioCardTitle, BioCardContent } from '@/components/ui/BioCard';
import { NeuralButton } from '@/components/ui/NeuralButton';
import { Bell, Slack, Mail, MessageSquare, CheckCircle, Clock } from 'lucide-react';

const alerts = [
    { id: 1, title: 'Critical: Root Access Detected', channel: 'PagerDuty', time: '2m ago', status: 'escalated' },
    { id: 2, title: 'Warning: Policy Drift', channel: 'Slack', time: '15m ago', status: 'delivered' },
    { id: 3, title: 'Info: Daily Report Ready', channel: 'Email', time: '1h ago', status: 'delivered' },
];

export default function AlertManagement() {
    return (
        <ImmuneShell>
            <div className="flex justify-between items-center mb-8">
                <div>
                    <h1 className="text-3xl font-bold text-white font-space-grotesk tracking-tight">ALERT_MANAGEMENT</h1>
                    <p className="text-text-secondary mt-1">Multi-channel notification routing and escalation</p>
                </div>
            </div>

            <div className="grid grid-cols-12 gap-6 h-[calc(100vh-200px)]">
                {/* Channels */}
                <div className="col-span-4 flex flex-col gap-4">
                    <BioCard>
                        <BioCardHeader>
                            <BioCardTitle>ACTIVE_CHANNELS</BioCardTitle>
                        </BioCardHeader>
                        <BioCardContent className="space-y-3">
                            {[
                                { name: 'Slack #security-ops', icon: Slack, status: 'connected', color: 'text-bio-green' },
                                { name: 'PagerDuty On-Call', icon: Bell, status: 'connected', color: 'text-bio-green' },
                                { name: 'OpsGenie', icon: Zap, status: 'disconnected', color: 'text-text-muted' },
                                { name: 'Email Relay', icon: Mail, status: 'connected', color: 'text-bio-green' },
                            ].map((channel, i) => (
                                <div key={i} className="flex items-center justify-between p-3 bg-white/5 rounded-lg border border-white/5">
                                    <div className="flex items-center gap-3">
                                        <channel.icon className={channel.color} size={18} />
                                        <span className="text-sm font-bold text-white">{channel.name}</span>
                                    </div>
                                    <div className={`w-2 h-2 rounded-full ${channel.status === 'connected' ? 'bg-bio-green shadow-glow-bio' : 'bg-text-muted'}`} />
                                </div>
                            ))}
                        </BioCardContent>
                    </BioCard>

                    <BioCard className="flex-1">
                        <BioCardHeader>
                            <BioCardTitle>SEVERITY_THRESHOLDS</BioCardTitle>
                        </BioCardHeader>
                        <BioCardContent className="space-y-6">
                            {['Critical', 'High', 'Medium', 'Low'].map((level, i) => (
                                <div key={i}>
                                    <div className="flex justify-between text-xs mb-2">
                                        <span className="text-white font-bold">{level}</span>
                                        <span className="text-text-muted">Notify: {i < 2 ? 'Immediate' : 'Digest'}</span>
                                    </div>
                                    <input type="range" className="w-full accent-bio-green h-1 bg-white/10 rounded-lg appearance-none cursor-pointer" />
                                </div>
                            ))}
                        </BioCardContent>
                    </BioCard>
                </div>

                {/* Alert History */}
                <div className="col-span-8">
                    <BioCard className="h-full">
                        <BioCardHeader>
                            <BioCardTitle>NOTIFICATION_HISTORY</BioCardTitle>
                        </BioCardHeader>
                        <BioCardContent>
                            <div className="space-y-4">
                                {alerts.map((alert) => (
                                    <div key={alert.id} className="flex items-center justify-between p-4 bg-void-obsidian border border-white/10 rounded-xl hover:border-white/20 transition-all group">
                                        <div className="flex items-center gap-4">
                                            <div className={`p-3 rounded-full ${alert.status === 'escalated' ? 'bg-bio-red/10 text-bio-red' : 'bg-bio-green/10 text-bio-green'}`}>
                                                <Bell size={20} />
                                            </div>
                                            <div>
                                                <div className="font-bold text-white group-hover:text-glow transition-all">{alert.title}</div>
                                                <div className="flex items-center gap-2 text-xs text-text-muted mt-1">
                                                    <Clock size={12} />
                                                    <span>{alert.time}</span>
                                                    <span>•</span>
                                                    <span>via {alert.channel}</span>
                                                </div>
                                            </div>
                                        </div>
                                        <div className="flex items-center gap-2">
                                            <span className={`text-xs font-bold uppercase ${alert.status === 'escalated' ? 'text-bio-red' : 'text-bio-green'}`}>
                                                {alert.status}
                                            </span>
                                            {alert.status === 'delivered' && <CheckCircle size={16} className="text-bio-green" />}
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </BioCardContent>
                    </BioCard>
                </div>
            </div>
        </ImmuneShell>
    );
}

import { Zap } from 'lucide-react';
