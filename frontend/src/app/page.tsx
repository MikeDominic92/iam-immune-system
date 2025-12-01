'use client';

import React from 'react';
import { ImmuneShell } from '@/components/layout/ImmuneShell';
import { OrganismViz } from '@/components/dashboard/OrganismViz';
import { HealthVitals } from '@/components/dashboard/HealthVitals';
import { ThreatGauge } from '@/components/dashboard/ThreatGauge';
import { EventStream } from '@/components/dashboard/EventStream';

export default function Dashboard() {
    return (
        <ImmuneShell>
            <div className="grid grid-cols-12 gap-6 h-[calc(100vh-140px)]">
                {/* Left Column: Vitals & Threat Level */}
                <div className="col-span-3 flex flex-col gap-6">
                    <div className="flex-1">
                        <HealthVitals />
                    </div>
                    <div className="h-1/3">
                        <ThreatGauge />
                    </div>
                </div>

                {/* Center Column: Main Organism Visualization */}
                <div className="col-span-6">
                    <OrganismViz />
                </div>

                {/* Right Column: Event Stream & Actions */}
                <div className="col-span-3 flex flex-col gap-6">
                    <div className="flex-1">
                        <EventStream />
                    </div>

                    {/* Quick Actions Panel */}
                    <div className="h-1/3 bg-void-obsidian/40 backdrop-blur-md border border-white/5 rounded-2xl p-6 flex flex-col justify-between">
                        <div className="text-xs text-text-muted uppercase tracking-wider mb-4">Manual Override</div>
                        <div className="space-y-3">
                            <button className="w-full py-3 px-4 bg-bio-red/10 border border-bio-red/20 text-bio-red rounded-lg text-sm font-bold hover:bg-bio-red/20 hover:shadow-glow-threat transition-all flex items-center justify-center">
                                INITIATE LOCKDOWN
                            </button>
                            <button className="w-full py-3 px-4 bg-neural-purple/10 border border-neural-purple/20 text-neural-purple rounded-lg text-sm font-bold hover:bg-neural-purple/20 hover:shadow-glow-neural transition-all flex items-center justify-center">
                                RUN DIAGNOSTICS
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </ImmuneShell>
    );
}
