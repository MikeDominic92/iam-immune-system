'use client';

import React from 'react';
import { BioCard, BioCardHeader, BioCardTitle, BioCardContent } from '@/components/ui/BioCard';
import { ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';

const data = [
    { name: 'Safe', value: 85 },
    { name: 'Risk', value: 10 },
    { name: 'Critical', value: 5 },
];

const COLORS = ['#00FF88', '#F59E0B', '#FF3366'];

export function ThreatGauge() {
    return (
        <BioCard className="h-full">
            <BioCardHeader>
                <BioCardTitle>THREAT_LEVEL_INDICATOR</BioCardTitle>
            </BioCardHeader>
            <BioCardContent className="h-[200px] relative flex items-center justify-center">
                <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                        <Pie
                            data={data}
                            cx="50%"
                            cy="50%"
                            innerRadius={60}
                            outerRadius={80}
                            startAngle={180}
                            endAngle={0}
                            paddingAngle={2}
                            dataKey="value"
                            stroke="none"
                            cornerRadius={4}
                        >
                            {data.map((entry, index) => (
                                <Cell key={`cell-${index}`} fill={COLORS[index]} />
                            ))}
                        </Pie>
                    </PieChart>
                </ResponsiveContainer>

                <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/4 text-center">
                    <div className="text-4xl font-bold text-white font-space-grotesk text-glow">LOW</div>
                    <div className="text-xs text-bio-green uppercase tracking-widest mt-1">Stable</div>
                </div>

                {/* Decorative Gauge Ticks */}
                <div className="absolute bottom-4 w-full flex justify-between px-12 text-[10px] text-text-muted font-fira-code">
                    <span>0%</span>
                    <span>50%</span>
                    <span>100%</span>
                </div>
            </BioCardContent>
        </BioCard>
    );
}
