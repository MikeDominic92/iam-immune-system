'use client';

import React from 'react';
import { BioCard, BioCardHeader, BioCardTitle, BioCardContent } from '@/components/ui/BioCard';
import { motion } from 'framer-motion';

export function NeuralNetworkViz() {
    return (
        <BioCard className="h-full overflow-hidden">
            <BioCardHeader>
                <BioCardTitle>ML_PATTERN_RECOGNITION</BioCardTitle>
            </BioCardHeader>
            <BioCardContent className="h-[300px] relative">
                {/* Neural Nodes */}
                <div className="absolute inset-0 flex items-center justify-center">
                    <svg className="w-full h-full absolute top-0 left-0 pointer-events-none">
                        {/* Connections */}
                        <motion.path
                            d="M100,150 Q200,50 300,150 T500,150"
                            stroke="rgba(168, 85, 247, 0.2)"
                            strokeWidth="2"
                            fill="none"
                            initial={{ pathLength: 0 }}
                            animate={{ pathLength: 1 }}
                            transition={{ duration: 2, repeat: Infinity, repeatType: "reverse" }}
                        />
                        <motion.path
                            d="M100,150 Q200,250 300,150 T500,150"
                            stroke="rgba(168, 85, 247, 0.2)"
                            strokeWidth="2"
                            fill="none"
                            initial={{ pathLength: 0 }}
                            animate={{ pathLength: 1 }}
                            transition={{ duration: 2.5, repeat: Infinity, repeatType: "reverse", delay: 0.5 }}
                        />
                    </svg>

                    {/* Nodes */}
                    {[1, 2, 3].map((i) => (
                        <motion.div
                            key={i}
                            className="absolute w-4 h-4 rounded-full bg-neural-purple shadow-glow-neural z-10"
                            style={{ left: `${20 * i}%`, top: '50%' }}
                            animate={{ scale: [1, 1.5, 1] }}
                            transition={{ duration: 2, delay: i * 0.3, repeat: Infinity }}
                        />
                    ))}

                    <motion.div
                        className="absolute w-6 h-6 rounded-full bg-bio-green shadow-glow-bio z-10"
                        style={{ right: '15%', top: '50%' }}
                        animate={{ scale: [1, 1.2, 1] }}
                        transition={{ duration: 1, repeat: Infinity }}
                    />
                </div>

                <div className="absolute bottom-4 right-4 text-right">
                    <div className="text-xs text-text-muted uppercase">Pattern Match</div>
                    <div className="text-2xl font-bold text-neural-purple font-fira-code">99.8%</div>
                </div>
            </BioCardContent>
        </BioCard>
    );
}
