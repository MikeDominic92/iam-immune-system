'use client';

import React from 'react';
import { BioCard, BioCardHeader, BioCardTitle, BioCardContent } from '@/components/ui/BioCard';
import { motion } from 'framer-motion';

export function OrganismViz() {
    return (
        <BioCard className="h-full overflow-hidden" hoverEffect={false}>
            <BioCardHeader className="absolute top-0 left-0 z-20 w-full">
                <BioCardTitle>IMMUNE_CORE_VISUALIZATION</BioCardTitle>
            </BioCardHeader>

            <div className="relative w-full h-full bg-void-black flex items-center justify-center">
                {/* Central Core */}
                <motion.div
                    className="w-32 h-32 rounded-full bg-bio-green/20 blur-xl absolute"
                    animate={{ scale: [1, 1.2, 1], opacity: [0.5, 0.8, 0.5] }}
                    transition={{ duration: 4, repeat: Infinity, ease: "easeInOut" }}
                />

                {/* Orbiting Nodes */}
                {[...Array(6)].map((_, i) => (
                    <motion.div
                        key={i}
                        className="absolute w-full h-full flex items-center justify-center"
                        animate={{ rotate: 360 }}
                        transition={{ duration: 20 + i * 5, repeat: Infinity, ease: "linear" }}
                    >
                        <div
                            className="w-4 h-4 rounded-full bg-bio-green shadow-glow-bio absolute"
                            style={{ transform: `translateX(${100 + i * 20}px)` }}
                        />
                        <div
                            className="w-[200px] h-[200px] rounded-full border border-bio-green/10 absolute"
                            style={{ width: `${200 + i * 40}px`, height: `${200 + i * 40}px` }}
                        />
                    </motion.div>
                ))}

                {/* Connecting Lines (Simulated) */}
                <svg className="absolute inset-0 w-full h-full pointer-events-none opacity-30">
                    <circle cx="50%" cy="50%" r="100" stroke="#00FF88" strokeWidth="1" fill="none" strokeDasharray="5,5" />
                    <circle cx="50%" cy="50%" r="150" stroke="#A855F7" strokeWidth="1" fill="none" strokeDasharray="10,10" />
                </svg>

                {/* Status Text */}
                <div className="absolute bottom-8 left-8 z-20">
                    <div className="text-xs text-text-muted uppercase tracking-widest mb-1">System Status</div>
                    <div className="text-2xl font-bold text-bio-green font-fira-code text-glow">HOMEOSTASIS</div>
                </div>
            </div>
        </BioCard>
    );
}
