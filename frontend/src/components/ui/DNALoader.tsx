'use client';

import React from 'react';
import { motion } from 'framer-motion';

export function DNALoader() {
    return (
        <div className="flex items-center justify-center gap-1 h-10">
            {[...Array(5)].map((_, i) => (
                <motion.div
                    key={i}
                    className="w-1 h-8 bg-bio-green rounded-full"
                    animate={{
                        scaleY: [1, 1.5, 1],
                        opacity: [0.3, 1, 0.3],
                        backgroundColor: ["#0D9488", "#00FF88", "#0D9488"]
                    }}
                    transition={{
                        duration: 1,
                        repeat: Infinity,
                        delay: i * 0.1,
                        ease: "easeInOut"
                    }}
                />
            ))}
        </div>
    );
}
