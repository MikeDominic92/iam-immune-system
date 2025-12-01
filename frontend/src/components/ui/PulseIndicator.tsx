'use client';

import React from 'react';
import { cn } from '@/lib/utils';

interface PulseIndicatorProps {
    status?: 'healthy' | 'warning' | 'critical' | 'neural';
    className?: string;
    animate?: boolean;
}

export function PulseIndicator({ status = 'healthy', className, animate = true }: PulseIndicatorProps) {
    return (
        <div className={cn("relative flex items-center justify-center w-3 h-3", className)}>
            {animate && (
                <span className={cn(
                    "absolute inline-flex h-full w-full rounded-full opacity-75 animate-ping",
                    status === 'healthy' && "bg-bio-green",
                    status === 'warning' && "bg-amber-pulse",
                    status === 'critical' && "bg-bio-red",
                    status === 'neural' && "bg-neural-purple",
                )} />
            )}
            <span className={cn(
                "relative inline-flex rounded-full h-2 w-2",
                status === 'healthy' && "bg-bio-green shadow-[0_0_8px_#00FF88]",
                status === 'warning' && "bg-amber-pulse shadow-[0_0_8px_#F59E0B]",
                status === 'critical' && "bg-bio-red shadow-[0_0_8px_#FF3366]",
                status === 'neural' && "bg-neural-purple shadow-[0_0_8px_#A855F7]",
            )} />
        </div>
    );
}
