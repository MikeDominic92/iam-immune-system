'use client';

import React from 'react';
import { cn } from '@/lib/utils';

interface BioCardProps extends React.HTMLAttributes<HTMLDivElement> {
    variant?: 'default' | 'glass' | 'alert' | 'healthy';
    hoverEffect?: boolean;
}

export const BioCard = React.forwardRef<HTMLDivElement, BioCardProps>(
    ({ className, variant = 'glass', hoverEffect = true, children, ...props }, ref) => {
        return (
            <div
                ref={ref}
                className={cn(
                    "relative rounded-2xl border transition-all duration-500 overflow-hidden",
                    // Base styles
                    variant === 'default' && "bg-void-obsidian border-white/10",
                    variant === 'glass' && "bg-void-obsidian/40 backdrop-blur-md border-white/5",
                    variant === 'alert' && "bg-bio-red/5 border-bio-red/20 shadow-glow-threat",
                    variant === 'healthy' && "bg-bio-green/5 border-bio-green/20 shadow-glow-bio",

                    // Hover effects
                    hoverEffect && "hover:border-bio-green/30 hover:shadow-[0_0_20px_rgba(0,255,136,0.1)] group",

                    className
                )}
                {...props}
            >
                {/* Organic corner accent */}
                <div className="absolute top-0 right-0 w-16 h-16 bg-gradient-to-bl from-white/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500 pointer-events-none" />

                {/* Content */}
                <div className="relative z-10">
                    {children}
                </div>
            </div>
        );
    }
);
BioCard.displayName = "BioCard";

export function BioCardHeader({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
    return <div className={cn("p-6 pb-2", className)} {...props} />;
}

export function BioCardTitle({ className, ...props }: React.HTMLAttributes<HTMLHeadingElement>) {
    return <h3 className={cn("text-lg font-bold font-space-grotesk tracking-tight text-white", className)} {...props} />;
}

export function BioCardContent({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
    return <div className={cn("p-6 pt-2", className)} {...props} />;
}
