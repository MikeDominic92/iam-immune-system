'use client';

import React from 'react';
import { cn } from '@/lib/utils';
import { cva, type VariantProps } from 'class-variance-authority';
import { Loader2 } from 'lucide-react';

const buttonVariants = cva(
    "relative inline-flex items-center justify-center whitespace-nowrap rounded-lg text-sm font-medium transition-all duration-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-bio-green/50 disabled:pointer-events-none disabled:opacity-50 overflow-hidden",
    {
        variants: {
            variant: {
                primary: "bg-bio-green/10 text-bio-green border border-bio-green/20 hover:bg-bio-green/20 hover:border-bio-green/40 hover:shadow-glow-bio",
                secondary: "bg-void-obsidian text-text-primary border border-white/10 hover:bg-white/5 hover:border-white/20",
                neural: "bg-neural-purple/10 text-neural-purple border border-neural-purple/20 hover:bg-neural-purple/20 hover:border-neural-purple/40 hover:shadow-glow-neural",
                danger: "bg-bio-red/10 text-bio-red border border-bio-red/20 hover:bg-bio-red/20 hover:border-bio-red/40 hover:shadow-glow-threat",
                ghost: "hover:bg-white/5 text-text-secondary hover:text-white",
            },
            size: {
                default: "h-10 px-4 py-2",
                sm: "h-9 rounded-md px-3",
                lg: "h-11 rounded-md px-8",
                icon: "h-10 w-10",
            },
        },
        defaultVariants: {
            variant: "primary",
            size: "default",
        },
    }
);

export interface NeuralButtonProps
    extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
    loading?: boolean;
}

export const NeuralButton = React.forwardRef<HTMLButtonElement, NeuralButtonProps>(
    ({ className, variant, size, loading, children, ...props }, ref) => {
        return (
            <button
                className={cn(buttonVariants({ variant, size, className }))}
                ref={ref}
                disabled={loading || props.disabled}
                {...props}
            >
                {/* Synaptic flash effect on hover */}
                <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/10 to-transparent -translate-x-full group-hover:animate-flow pointer-events-none" />

                {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                <span className="relative z-10 flex items-center gap-2">
                    {children}
                </span>
            </button>
        );
    }
);
NeuralButton.displayName = "NeuralButton";
