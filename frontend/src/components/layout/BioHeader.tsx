'use client';

import React from 'react';
import { Bell, Search, Shield } from 'lucide-react';
import { NeuralButton } from '@/components/ui/NeuralButton';

export function BioHeader() {
    return (
        <header className="h-20 border-b border-white/5 bg-void-black/80 backdrop-blur-md flex items-center justify-between px-8 fixed top-0 right-0 left-64 z-40">
            <div className="flex items-center flex-1 max-w-xl">
                <div className="relative w-full group">
                    <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted group-focus-within:text-bio-green transition-colors" />
                    <input
                        type="text"
                        placeholder="Search threats, identities, or events..."
                        className="w-full bg-void-obsidian/50 border border-white/10 rounded-full py-2.5 pl-12 pr-4 text-sm text-text-primary focus:outline-none focus:border-bio-green/30 focus:ring-1 focus:ring-bio-green/30 transition-all placeholder:text-text-muted"
                    />
                </div>
            </div>

            <div className="flex items-center space-x-6">
                <div className="flex items-center space-x-4">
                    <div className="text-right hidden md:block">
                        <div className="text-xs text-text-muted uppercase tracking-wider">Active Threats</div>
                        <div className="text-lg font-bold text-bio-green font-fira-code leading-none">0 DETECTED</div>
                    </div>
                    <div className="h-8 w-px bg-white/10"></div>
                    <div className="text-right hidden md:block">
                        <div className="text-xs text-text-muted uppercase tracking-wider">Auto-Response</div>
                        <div className="text-lg font-bold text-neural-purple font-fira-code leading-none">ENABLED</div>
                    </div>
                </div>

                <NeuralButton variant="ghost" size="icon" className="relative">
                    <Bell className="w-5 h-5" />
                    <span className="absolute top-2 right-2 w-2 h-2 rounded-full bg-bio-red shadow-glow-threat animate-pulse"></span>
                </NeuralButton>

                <div className="flex items-center space-x-3 pl-4 border-l border-white/10">
                    <div className="w-10 h-10 rounded-full bg-gradient-to-br from-bio-green to-deep-teal p-[1px]">
                        <div className="w-full h-full rounded-full bg-void-black flex items-center justify-center">
                            <Shield className="w-5 h-5 text-bio-green" />
                        </div>
                    </div>
                </div>
            </div>
        </header>
    );
}
