'use client';

import React from 'react';
import { Bell, Search, Shield } from 'lucide-react';
import { NeuralButton } from '@/components/ui/NeuralButton';
import { IdentityBadge } from '@/components/ui/IdentityBadge';

export function BioHeader() {
    return (
        <header className="h-20 glass-panel border-b-0 sticky top-0 z-40 px-8 flex items-center justify-between m-4 rounded-2xl ml-[17rem]">
            <div className="flex items-center flex-1 max-w-xl group">
                <div className="relative w-full">
                    <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-cyber-cyan/50 group-focus-within:text-cyber-cyan transition-colors" />
                    <input
                        type="text"
                        placeholder="Search threats, identities, or events..."
                        className="w-full bg-black/20 border border-white/10 rounded-xl py-2.5 pl-12 pr-4 text-sm text-white focus:outline-none focus:border-cyber-cyan/50 focus:ring-1 focus:ring-cyber-cyan/50 transition-all placeholder:text-gray-500 backdrop-blur-sm"
                    />
                </div>
            </div>

            <div className="flex items-center space-x-6">
                <div className="flex items-center space-x-4">
                    <div className="text-right hidden md:block">
                        <div className="text-xs text-gray-500 uppercase tracking-wider">Active Threats</div>
                        <div className="text-lg font-bold text-cyber-green font-mono leading-none">0 DETECTED</div>
                    </div>
                    <div className="h-8 w-px bg-white/10"></div>
                    <div className="text-right hidden md:block">
                        <div className="text-xs text-gray-500 uppercase tracking-wider">Auto-Response</div>
                        <div className="text-lg font-bold text-cyber-purple font-mono leading-none">ENABLED</div>
                    </div>
                </div>

                <NeuralButton variant="ghost" size="icon" className="relative hover:bg-white/5 rounded-full p-2">
                    <Bell className="w-5 h-5 text-gray-400 hover:text-cyber-cyan transition-colors" />
                    <span className="absolute top-2 right-2 w-2 h-2 rounded-full bg-cyber-purple shadow-[0_0_5px_#7c3aed] animate-pulse"></span>
                </NeuralButton>

                <div className="h-8 w-px bg-white/10 mx-2"></div>

                <IdentityBadge />
            </div>
        </header>
    );
}

