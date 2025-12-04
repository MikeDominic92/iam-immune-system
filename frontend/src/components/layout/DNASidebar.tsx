'use client';

import React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { cn } from '@/lib/utils';
import {
    Activity,
    ShieldAlert,
    Zap,
    Fingerprint,
    Bell,
    Settings,
    Dna,
    LogOut
} from 'lucide-react';

const navItems = [
    { name: 'Immune Status', href: '/', icon: Activity },
    { name: 'Detection Center', href: '/detection', icon: ShieldAlert },
    { name: 'Auto-Remediation', href: '/remediation', icon: Zap },
    { name: 'Identity Monitor', href: '/identity', icon: Fingerprint },
    { name: 'Alert Management', href: '/alerts', icon: Bell },
];

export function DNASidebar() {
    const pathname = usePathname();

    return (
        <div className="w-64 h-[calc(100vh-2rem)] glass-panel border-r-0 flex flex-col fixed left-4 top-4 z-50 overflow-hidden rounded-2xl">
            {/* DNA Helix Background Effect */}
            <div className="absolute left-0 top-0 w-1 h-full bg-gradient-to-b from-cyber-green/20 via-cyber-purple/20 to-cyber-green/20 opacity-50" />

            <div className="h-20 flex items-center px-6 border-b border-white/10 relative z-10">
                <div className="w-10 h-10 rounded-full bg-cyber-green/10 flex items-center justify-center border border-cyber-green/20 shadow-[0_0_10px_rgba(16,185,129,0.3)] mr-3">
                    <Dna className="w-6 h-6 text-cyber-green animate-pulse" />
                </div>
                <div>
                    <span className="font-orbitron font-bold text-lg tracking-tight text-white block leading-none">IMMUNE</span>
                    <span className="text-xs text-cyber-green tracking-widest uppercase">System</span>
                </div>
            </div>

            <nav className="flex-1 p-4 space-y-2 relative z-10">
                <div className="px-2 mb-4 text-[10px] font-bold text-gray-500 uppercase tracking-[0.2em] font-mono">
                    Core Functions
                </div>
                {navItems.map((item) => {
                    const isActive = pathname === item.href;
                    return (
                        <Link
                            key={item.href}
                            href={item.href}
                            className={cn(
                                "flex items-center px-3 py-3 rounded-xl text-sm font-medium transition-all duration-300 group relative overflow-hidden",
                                isActive
                                    ? "text-cyber-green bg-cyber-green/5 border border-cyber-green/10 shadow-[0_0_15px_rgba(16,185,129,0.05)]"
                                    : "text-gray-400 hover:text-white hover:bg-white/5"
                            )}
                        >
                            {isActive && (
                                <div className="absolute left-0 top-0 w-1 h-full bg-cyber-green shadow-[0_0_10px_#10b981]" />
                            )}
                            <item.icon className={cn(
                                "w-5 h-5 mr-3 transition-colors duration-300",
                                isActive ? "text-cyber-green" : "text-gray-500 group-hover:text-white"
                            )} />
                            <span className="relative z-10">{item.name}</span>
                        </Link>
                    );
                })}
            </nav>

            <div className="p-4 border-t border-white/10 relative z-10 space-y-2">
                <div className="flex items-center p-3 rounded-lg bg-black/40 border border-white/5 mb-2">
                    <div className="w-2 h-2 rounded-full bg-cyber-green animate-pulse mr-3 shadow-[0_0_5px_#10b981]" />
                    <div className="flex-1">
                        <div className="text-xs text-gray-400 uppercase tracking-wider">System Health</div>
                        <div className="text-sm font-bold text-cyber-green font-mono">OPTIMAL</div>
                    </div>
                </div>
                <button className="flex items-center w-full px-3 py-2 rounded-lg text-sm font-medium text-gray-400 hover:bg-white/5 hover:text-white transition-colors">
                    <Settings className="w-5 h-5 mr-3 text-gray-500" />
                    Configuration
                </button>
                <button className="flex items-center w-full px-3 py-2 rounded-lg text-sm font-medium text-red-400 hover:bg-red-500/10 hover:text-red-300 transition-colors">
                    <LogOut className="w-5 h-5 mr-3" />
                    Sign Out
                </button>
            </div>
        </div>
    );
}

