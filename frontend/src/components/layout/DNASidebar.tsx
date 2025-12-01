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
    Dna
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
        <div className="w-64 h-screen bg-void-obsidian border-r border-white/5 flex flex-col fixed left-0 top-0 z-50 overflow-hidden">
            {/* DNA Helix Background Effect */}
            <div className="absolute left-0 top-0 w-1 h-full bg-gradient-to-b from-bio-green/20 via-neural-purple/20 to-bio-green/20 opacity-50" />

            <div className="p-6 flex items-center space-x-3 border-b border-white/5 relative z-10">
                <div className="w-10 h-10 rounded-full bg-bio-green/10 flex items-center justify-center border border-bio-green/20 shadow-glow-bio">
                    <Dna className="w-6 h-6 text-bio-green animate-pulse-slow" />
                </div>
                <div>
                    <span className="font-bold text-lg font-space-grotesk tracking-tight text-white block leading-none">IMMUNE</span>
                    <span className="text-xs text-bio-green tracking-widest uppercase">System</span>
                </div>
            </div>

            <nav className="flex-1 p-4 space-y-2 relative z-10">
                <div className="px-2 mb-4 text-[10px] font-bold text-text-muted uppercase tracking-[0.2em]">
                    Core Functions
                </div>
                {navItems.map((item) => {
                    const isActive = pathname === item.href;
                    return (
                        <Link
                            key={item.href}
                            href={item.href}
                            className={cn(
                                "flex items-center px-3 py-3 rounded-lg text-sm font-medium transition-all duration-300 group relative overflow-hidden",
                                isActive
                                    ? "text-bio-green bg-bio-green/5 border border-bio-green/10 shadow-[0_0_15px_rgba(0,255,136,0.05)]"
                                    : "text-text-secondary hover:text-white hover:bg-white/5"
                            )}
                        >
                            {isActive && (
                                <div className="absolute left-0 top-0 w-1 h-full bg-bio-green shadow-[0_0_10px_#00FF88]" />
                            )}
                            <item.icon className={cn(
                                "w-5 h-5 mr-3 transition-colors duration-300",
                                isActive ? "text-bio-green" : "text-text-muted group-hover:text-white"
                            )} />
                            <span className="relative z-10">{item.name}</span>
                        </Link>
                    );
                })}
            </nav>

            <div className="p-4 border-t border-white/5 relative z-10">
                <div className="flex items-center p-3 rounded-lg bg-void-black/50 border border-white/5 mb-2">
                    <div className="w-2 h-2 rounded-full bg-bio-green animate-pulse mr-3 shadow-[0_0_5px_#00FF88]" />
                    <div className="flex-1">
                        <div className="text-xs text-text-secondary uppercase tracking-wider">System Health</div>
                        <div className="text-sm font-bold text-bio-green font-fira-code">OPTIMAL</div>
                    </div>
                </div>
                <button className="flex items-center w-full px-3 py-2.5 rounded-lg text-sm font-medium text-text-secondary hover:bg-white/5 hover:text-white transition-colors">
                    <Settings className="w-5 h-5 mr-3 text-text-muted" />
                    Configuration
                </button>
            </div>
        </div>
    );
}
