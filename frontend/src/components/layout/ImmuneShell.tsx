'use client';

import React from 'react';
import { DNASidebar } from './DNASidebar';
import { BioHeader } from './BioHeader';

interface ImmuneShellProps {
    children: React.ReactNode;
}

export function ImmuneShell({ children }: ImmuneShellProps) {
    return (
        <div className="min-h-screen bg-void-black text-text-primary font-sans selection:bg-bio-green/30 selection:text-bio-green">
            <DNASidebar />
            <BioHeader />

            <main className="pl-64 pt-20 min-h-screen relative overflow-hidden">
                {/* Ambient Background Effects */}
                <div className="absolute top-0 left-0 w-full h-full pointer-events-none overflow-hidden">
                    <div className="absolute top-[-20%] right-[-10%] w-[800px] h-[800px] bg-bio-green/5 rounded-full blur-[120px] animate-pulse-slow" />
                    <div className="absolute bottom-[-20%] left-[-10%] w-[600px] h-[600px] bg-neural-purple/5 rounded-full blur-[100px] animate-pulse-slow" style={{ animationDelay: '2s' }} />
                </div>

                <div className="relative z-10 p-8 max-w-[1600px] mx-auto animate-in fade-in duration-700">
                    {children}
                </div>
            </main>

            {/* Scanning line effect */}
            <div className="fixed top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-bio-green/30 to-transparent opacity-20 animate-scan pointer-events-none z-50"></div>
        </div>
    );
}
