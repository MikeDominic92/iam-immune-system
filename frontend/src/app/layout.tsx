import { Space_Grotesk, Inter, Fira_Code } from "next/font/google";
import "./globals.css";

const spaceGrotesk = Space_Grotesk({
    variable: "--font-space-grotesk",
    subsets: ["latin"],
});

const inter = Inter({
    variable: "--font-inter",
    subsets: ["latin"],
});

const firaCode = Fira_Code({
    variable: "--font-fira-code",
    subsets: ["latin"],
});

export const metadata = {
    title: "IAM Immune System",
    description: "Real-time Security Orchestration",
};

export default function RootLayout({
    children,
}: Readonly<{
    children: React.ReactNode;
}>) {
    return (
        <html lang="en" className="dark">
            <body
                className={`${spaceGrotesk.variable} ${inter.variable} ${firaCode.variable} antialiased bg-void-black text-text-primary min-h-screen overflow-hidden`}
            >
                <div className="fixed inset-0 bg-[url('/grid.svg')] bg-center [mask-image:linear-gradient(180deg,white,rgba(255,255,255,0))] opacity-20 pointer-events-none"></div>
                {children}
            </body>
        </html>
    );
}
