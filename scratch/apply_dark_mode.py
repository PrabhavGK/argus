import re

with open('templates/index.html', 'r', encoding='utf-8') as f:
    html = f.read()

# 1. Update <head> Google Fonts and HTML tag
html = html.replace('<html lang="en" class="h-full bg-slate-50 antialiased">',
                    '<html lang="en" class="h-full bg-[#0F172A] text-[#F8FAFC] antialiased">')

# 2. Update Google Fonts link to ensure Inter & JetBrains Mono are imported
old_fonts = re.search(r'<!-- Google Fonts.*?rel="stylesheet">', html, re.DOTALL)
new_fonts = """<!-- Google Fonts: Inter & JetBrains Mono -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">"""
if old_fonts:
    html = html.replace(old_fonts.group(0), new_fonts)

# 3. Update Tailwind config & styles
old_tailwind = re.search(r'<script>\s*tailwind\.config =.*?</style>', html, re.DOTALL)
new_tailwind = """<script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    fontFamily: {
                        sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'sans-serif'],
                        inter: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'sans-serif'],
                        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'monospace'],
                    },
                    colors: {
                        enclave: {
                            bg: '#0F172A',
                            vault: '#1E293B',
                            border: '#334155',
                            crisp: '#F8FAFC',
                            muted: '#94A3B8',
                            sentinel: '#0D9488',
                            sentinelHover: '#0F766E',
                            emerald: '#10B981',
                            emeraldBg: '#064E3B',
                            emeraldBorder: '#047857',
                            crimson: '#E11D48',
                            crimsonBg: '#4C0519',
                            crimsonBorder: '#BE123C',
                        }
                    }
                }
            }
        }
    </script>
    <style>
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: #0F172A; }
        ::-webkit-scrollbar-thumb { background: #334155; border-radius: 9999px; }
        ::-webkit-scrollbar-thumb:hover { background: #475569; }
        .code-container { font-family: 'JetBrains Mono', monospace; font-size: 0.8125rem; line-height: 1.6; }
    </style>"""
if old_tailwind:
    html = html.replace(old_tailwind.group(0), new_tailwind)

# 4. Body tag
html = html.replace('<body class="h-full flex overflow-hidden text-slate-800 bg-slate-50 font-sans">',
                    '<body class="h-full flex overflow-hidden text-[#F8FAFC] bg-[#0F172A] font-inter">')

# 5. Global class replacements for backgrounds, borders, and typography
# General card replacements
replacements = [
    # General surfaces and borders
    ('bg-white', 'bg-[#1E293B]'),
    ('bg-slate-50/50', 'bg-[#0F172A]/50'),
    ('bg-slate-50/60', 'bg-[#0F172A]/60'),
    ('bg-slate-50/70', 'bg-[#0F172A]/70'),
    ('bg-slate-50/80', 'bg-[#0F172A]/80'),
    ('bg-slate-50/90', 'bg-[#0F172A]/90'),
    ('bg-slate-50', 'bg-[#0F172A]/60'),
    ('bg-slate-100/70', 'bg-[#0F172A]/70'),
    ('bg-slate-100', 'bg-[#0F172A]'),
    ('bg-slate-200', 'bg-[#334155]'),
    ('hover:bg-slate-50', 'hover:bg-[#334155]/40'),
    ('hover:bg-slate-100', 'hover:bg-[#334155]/50'),
    ('hover:bg-slate-200', 'hover:bg-[#334155]/70'),
    ('hover:bg-slate-300', 'hover:bg-[#475569]'),
    
    # Borders
    ('border-slate-100', 'border-[#334155]/60'),
    ('border-slate-200/80', 'border-[#334155]'),
    ('border-slate-200/90', 'border-[#334155]'),
    ('border-slate-200', 'border-[#334155]'),
    ('border-slate-300', 'border-[#334155]'),
    ('divide-slate-100', 'divide-[#334155]/60'),
    ('divide-slate-200', 'divide-[#334155]'),

    # Typography
    ('text-slate-900', 'text-[#F8FAFC]'),
    ('text-slate-800', 'text-[#F8FAFC]'),
    ('text-slate-700', 'text-[#F8FAFC]'),
    ('text-slate-600', 'text-[#94A3B8]'),
    ('text-slate-500', 'text-[#94A3B8]'),
    ('text-slate-400', 'text-[#94A3B8]'),
    ('text-slate-300', 'text-[#CBD5E1]'),

    # Brand Colors - Emerald / Success
    ('bg-teal-50', 'bg-[#064E3B]'),
    ('text-teal-700', 'text-[#10B981]'),
    ('text-teal-800', 'text-[#10B981]'),
    ('border-teal-200/90', 'border-[#047857]'),
    ('border-teal-200', 'border-[#047857]'),
    ('border-teal-300', 'border-[#047857]'),
    ('bg-emerald-50', 'bg-[#064E3B]'),
    ('text-emerald-700', 'text-[#10B981]'),
    ('text-emerald-800', 'text-[#10B981]'),
    ('border-emerald-200', 'border-[#047857]'),
    ('border-emerald-300', 'border-[#047857]'),

    # Brand Colors - Crimson / Danger
    ('bg-rose-50/60', 'bg-[#4C0519]/60'),
    ('bg-rose-50/70', 'bg-[#4C0519]/70'),
    ('bg-rose-50', 'bg-[#4C0519]'),
    ('text-rose-700', 'text-[#E11D48]'),
    ('text-rose-800', 'text-[#E11D48]'),
    ('text-rose-900', 'text-[#E11D48]'),
    ('border-rose-100', 'border-[#BE123C]/60'),
    ('border-rose-200/70', 'border-[#BE123C]/70'),
    ('border-rose-200/80', 'border-[#BE123C]/80'),
    ('border-rose-200', 'border-[#BE123C]'),
    ('border-rose-300', 'border-[#BE123C]'),

    # Amber / Cryptographic Enclave
    ('bg-amber-50/60', 'bg-[#451A03]/60'),
    ('bg-amber-50/70', 'bg-[#451A03]/70'),
    ('bg-amber-50', 'bg-[#451A03]'),
    ('text-amber-700', 'text-[#F59E0B]'),
    ('text-amber-800', 'text-[#F59E0B]'),
    ('text-amber-900', 'text-[#F59E0B]'),
    ('text-amber-950', 'text-[#F59E0B]'),
    ('border-amber-200/80', 'border-[#78350F]/80'),
    ('border-amber-200', 'border-[#78350F]'),
    ('border-amber-300', 'border-[#78350F]'),

    # Buttons - Sentinel Teal
    ('bg-teal-600', 'bg-[#0D9488]'),
    ('hover:bg-teal-700', 'hover:bg-[#0F766E]'),
    ('focus:ring-teal-500/20', 'focus:ring-[#0D9488]/30'),
    ('focus:border-teal-500', 'focus:border-[#0D9488]'),

    # Shadow normalization (Linear/Vercel uses borders for depth)
    ('shadow-2xl', 'shadow-none'),
    ('shadow-xl', 'shadow-none'),
    ('shadow-lg', 'shadow-none'),
    ('shadow-md', 'shadow-none'),
    ('shadow-sm', 'shadow-none'),
    ('shadow-xs', 'shadow-none'),
    ('shadow-2xs', 'shadow-none'),
]

for src, target in replacements:
    html = html.replace(src, target)

with open('templates/index.html', 'w', encoding='utf-8') as f:
    f.write(html)

print("templates/index.html transformed successfully.")
