with open('static/app.js', 'r', encoding='utf-8') as f:
    js = f.read()

# 1. Update Navigation tab active / inactive styles (Linear/Vercel style)
js = js.replace(
    "item.btn.className = 'nav-item w-full flex items-start space-x-3 px-3 py-2.5 rounded-xl text-left transition-all duration-150 bg-slate-900 text-white shadow-xs font-medium cursor-pointer';",
    "item.btn.className = 'nav-item w-full flex items-start space-x-3 px-3 py-2.5 rounded-xl text-left transition-all duration-150 bg-[#0D9488] text-[#F8FAFC] font-semibold cursor-pointer shadow-none';"
)
js = js.replace(
    "if (svg) svg.className = 'w-4 h-4 text-teal-400';",
    "if (svg) svg.className = 'w-4 h-4 text-[#F8FAFC]';"
)
js = js.replace(
    "item.btn.className = 'nav-item w-full flex items-start space-x-3 px-3 py-2.5 rounded-xl text-left transition-all duration-150 text-slate-600 hover:text-slate-900 hover:bg-slate-100 cursor-pointer';",
    "item.btn.className = 'nav-item w-full flex items-start space-x-3 px-3 py-2.5 rounded-xl text-left transition-all duration-150 text-[#94A3B8] hover:text-[#F8FAFC] hover:bg-[#1E293B]/70 cursor-pointer';"
)
js = js.replace(
    "if (svg) svg.className = 'w-4 h-4 text-slate-400';",
    "if (svg) svg.className = 'w-4 h-4 text-[#94A3B8]';"
)

# 2. Preset button styling on Page 2 and Page 1
js = js.replace(
    "b.el.className = 'p-2.5 rounded-lg border border-teal-400 bg-teal-50/70 text-slate-900 font-medium text-left transition-all duration-150 cursor-pointer shadow-xs';",
    "b.el.className = 'p-2.5 rounded-lg border border-[#047857] bg-[#064E3B]/40 text-[#10B981] font-medium text-left transition-all duration-150 cursor-pointer ring-1 ring-[#10B981]/30 shadow-none';"
)
js = js.replace(
    "b.el.className = 'p-2.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-800 font-medium text-left transition-all duration-150 cursor-pointer shadow-xs';",
    "b.el.className = 'p-2.5 rounded-lg border border-[#334155] bg-[#0F172A] hover:bg-[#1E293B] text-[#94A3B8] hover:text-[#F8FAFC] font-medium text-left transition-all duration-150 cursor-pointer shadow-none';"
)
js = js.replace(
    "c.el.className = 'p1-preset-card p-3 rounded-xl border border-teal-500 bg-teal-50/60 text-left transition-all duration-150 cursor-pointer shadow-xs ring-2 ring-teal-500/20 group';",
    "c.el.className = 'p1-preset-card p-3 rounded-xl border border-[#047857] bg-[#064E3B]/40 text-left transition-all duration-150 cursor-pointer ring-1 ring-[#10B981]/30 shadow-none group';"
)
js = js.replace(
    "c.el.className = 'p1-preset-card p-3 rounded-xl border border-slate-200 hover:border-teal-400 hover:bg-teal-50/30 text-left transition-all duration-150 cursor-pointer shadow-xs group';",
    "c.el.className = 'p1-preset-card p-3 rounded-xl border border-[#334155] bg-[#0F172A] hover:border-[#0D9488]/60 hover:bg-[#1E293B] text-left transition-all duration-150 cursor-pointer shadow-none group';"
)

# 3. Pipeline status badge
js = js.replace(
    "p2PipelineStatusBadge.className = 'text-xs font-mono font-semibold px-2.5 py-0.5 rounded bg-slate-100 text-slate-600 border border-slate-200';",
    "p2PipelineStatusBadge.className = 'text-xs font-mono font-semibold px-2.5 py-0.5 rounded bg-[#0F172A] text-[#94A3B8] border border-[#334155]';"
)
js = js.replace(
    "p2PipelineStatusBadge.className = 'text-xs font-mono font-semibold px-2.5 py-0.5 rounded bg-teal-50 text-teal-700 border border-teal-300 animate-pulse';",
    "p2PipelineStatusBadge.className = 'text-xs font-mono font-semibold px-2.5 py-0.5 rounded bg-[#064E3B] text-[#10B981] border border-[#047857] animate-pulse';"
)
js = js.replace(
    "p2PipelineStatusBadge.className = 'text-xs font-mono font-semibold px-2.5 py-0.5 rounded bg-teal-50 text-teal-800 border border-teal-300';",
    "p2PipelineStatusBadge.className = 'text-xs font-mono font-semibold px-2.5 py-0.5 rounded bg-[#064E3B] text-[#10B981] border border-[#047857]';"
)
js = js.replace(
    "p2PipelineStatusBadge.className = 'text-xs font-mono font-semibold px-2.5 py-0.5 rounded bg-rose-50 text-rose-700 border border-rose-300 animate-pulse';",
    "p2PipelineStatusBadge.className = 'text-xs font-mono font-semibold px-2.5 py-0.5 rounded bg-[#4C0519] text-[#E11D48] border border-[#BE123C] animate-pulse';"
)

# 4. Pipeline stages nodes
js = js.replace(
    "node.className = 'border border-slate-200 rounded-xl p-4 bg-slate-50 transition-all duration-200';",
    "node.className = 'border border-[#334155] rounded-xl p-4 bg-[#0F172A] transition-all duration-200';"
)
js = js.replace(
    "if (dot) dot.className = 'h-2.5 w-2.5 rounded-full bg-slate-400 status-dot';",
    "if (dot) dot.className = 'h-2.5 w-2.5 rounded-full bg-[#334155] status-dot';"
)
js = js.replace(
    "node.className = 'border border-teal-500 rounded-xl p-4 bg-teal-50/80 transition-all duration-200 shadow-sm ring-2 ring-teal-400/40';",
    "node.className = 'border border-[#0D9488] rounded-xl p-4 bg-[#064E3B]/50 transition-all duration-200 ring-1 ring-[#10B981]/40';"
)
js = js.replace(
    "if (dot) dot.className = 'h-2.5 w-2.5 rounded-full bg-teal-500 status-dot animate-ping';",
    "if (dot) dot.className = 'h-2.5 w-2.5 rounded-full bg-[#10B981] status-dot animate-ping';"
)
js = js.replace(
    "node.className = 'border border-teal-300 rounded-xl p-4 bg-teal-50/60 transition-all duration-200 shadow-xs';",
    "node.className = 'border border-[#047857] rounded-xl p-4 bg-[#064E3B]/30 transition-all duration-200';"
)
js = js.replace(
    "if (dot) dot.className = 'h-2.5 w-2.5 rounded-full bg-teal-500 status-dot';",
    "if (dot) dot.className = 'h-2.5 w-2.5 rounded-full bg-[#10B981] status-dot';"
)
js = js.replace(
    "node.className = 'border border-rose-400 rounded-xl p-4 bg-rose-50 transition-all duration-200 shadow-xs ring-2 ring-rose-400/30';",
    "node.className = 'border border-[#BE123C] rounded-xl p-4 bg-[#4C0519]/40 transition-all duration-200 ring-1 ring-[#E11D48]/30';"
)
js = js.replace(
    "if (dot) dot.className = 'h-2.5 w-2.5 rounded-full bg-rose-500 status-dot';",
    "if (dot) dot.className = 'h-2.5 w-2.5 rounded-full bg-[#E11D48] status-dot';"
)
js = js.replace(
    "node.className = 'border border-rose-500 rounded-xl p-4 bg-rose-100/90 transition-all duration-200 shadow-xs';",
    "node.className = 'border border-[#BE123C] rounded-xl p-4 bg-[#4C0519]/70 transition-all duration-200';"
)
js = js.replace(
    "if (dot) dot.className = 'h-2.5 w-2.5 rounded-full bg-rose-600 status-dot animate-ping';",
    "if (dot) dot.className = 'h-2.5 w-2.5 rounded-full bg-[#E11D48] status-dot animate-ping';"
)

# 5. Integration tabs on Page 3
js = js.replace(
    "t.el.className = 'integ-tab-btn px-4 py-2 rounded-lg text-xs font-semibold bg-white border border-slate-200 text-slate-900 shadow-xs cursor-pointer';",
    "t.el.className = 'integ-tab-btn px-4 py-2 rounded-lg text-xs font-semibold bg-[#0D9488] border border-[#0D9488] text-white cursor-pointer shadow-none';"
)
js = js.replace(
    "t.el.className = 'integ-tab-btn px-4 py-2 rounded-lg text-xs font-semibold text-slate-600 hover:text-slate-900 hover:bg-slate-100 cursor-pointer';",
    "t.el.className = 'integ-tab-btn px-4 py-2 rounded-lg text-xs font-semibold text-[#94A3B8] border border-[#334155] bg-[#0F172A] hover:text-[#F8FAFC] hover:bg-[#1E293B] cursor-pointer';"
)

# 6. Toast notifications
js = js.replace(
    "toast.className = 'pointer-events-auto flex items-center space-x-2.5 px-4 py-3 rounded-lg shadow-lg border text-xs font-medium transition-all duration-300 transform translate-y-2 opacity-0';",
    "toast.className = 'pointer-events-auto flex items-center space-x-2.5 px-4 py-3 rounded-lg border text-xs font-medium transition-all duration-300 transform translate-y-2 opacity-0 bg-[#1E293B] border-[#334155] text-[#F8FAFC] shadow-none';"
)

# 7. SRE Simulator dynamic classes
js = js.replace(
    "sreScenarioSeverity.className = 'inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-rose-50 text-rose-700 border border-rose-200';",
    "sreScenarioSeverity.className = 'inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-[#4C0519] text-[#E11D48] border border-[#BE123C]';"
)
js = js.replace(
    "sreScenarioSeverity.className = 'inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-amber-50 text-amber-700 border border-amber-200';",
    "sreScenarioSeverity.className = 'inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-[#451A03] text-[#F59E0B] border border-[#78350F]';"
)
js = js.replace(
    "btn.className = 'px-2 py-0.5 rounded font-mono text-[11px] font-bold bg-teal-50 text-teal-800 border border-teal-200 hover:bg-teal-100 hover:border-teal-300 transition-colors cursor-pointer active:scale-95';",
    "btn.className = 'px-2 py-0.5 rounded font-mono text-[11px] font-bold bg-[#064E3B] text-[#10B981] border border-[#047857] hover:bg-[#064E3B]/80 hover:border-[#10B981] transition-colors cursor-pointer active:scale-95';"
)
js = js.replace(
    "sreGradeBadge.className = 'text-xs font-bold px-2 py-0.5 rounded bg-emerald-100 text-emerald-800 border border-emerald-300';",
    "sreGradeBadge.className = 'text-xs font-bold px-2 py-0.5 rounded bg-[#064E3B] text-[#10B981] border border-[#047857]';"
)
js = js.replace(
    "sreGradeBadge.className = 'text-xs font-bold px-2 py-0.5 rounded bg-teal-100 text-teal-800 border border-teal-300';",
    "sreGradeBadge.className = 'text-xs font-bold px-2 py-0.5 rounded bg-[#134E4A] text-[#2DD4BF] border border-[#0F766E]';"
)
js = js.replace(
    "sreGradeBadge.className = 'text-xs font-bold px-2 py-0.5 rounded bg-amber-100 text-amber-800 border border-amber-300';",
    "sreGradeBadge.className = 'text-xs font-bold px-2 py-0.5 rounded bg-[#451A03] text-[#F59E0B] border border-[#78350F]';"
)
js = js.replace(
    "sreGradeBadge.className = 'text-xs font-bold px-2 py-0.5 rounded bg-rose-100 text-rose-800 border border-rose-300';",
    "sreGradeBadge.className = 'text-xs font-bold px-2 py-0.5 rounded bg-[#4C0519] text-[#E11D48] border border-[#BE123C]';"
)
js = js.replace(
    "span.className = 'px-1.5 py-0.5 rounded font-mono text-[10px] font-bold bg-emerald-100 text-emerald-800 border border-emerald-300';",
    "span.className = 'px-1.5 py-0.5 rounded font-mono text-[10px] font-bold bg-[#064E3B] text-[#10B981] border border-[#047857]';"
)
js = js.replace(
    "span.className = 'px-1.5 py-0.5 rounded font-mono text-[10px] font-bold bg-rose-100 text-rose-800 border border-rose-300';",
    "span.className = 'px-1.5 py-0.5 rounded font-mono text-[10px] font-bold bg-[#4C0519] text-[#E11D48] border border-[#BE123C]';"
)

# 8. D3.js Topology Graph overhaul
# Link styles
js = js.replace(
    ".attr('stroke', '#334155')",
    ".attr('stroke', 'rgba(148, 163, 184, 0.3)')"
)
js = js.replace(
    ".attr('stroke-opacity', 0.6)",
    ".attr('stroke-opacity', 0.8)"
)

# Runbook nodes: Vault Gray (#1E293B) with Sentinel Teal stroke (#0D9488)
old_runbook_node = """.attr('fill', '#0284c7') // sky-600
                    .attr('stroke', '#38bdf8') // sky-400"""
new_runbook_node = """.attr('fill', '#1E293B')
                    .attr('stroke', '#0D9488')"""
js = js.replace(old_runbook_node, new_runbook_node)

# Incident nodes: Breach Crimson (#E11D48)
old_incident_node = """.attr('fill', '#f43f5e') // rose-500
                    .attr('stroke', '#fda4af') // rose-300"""
new_incident_node = """.attr('fill', '#E11D48')
                    .attr('stroke', '#BE123C')"""
js = js.replace(old_incident_node, new_incident_node)

# Token nodes: Deterministic Emerald (#10B981)
old_token_node = """.attr('fill', d.is_shared_hub ? '#059669' : '#10b981') // emerald-600 / emerald-500
                    .attr('stroke', '#a7f3d0') // emerald-200"""
new_token_node = """.attr('fill', '#10B981')
                    .attr('stroke', '#047857')"""
js = js.replace(old_token_node, new_token_node)

# Label colors
old_label_fill = ".attr('fill', d.type === 'token' ? '#34d399' : (d.type === 'runbook' ? '#7dd3fc' : '#fda4af'))"
new_label_fill = ".attr('fill', d.type === 'token' ? '#10B981' : (d.type === 'runbook' ? '#0D9488' : '#E11D48'))"
js = js.replace(old_label_fill, new_label_fill)

# Link highlight in D3
old_d3_highlight = """linkSelection
            .attr('stroke', l => {
                if (l.source.id === d.id || l.target.id === d.id) {
                    connectedIds.add(l.source.id);
                    connectedIds.add(l.target.id);
                    return l.target.type === 'token' || l.source.type === 'token' ? '#10b981' : '#38bdf8';
                }
                return '#1e293b';
            })
            .attr('stroke-width', l => (l.source.id === d.id || l.target.id === d.id) ? 2.5 : 1)
            .attr('stroke-opacity', l => (l.source.id === d.id || l.target.id === d.id) ? 1 : 0.15);"""

new_d3_highlight = """linkSelection
            .attr('stroke', l => {
                if (l.source.id === d.id || l.target.id === d.id) {
                    connectedIds.add(l.source.id);
                    connectedIds.add(l.target.id);
                    return '#0D9488';
                }
                return 'rgba(148, 163, 184, 0.08)';
            })
            .attr('stroke-width', l => (l.source.id === d.id || l.target.id === d.id) ? 2.5 : 1)
            .attr('stroke-opacity', l => (l.source.id === d.id || l.target.id === d.id) ? 1 : 0.1);"""
js = js.replace(old_d3_highlight, new_d3_highlight)

old_d3_restore = """linkSelection
            .attr('stroke', '#334155')
            .attr('stroke-width', 1.5)
            .attr('stroke-opacity', 0.6);"""

new_d3_restore = """linkSelection
            .attr('stroke', 'rgba(148, 163, 184, 0.3)')
            .attr('stroke-width', 1.5)
            .attr('stroke-opacity', 0.8);"""
js = js.replace(old_d3_restore, new_d3_restore)

# D3 Inspector tags
js = js.replace(
    "p5InspectorTypeTag.className = 'inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-100 text-emerald-800 border border-emerald-300';",
    "p5InspectorTypeTag.className = 'inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-[#064E3B] text-[#10B981] border border-[#047857]';"
)
js = js.replace(
    "p5InspectorTypeTag.className = 'inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-sky-100 text-sky-800 border border-sky-300';",
    "p5InspectorTypeTag.className = 'inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-[#0D9488]/20 text-[#2DD4BF] border border-[#0D9488]';"
)
js = js.replace(
    "p5InspectorTypeTag.className = 'inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-100 text-rose-800 border border-rose-300';",
    "p5InspectorTypeTag.className = 'inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-[#4C0519] text-[#E11D48] border border-[#BE123C]';"
)

# 9. GitHub-dark style rendering in renderMarkdownToHtml
old_md_render = """        let html = md
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            // Restore deterministic token tags for highlighting
            .replace(/&lt;([A-Z0-9_]+_\d+)&gt;/g, '<span class="px-1.5 py-0.5 rounded font-mono font-bold text-[11px] bg-teal-100 text-teal-900 border border-teal-300">&lt;$1&gt;</span>')
            // Headers
            .replace(/^# (.*$)/gim, '<h1 class="text-lg font-bold text-slate-900 pb-2 border-b border-slate-200 mt-4 mb-2">$1</h1>')
            .replace(/^## (.*$)/gim, '<h2 class="text-base font-bold text-slate-800 pb-1 border-b border-slate-100 mt-3 mb-2">$1</h2>')
            .replace(/^### (.*$)/gim, '<h3 class="text-sm font-bold text-slate-800 mt-3 mb-1.5">$1</h3>')
            // Code blocks
            .replace(/```([\\s\\S]*?)```/gm, '<pre class="bg-slate-900 text-emerald-400 p-3.5 rounded-xl font-mono text-[11px] overflow-x-auto my-2 border border-slate-800">$1</pre>')
            // Inline code
            .replace(/`([^`]+)`/g, '<code class="bg-slate-100 text-slate-800 px-1 py-0.5 rounded font-mono text-[11px] border border-slate-200">$1</code>')
            // Bold
            .replace(/\\*\\*([^*]+)\\*\\*/g, '<strong class="font-bold text-slate-900">$1</strong>')
            // Blockquote
            .replace(/^\\> (.*$)/gim, '<blockquote class="border-l-4 border-indigo-400 bg-indigo-50/50 p-2.5 my-2 text-indigo-900 rounded-r-lg italic text-xs">$1</blockquote>')
            // Horizontal rule
            .replace(/^---$/gim, '<hr class="my-4 border-slate-200" />')
            // Unordered list
            .replace(/^\\- (.*$)/gim, '<li class="ml-4 list-disc text-slate-700 my-0.5">$1</li>')
            // Numbered list
            .replace(/^\\d+\\. (.*$)/gim, '<li class="ml-4 list-decimal text-slate-700 my-0.5">$1</li>');"""

new_md_render = """        let html = md
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            // Restore deterministic token tags for highlighting (Deterministic Emerald)
            .replace(/&lt;([A-Z0-9_]+_\d+)&gt;/g, '<span class="px-2 py-0.5 rounded font-mono font-bold text-[11px] bg-[#064E3B] text-[#10B981] border border-[#047857] shadow-none">&lt;$1&gt;</span>')
            // Headers with GitHub-dark border and crisp typography
            .replace(/^# (.*$)/gim, '<h1 class="text-xl font-bold text-[#F8FAFC] pb-2 border-b border-[#334155] mt-4 mb-3 font-inter">$1</h1>')
            .replace(/^## (.*$)/gim, '<h2 class="text-base font-bold text-[#F8FAFC] pb-1.5 border-b border-[#334155]/60 mt-4 mb-2 font-inter">$1</h2>')
            .replace(/^### (.*$)/gim, '<h3 class="text-sm font-bold text-[#F8FAFC] mt-3.5 mb-1.5 font-inter">$1</h3>')
            // Code blocks: Vault black with subtle border and emerald syntax
            .replace(/```([\\s\\S]*?)```/gm, '<pre class="bg-[#0F172A] text-[#10B981] p-4 rounded-xl font-mono text-[11px] overflow-x-auto my-3 border border-[#334155] leading-relaxed select-text shadow-none">$1</pre>')
            // Inline code
            .replace(/`([^`]+)`/g, '<code class="bg-[#334155]/60 text-[#2DD4BF] px-1.5 py-0.5 rounded font-mono text-[11px] border border-[#334155]">$1</code>')
            // Bold
            .replace(/\\*\\*([^*]+)\\*\\*/g, '<strong class="font-bold text-[#F8FAFC]">$1</strong>')
            // Blockquote: Sentinel Teal indicator
            .replace(/^\\> (.*$)/gim, '<blockquote class="border-l-4 border-[#0D9488] bg-[#0D9488]/10 p-3 my-2.5 text-[#F8FAFC] rounded-r-lg italic text-xs leading-relaxed">$1</blockquote>')
            // Horizontal rule
            .replace(/^---$/gim, '<hr class="my-4 border-[#334155]" />')
            // Unordered list
            .replace(/^\\- (.*$)/gim, '<li class="ml-4 list-disc text-[#94A3B8] my-0.5">$1</li>')
            // Numbered list
            .replace(/^\\d+\\. (.*$)/gim, '<li class="ml-4 list-decimal text-[#94A3B8] my-0.5">$1</li>');"""
js = js.replace(old_md_render, new_md_render)

old_md_table = """            let tableHtml = '<div class="overflow-x-auto my-3"><table class="min-w-full divide-y divide-slate-200 border border-slate-200 rounded-lg text-xs">';
            rows.forEach((row, rIdx) => {
                if (row.includes('---')) return; // separator row
                const cells = row.split('|').slice(1, -1);
                if (rIdx === 0) {
                    tableHtml += '<thead class="bg-slate-50 font-bold text-slate-700"><tr>';
                    cells.forEach(c => tableHtml += `<th class="px-3 py-2 text-left">${c.trim()}</th>`);
                    tableHtml += '</tr></thead><tbody class="divide-y divide-slate-100 bg-white">';
                } else {
                    tableHtml += '<tr>';
                    cells.forEach(c => tableHtml += `<td class="px-3 py-2">${c.trim()}</td>`);
                    tableHtml += '</tr>';
                }
            });
            tableHtml += '</tbody></table></div>';"""

new_md_table = """            let tableHtml = '<div class="overflow-x-auto my-3"><table class="min-w-full divide-y divide-[#334155] border border-[#334155] rounded-xl text-xs bg-[#0F172A]">';
            rows.forEach((row, rIdx) => {
                if (row.includes('---')) return; // separator row
                const cells = row.split('|').slice(1, -1);
                if (rIdx === 0) {
                    tableHtml += '<thead class="bg-[#1E293B] font-bold text-[#F8FAFC]"><tr>';
                    cells.forEach(c => tableHtml += `<th class="px-3.5 py-2.5 text-left border-b border-[#334155] font-inter">${c.trim()}</th>`);
                    tableHtml += '</tr></thead><tbody class="divide-y divide-[#334155] bg-[#0F172A]">';
                } else {
                    tableHtml += '<tr class="hover:bg-[#1E293B]/40 transition-colors">';
                    cells.forEach(c => tableHtml += `<td class="px-3.5 py-2 text-[#94A3B8] font-mono text-[11px]">${c.trim()}</td>`);
                    tableHtml += '</tr>';
                }
            });
            tableHtml += '</tbody></table></div>';"""
js = js.replace(old_md_table, new_md_table)

old_md_para = "return `<p class=\"my-1.5 text-slate-700\">${p}</p>`;"
new_md_para = "return `<p class=\"my-1.5 text-[#94A3B8] leading-relaxed\">${p}</p>`;"
js = js.replace(old_md_para, new_md_para)

with open('static/app.js', 'w', encoding='utf-8') as f:
    f.write(js)

print("static/app.js updated successfully.")
