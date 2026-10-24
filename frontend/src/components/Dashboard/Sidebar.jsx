import React from 'react';

export default function Sidebar({ activeTab, onSelectTab, isCollapsed, onToggleCollapse, stats }) {
  const navItems = [
    { id: 'overview', label: 'Overview', icon: 'dashboard' },
    { id: 'timeline', label: 'Timeline', icon: 'schedule' },
    { id: 'graph', label: 'Attack Graph', icon: 'hub' },
    { id: 'evidence', label: 'Evidence', icon: 'fact_check' },
    { id: 'gaps', label: 'Gaps', icon: 'warning' },
    { id: 'impact', label: 'Impact', icon: 'gavel' },
    { id: 'mitre', label: 'MITRE ATT&CK', icon: 'security' },
    { id: 'anomalies', label: 'Anomalies & ML', icon: 'auto_awesome' },
    { id: 'ai', label: 'AI Investigator', icon: 'psychology' },
    { id: 'replay', label: 'Replay', icon: 'play_circle' },
    { id: 'whatif', label: 'What-If', icon: 'alt_route' },
    { id: 'infra', label: 'Infrastructure', icon: 'lan' },
  ];

  return (
    <aside
      className={`border-r border-main bg-surface flex flex-col justify-between transition-all duration-200 shrink-0 ${
        isCollapsed ? 'w-14' : 'w-56'
      }`}
    >
      <div className="p-2.5 space-y-4">
        {/* Collapse toggle header */}
        <div className="flex items-center justify-between px-2 py-1">
          {!isCollapsed && (
            <span className="text-[10px] font-mono-code uppercase tracking-wider text-muted font-semibold">
              Investigation Panes
            </span>
          )}
          <button
            onClick={onToggleCollapse}
            className="p-1 rounded-[3px] text-muted hover:text-primary hover:bg-main transition-colors ml-auto"
            title={isCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            <span className="material-symbols-outlined text-[18px]">
              {isCollapsed ? 'last_page' : 'first_page'}
            </span>
          </button>
        </div>

        {/* Navigation list */}
        <nav className="space-y-1">
          {navItems.map(item => {
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onSelectTab(item.id)}
                title={isCollapsed ? item.label : undefined}
                className={`w-full flex items-center space-x-3 px-2.5 py-2 rounded-[3px] text-xs transition-colors font-sans ${
                  isActive
                    ? 'bg-main text-primary font-medium border border-main text-[#10b981]'
                    : 'text-muted hover:text-primary hover:bg-main/50'
                } ${isCollapsed ? 'justify-center space-x-0' : ''}`}
              >
                <span className={`material-symbols-outlined text-[18px] shrink-0 ${isActive ? 'text-[#10b981]' : ''}`}>
                  {item.icon}
                </span>
                {!isCollapsed && <span className="truncate">{item.label}</span>}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Footer stats in sidebar */}
      {!isCollapsed && stats && (
        <div className="p-3 border-t border-main font-mono-code text-[11px] space-y-1 text-muted">
          <div className="flex justify-between">
            <span>Confidence:</span>
            <span className="text-[#10b981] font-semibold">{stats.confidence}%</span>
          </div>
          <div className="flex justify-between">
            <span>Completeness:</span>
            <span className="text-[#10b981] font-semibold">{stats.completeness}%</span>
          </div>
        </div>
      )}
    </aside>
  );
}
