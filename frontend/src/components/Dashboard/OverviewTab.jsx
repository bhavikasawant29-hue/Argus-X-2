import React from 'react';

export default function OverviewTab({ data, selectedEvent, onSelectEvent }) {
  if (!data) return null;

  const timeline = data.timeline || [];
  const confidence = data.confidence ?? 0;
  const completeness = data.completeness ?? 0;
  const blastRadius = data.blast_radius || {};
  const attackPath = blastRadius.attack_path || [];

  return (
    <div className="space-y-6">
      {/* Reconstructed Banner */}
      <div className="p-6 border border-main bg-surface rounded-[4px] space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center space-x-3">
            <span className="w-2 h-2 rounded-full bg-[#10b981]"></span>
            <h2 className="text-lg font-semibold tracking-wide text-primary uppercase font-mono-code">
              ATTACK RECONSTRUCTED
            </h2>
          </div>
          <div className="flex items-center space-x-4 text-xs font-mono-code">
            <span className="px-2.5 py-1 rounded-[3px] bg-[#10b981]/10 border border-[#10b981]/30 text-[#10b981] font-semibold">
              Confidence: {confidence}%
            </span>
            <span className="px-2.5 py-1 rounded-[3px] bg-[#10b981]/10 border border-[#10b981]/30 text-[#10b981] font-semibold">
              Completeness: {completeness}%
            </span>
          </div>
        </div>

        <div className="text-xs sm:text-sm font-mono-code text-primary flex flex-wrap items-center gap-2 pt-3 border-t border-main">
          <span className="text-muted">Reconstructed Attack Vector:</span>
          {attackPath.length > 0 ? (
            attackPath.map((path, idx) => (
              <React.Fragment key={idx}>
                {idx > 0 && <span className="text-muted">|</span>}
                <span className="text-[#10b981] font-semibold">{path}</span>
              </React.Fragment>
            ))
          ) : (
            <span className="text-[#10b981] font-semibold">
              {blastRadius.affected_hosts?.join(' → ') || 'Linear Attack Chain'}
            </span>
          )}
        </div>
      </div>

      {/* Metrics Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 font-mono-code">
        <div className="p-3 border border-main bg-surface rounded-[4px] space-y-1">
          <span className="text-[10px] text-muted uppercase">Reconstructed</span>
          <div className="text-xl font-semibold text-primary">{timeline.length}</div>
        </div>
        <div className="p-3 border border-main bg-surface rounded-[4px] space-y-1">
          <span className="text-[10px] text-muted uppercase">Affected Hosts</span>
          <div className="text-xl font-semibold text-primary">{blastRadius.host_count || 0}</div>
        </div>
        <div className="p-3 border border-main bg-surface rounded-[4px] space-y-1">
          <span className="text-[10px] text-muted uppercase">Affected Users</span>
          <div className="text-xl font-semibold text-primary">{blastRadius.user_count || 0}</div>
        </div>
        <div className="p-3 border border-main bg-surface rounded-[4px] space-y-1">
          <span className="text-[10px] text-muted uppercase">Critical Assets</span>
          <div className="text-xl font-semibold text-[#ef4444]">{blastRadius.critical_asset_count || 0}</div>
        </div>
        <div className="p-3 border border-main bg-surface rounded-[4px] space-y-1">
          <span className="text-[10px] text-muted uppercase">ML Anomalies</span>
          <div className="text-xl font-semibold text-[#f59e0b]">
            {data.summary?.anomalies_detected ?? (data.anomalies?.filter(a => a.is_anomaly)?.length || 0)}
          </div>
        </div>
        <div className="p-3 border border-main bg-surface rounded-[4px] space-y-1">
          <span className="text-[10px] text-muted uppercase">MITRE Mapped</span>
          <div className="text-xl font-semibold text-[#10b981]">
            {data.summary?.mitre_techniques_mapped ?? (data.mitre_mappings?.length || 0)}
          </div>
        </div>
        <div className="p-3 border border-main bg-surface rounded-[4px] space-y-1">
          <span className="text-[10px] text-muted uppercase">CVE Correlated</span>
          <div className="text-xl font-semibold text-[#f59e0b]">
            {data.summary?.vuln_correlations_total ?? (data.vuln_correlations?.summary?.total || 0)}
          </div>
        </div>
      </div>

      {/* Reconstructed Sequence List */}
      <div className="border border-main bg-surface rounded-[4px] p-5 space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-main">
          <span className="text-xs font-mono-code uppercase tracking-wider text-muted font-semibold">Reconstructed Attack Sequence</span>
          <span className="text-xs text-muted font-mono-code">{timeline.length} events grounded</span>
        </div>

        <div className="divide-y divide-main">
          {timeline.map((ev, index) => {
            const isSelected = selectedEvent && (selectedEvent.event_id === ev.event_id || selectedEvent.id === ev.event_id);
            return (
              <div
                key={ev.event_id || index}
                onClick={() => onSelectEvent(ev)}
                className={`py-3 px-3 flex flex-wrap items-center justify-between cursor-pointer text-xs transition-colors rounded-[3px] ${
                  isSelected ? 'bg-main font-medium border-l-2 border-[#10b981]' : 'hover:bg-main/50'
                }`}
              >
                <div className="flex items-center space-x-4">
                  <span className="font-mono-code text-muted text-[11px] w-6">0{ev.sequence || index + 1}</span>
                  <span className="text-primary font-sans font-medium">{ev.stage}</span>
                  <span className="font-mono-code text-muted text-[11px]">{ev.timestamp}</span>
                </div>
                <div className="flex items-center space-x-6">
                  <span className="font-mono-code text-primary text-[11px]">
                    {ev.source_host} {ev.destination_host ? `→ ${ev.destination_host}` : ''}
                  </span>
                  <span className="font-mono-code text-[#10b981] text-[11px]">{ev.event_id}</span>
                  <span className={`text-[10px] font-mono-code uppercase font-semibold ${
                    ev.severity === 'CRITICAL' ? 'text-[#ef4444]' :
                    ev.severity === 'HIGH' ? 'text-[#f59e0b]' : 'text-muted'
                  }`}>
                    {ev.severity || 'HIGH'}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
