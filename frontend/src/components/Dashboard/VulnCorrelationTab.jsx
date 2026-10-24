import React, { useState } from 'react';

const STATUS_CONFIG = {
  evidence_supported: {
    label: 'Evidence Supported',
    color: 'text-[#f59e0b]',
    bg: 'bg-[#f59e0b]/10',
    border: 'border-[#f59e0b]/30',
    icon: 'policy',
    description: 'Direct telemetry places this host in an exploitation-relevant attack stage while its software is within the CVE affected range.',
  },
  plausible_correlation: {
    label: 'Plausible Correlation',
    color: 'text-[#3b82f6]',
    bg: 'bg-[#3b82f6]/10',
    border: 'border-[#3b82f6]/30',
    icon: 'link',
    description: 'Asset was present in the attack path and is version-affected, but no direct exploitation-stage telemetry was observed.',
  },
  unverified: {
    label: 'Unverified',
    color: 'text-muted',
    bg: 'bg-main/50',
    border: 'border-main',
    icon: 'help_outline',
    description: 'Insufficient evidence to correlate this CVE to the reconstructed attack. Asset may not be in the attack chain or version is unaffected.',
  },
};

const SEVERITY_COLOR = {
  CRITICAL: 'text-[#ef4444]',
  HIGH: 'text-[#f59e0b]',
  MEDIUM: 'text-[#3b82f6]',
  LOW: 'text-[#10b981]',
  unknown: 'text-muted',
};

function CVSSBadge({ score, severity }) {
  return (
    <span className={`font-mono-code text-[10px] font-semibold ${SEVERITY_COLOR[severity] || 'text-muted'}`}>
      CVSS {score != null ? score.toFixed(1) : 'N/A'} · {severity || 'unknown'}
    </span>
  );
}

function CorrelationCard({ corr, onInspectEvent, onGoToTimeline }) {
  const [expanded, setExpanded] = useState(false);
  const cfg = STATUS_CONFIG[corr.correlation_status] || STATUS_CONFIG.unverified;

  return (
    <div className={`border rounded-[4px] ${cfg.border} bg-surface`}>
      {/* Header row */}
      <button
        className="w-full text-left p-4 flex flex-wrap items-start justify-between gap-3"
        onClick={() => setExpanded(e => !e)}
      >
        <div className="flex items-start space-x-3 min-w-0">
          <span className={`material-symbols-outlined text-[18px] mt-0.5 shrink-0 ${cfg.color}`}>
            {cfg.icon}
          </span>
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono-code text-sm font-semibold text-primary">{corr.cve_id}</span>
              {corr.known_exploited && (
                <span className="px-1.5 py-0.5 text-[9px] font-bold uppercase rounded bg-[#ef4444]/10 border border-[#ef4444]/30 text-[#ef4444] font-mono-code">
                  CISA KEV
                </span>
              )}
              <span className={`px-2 py-0.5 text-[10px] rounded-[3px] border font-mono-code font-semibold ${cfg.bg} ${cfg.border} ${cfg.color}`}>
                {cfg.label}
              </span>
            </div>
            <div className="text-xs text-muted font-mono-code mt-1">
              Host: <span className="text-primary font-semibold">{corr.host}</span>
              {corr.asset_criticality && (
                <span className={`ml-2 text-[10px] uppercase ${
                  corr.asset_criticality === 'critical' ? 'text-[#ef4444]' :
                  corr.asset_criticality === 'high' ? 'text-[#f59e0b]' : 'text-muted'
                }`}>
                  {corr.asset_criticality}
                </span>
              )}
            </div>
            {corr.product && (
              <div className="text-[11px] text-muted font-mono-code mt-0.5">
                {corr.product}{corr.version ? ` v${corr.version}` : ''} ·{' '}
                <CVSSBadge score={corr.cvss_score} severity={corr.cvss_severity} />
                {corr.epss_score != null && (
                  <span className="ml-2 text-[10px] text-muted">
                    EPSS {(corr.epss_score * 100).toFixed(1)}%
                  </span>
                )}
              </div>
            )}
          </div>
        </div>

        <div className="flex items-center space-x-2 shrink-0">
          {corr.related_attack_stages?.length > 0 && (
            <div className="flex flex-wrap gap-1 justify-end">
              {corr.related_attack_stages.map(s => (
                <span key={s} className="px-1.5 py-0.5 rounded bg-main border border-main text-[10px] font-mono-code text-muted uppercase">
                  {s}
                </span>
              ))}
            </div>
          )}
          <span className={`material-symbols-outlined text-[16px] text-muted transition-transform ${expanded ? 'rotate-180' : ''}`}>
            expand_more
          </span>
        </div>
      </button>

      {/* Expanded detail */}
      {expanded && (
        <div className="px-4 pb-4 space-y-3 border-t border-main pt-3">
          {/* Rationale */}
          <div className="p-3 bg-main rounded border border-main">
            <div className="text-[10px] font-mono-code uppercase text-muted mb-1 font-semibold">Correlation Rationale</div>
            <p className="text-xs font-mono-code text-primary leading-relaxed">{corr.rationale}</p>
          </div>

          {/* Related events */}
          {corr.related_attack_event_ids?.length > 0 && (
            <div>
              <div className="text-[10px] font-mono-code uppercase text-muted mb-2 font-semibold">
                Related Attack Events ({corr.related_attack_event_ids.length})
              </div>
              <div className="flex flex-wrap gap-2">
                {corr.related_attack_event_ids.map(eid => (
                  <button
                    key={eid}
                    onClick={() => onInspectEvent && onInspectEvent(eid)}
                    className="px-2 py-1 bg-main border border-main rounded text-[11px] font-mono-code text-[#10b981] hover:underline"
                    title="Click to inspect in Event Inspector"
                  >
                    {eid}
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Action buttons */}
          <div className="flex items-center space-x-2 pt-1">
            {corr.related_attack_event_ids?.length > 0 && (
              <button
                onClick={() => onGoToTimeline && onGoToTimeline()}
                className="flex items-center space-x-1 px-3 py-1.5 text-[11px] font-mono-code text-muted border border-main rounded hover:text-primary hover:bg-main transition-colors"
              >
                <span className="material-symbols-outlined text-[14px]">schedule</span>
                <span>View Timeline</span>
              </button>
            )}
            <div className="text-[10px] font-mono-code text-muted italic ml-auto">
              Forensic confirmation required
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default function VulnCorrelationTab({ vulnCorrelations, onInspectRawEvent, onGoToTimeline }) {
  const [filter, setFilter] = useState('all');

  if (!vulnCorrelations) {
    return (
      <div className="p-8 text-center text-muted text-xs font-mono-code">
        Vulnerability correlation data not available. Run an analysis to populate this view.
      </div>
    );
  }

  const { correlations = [], summary = {}, disclaimer = '' } = vulnCorrelations;

  const filtered = filter === 'all'
    ? correlations
    : correlations.filter(c => c.correlation_status === filter);

  const filterOptions = [
    { value: 'all', label: `All (${summary.total ?? 0})` },
    { value: 'evidence_supported', label: `Evidence Supported (${summary.evidence_supported ?? 0})` },
    { value: 'plausible_correlation', label: `Plausible (${summary.plausible_correlation ?? 0})` },
    { value: 'unverified', label: `Unverified (${summary.unverified ?? 0})` },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="p-6 border border-main bg-surface rounded-[4px] space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center space-x-3">
            <span className="material-symbols-outlined text-[#f59e0b] text-2xl">bug_report</span>
            <div>
              <h2 className="text-lg font-semibold tracking-wide text-primary uppercase font-mono-code">
                Vulnerability Correlation
              </h2>
              <p className="text-xs text-muted font-sans mt-0.5">
                CVEs correlated to reconstructed attack events using asset identity, version matching, and attack stage alignment
              </p>
            </div>
          </div>
          <div className="flex flex-wrap gap-2 text-xs font-mono-code">
            <span className="px-2.5 py-1 rounded-[3px] bg-[#f59e0b]/10 border border-[#f59e0b]/30 text-[#f59e0b] font-semibold">
              Evidence Supported: {summary.evidence_supported ?? 0}
            </span>
            <span className="px-2.5 py-1 rounded-[3px] bg-[#3b82f6]/10 border border-[#3b82f6]/30 text-[#3b82f6] font-semibold">
              Plausible: {summary.plausible_correlation ?? 0}
            </span>
            <span className="px-2.5 py-1 rounded-[3px] bg-main border border-main text-muted font-semibold">
              Unverified: {summary.unverified ?? 0}
            </span>
          </div>
        </div>

        {/* Assessment categories legend */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-3 border-t border-main">
          {Object.entries(STATUS_CONFIG).map(([key, cfg]) => (
            <div key={key} className={`p-3 rounded border ${cfg.border} ${cfg.bg}`}>
              <div className={`text-[10px] font-mono-code uppercase font-bold ${cfg.color}`}>{cfg.label}</div>
              <div className="text-[10px] font-mono-code text-muted mt-1 leading-relaxed">{cfg.description}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Filter bar */}
      {correlations.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {filterOptions.map(opt => (
            <button
              key={opt.value}
              onClick={() => setFilter(opt.value)}
              className={`px-3 py-1.5 text-[11px] font-mono-code rounded-[3px] border transition-colors ${
                filter === opt.value
                  ? 'bg-main border-main text-primary font-semibold'
                  : 'border-main text-muted hover:text-primary hover:bg-main/50'
              }`}
            >
              {opt.label}
            </button>
          ))}
        </div>
      )}

      {/* Empty state */}
      {correlations.length === 0 && (
        <div className="p-8 border border-main bg-surface rounded-[4px] text-center space-y-2">
          <span className="material-symbols-outlined text-muted text-3xl">verified_user</span>
          <div className="text-sm text-muted font-mono-code">
            No vulnerability correlations found for the current dataset.
          </div>
          <div className="text-xs text-muted font-sans max-w-md mx-auto">
            This may indicate the vulnerability cache is empty (no CVE data loaded), or that
            no known-vulnerable assets were involved in the reconstructed attack path. Use
            <span className="font-mono-code text-primary"> POST /api/vulnerabilities/ingest </span>
            to load CVE data for the assets in scope.
          </div>
        </div>
      )}

      {/* Correlation cards */}
      {filtered.length > 0 && (
        <div className="space-y-3">
          {filtered.map((corr, idx) => (
            <CorrelationCard
              key={`${corr.cve_id}-${corr.host}-${idx}`}
              corr={corr}
              onInspectEvent={onInspectRawEvent}
              onGoToTimeline={onGoToTimeline}
            />
          ))}
        </div>
      )}

      {filtered.length === 0 && correlations.length > 0 && (
        <div className="p-6 text-center text-muted text-xs font-mono-code border border-main bg-surface rounded-[4px]">
          No correlations match the selected filter.
        </div>
      )}

      {/* Disclaimer */}
      {disclaimer && (
        <div className="p-4 bg-main/50 border border-main rounded-[4px] text-[11px] font-mono-code text-muted leading-relaxed">
          <span className="text-primary font-semibold">Epistemic Boundary: </span>
          {disclaimer}
        </div>
      )}
    </div>
  );
}
