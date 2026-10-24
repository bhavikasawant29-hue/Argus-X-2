import React, { useState } from 'react';

export default function MitreTab({ mitreMappings = [], onInspectRawEvent }) {
  const [filter, setFilter] = useState('all');

  const filtered = mitreMappings.filter(m => {
    if (filter === 'supported') return m.evidence_status === 'evidence_supported_candidate';
    if (filter === 'review') return m.evidence_status === 'candidate_requires_review';
    return true;
  });

  const supportedCount = mitreMappings.filter(m => m.evidence_status === 'evidence_supported_candidate').length;
  const reviewCount = mitreMappings.filter(m => m.evidence_status === 'candidate_requires_review').length;

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="p-6 border border-main bg-surface rounded-[4px] space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center space-x-3">
            <span className="material-symbols-outlined text-[#10b981] text-2xl">security</span>
            <div>
              <h2 className="text-lg font-semibold tracking-wide text-primary uppercase font-mono-code">
                MITRE ATT&CK Enterprise Mapping
              </h2>
              <p className="text-xs text-muted font-sans mt-0.5">
                Evidence-grounded technique correlation aligned with official STIX Enterprise knowledge base
              </p>
            </div>
          </div>
          <div className="flex items-center space-x-3 text-xs font-mono-code">
            <span className="px-2.5 py-1 rounded-[3px] bg-[#10b981]/10 border border-[#10b981]/30 text-[#10b981] font-semibold">
              Supported: {supportedCount}
            </span>
            <span className="px-2.5 py-1 rounded-[3px] bg-[#f59e0b]/10 border border-[#f59e0b]/30 text-[#f59e0b] font-semibold">
              Review: {reviewCount}
            </span>
          </div>
        </div>

        {/* Filter Bar */}
        <div className="flex items-center space-x-2 pt-3 border-t border-main text-xs font-mono-code">
          <span className="text-muted mr-2">Filter:</span>
          <button
            onClick={() => setFilter('all')}
            className={`px-3 py-1 rounded-[3px] transition-colors ${
              filter === 'all'
                ? 'bg-main text-primary font-semibold border border-main text-[#10b981]'
                : 'text-muted hover:text-primary hover:bg-main/50'
            }`}
          >
            All ({mitreMappings.length})
          </button>
          <button
            onClick={() => setFilter('supported')}
            className={`px-3 py-1 rounded-[3px] transition-colors ${
              filter === 'supported'
                ? 'bg-main text-[#10b981] font-semibold border border-main'
                : 'text-muted hover:text-primary hover:bg-main/50'
            }`}
          >
            Evidence Supported ({supportedCount})
          </button>
          <button
            onClick={() => setFilter('review')}
            className={`px-3 py-1 rounded-[3px] transition-colors ${
              filter === 'review'
                ? 'bg-main text-[#f59e0b] font-semibold border border-main'
                : 'text-muted hover:text-primary hover:bg-main/50'
            }`}
          >
            Requires Review ({reviewCount})
          </button>
        </div>
      </div>

      {/* Mappings Grid / List */}
      <div className="space-y-4">
        {filtered.length === 0 ? (
          <div className="p-8 text-center text-muted text-xs font-mono-code border border-main bg-surface rounded-[4px]">
            No MITRE ATT&CK techniques match the selected filter.
          </div>
        ) : (
          filtered.map((item, idx) => {
            const isSupported = item.evidence_status === 'evidence_supported_candidate';
            return (
              <div
                key={`${item.technique_id}_${idx}`}
                className="p-5 border border-main bg-surface rounded-[4px] space-y-4 transition-colors hover:border-main/80"
              >
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="space-y-1">
                    <div className="flex items-center space-x-2.5">
                      <a
                        href={item.official_url}
                        target="_blank"
                        rel="noreferrer"
                        className="text-sm font-mono-code font-bold text-[#10b981] hover:underline flex items-center space-x-1"
                        title="View technique on official MITRE ATT&CK website"
                      >
                        <span>{item.technique_id}</span>
                        <span className="material-symbols-outlined text-[14px]">open_in_new</span>
                      </a>
                      <span className="text-muted text-sm">/</span>
                      <h3 className="text-sm font-semibold text-primary font-sans">{item.technique_name}</h3>
                    </div>

                    <div className="flex flex-wrap items-center gap-1.5 pt-1">
                      {item.tactics?.map(tac => (
                        <span
                          key={tac}
                          className="px-2 py-0.5 rounded bg-main border border-main text-[10px] font-mono-code uppercase text-muted"
                        >
                          {tac}
                        </span>
                      ))}
                    </div>
                  </div>

                  <span
                    className={`px-2.5 py-1 rounded-[3px] text-[10px] font-mono-code uppercase font-semibold border ${
                      isSupported
                        ? 'bg-[#10b981]/10 text-[#10b981] border-[#10b981]/30'
                        : 'bg-[#f59e0b]/10 text-[#f59e0b] border-[#f59e0b]/30'
                    }`}
                  >
                    {isSupported ? 'Evidence Supported' : 'Requires Review'}
                  </span>
                </div>

                {/* Evidence Explanation */}
                <div className="space-y-1.5 text-xs">
                  <span className="text-[11px] font-mono-code text-muted uppercase">Evidence Rationale:</span>
                  <p className="text-primary leading-relaxed bg-main/50 p-3 rounded border border-main font-sans">
                    {item.evidence_explanation}
                  </p>
                </div>

                {/* Missing Evidence Warning */}
                {item.missing_evidence && item.missing_evidence.length > 0 && (
                  <div className="p-3 rounded bg-[#f59e0b]/10 border border-[#f59e0b]/20 text-xs font-mono-code text-[#f59e0b] space-y-1">
                    <div className="flex items-center space-x-1.5 font-semibold uppercase text-[11px]">
                      <span className="material-symbols-outlined text-[16px]">info</span>
                      <span>Missing Telemetry Evidence:</span>
                    </div>
                    <ul className="list-disc list-inside space-y-0.5 text-muted pl-1">
                      {item.missing_evidence.map((miss, mIdx) => (
                        <li key={mIdx} className="text-primary/90">{miss}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Supporting Telemetry IDs */}
                {item.supporting_event_ids && item.supporting_event_ids.length > 0 && (
                  <div className="flex flex-wrap items-center gap-2 pt-1 text-xs font-mono-code">
                    <span className="text-muted text-[11px] uppercase">Supporting Events:</span>
                    {item.supporting_event_ids.map(sid => (
                      <button
                        key={sid}
                        onClick={() => onInspectRawEvent && onInspectRawEvent(sid)}
                        className="px-2 py-0.5 rounded bg-main border border-main text-[11px] text-[#10b981] hover:underline"
                        title="Click to inspect this event in Inspector pane"
                      >
                        {sid}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>

      {/* Disclaimers */}
      <div className="p-4 rounded border border-main bg-surface/50 text-[11px] font-mono-code text-muted space-y-1">
        <div className="text-primary font-semibold">ATT&CK Alignment Semantics:</div>
        <p>
          Candidate technique mappings reflect observed telemetry features and cross-source correlation.
          A matched rule indicates consistency with adversary tradecraft, not definitive threat actor attribution.
        </p>
      </div>
    </div>
  );
}

