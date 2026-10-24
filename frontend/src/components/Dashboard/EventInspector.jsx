import React, { useState } from 'react';

export default function EventInspector({ selectedEvent, onInspectRawEvent, onAskAI }) {
  const [showTechnicalDetails, setShowTechnicalDetails] = useState(false);

  if (!selectedEvent) {
    return (
      <aside className="w-80 border-l border-main bg-surface p-5 flex flex-col justify-center items-center text-center text-muted text-xs">
        <span className="material-symbols-outlined text-3xl mb-2">find_in_page</span>
        <div>Select an event from the Timeline, Graph, or Replay to inspect details.</div>
      </aside>
    );
  }

  const supportingList = selectedEvent.supporting_events || selectedEvent.supporting || [];
  const evidenceStatus = selectedEvent.evidence_status;
  const evidenceBadge = evidenceStatus === 'Verified'
    ? { label: 'VERIFIED EVIDENCE', className: 'border-[#10b981]/30 bg-[#10b981]/10 text-[#10b981]' }
    : evidenceStatus === 'Inferred'
      ? { label: 'INFERRED', className: 'border-[#f59e0b]/30 bg-[#f59e0b]/10 text-[#f59e0b]' }
      : evidenceStatus === 'Insufficient Evidence'
        ? { label: 'INSUFFICIENT EVIDENCE', className: 'border-[#f59e0b]/30 bg-[#f59e0b]/10 text-[#f59e0b]' }
        : null;

  return (
    <aside className="w-80 border-l border-main bg-surface p-5 flex flex-col justify-between overflow-y-auto shrink-0">
      <div className="space-y-5">
        <div className="flex items-center justify-between pb-3 border-b border-main">
          <span className="text-xs font-mono-code text-muted uppercase tracking-wider">Event Inspector</span>
          <div className="flex items-center space-x-1.5">
            {selectedEvent.is_anomaly && (
              <span className="px-2 py-0.5 rounded border border-[#ef4444]/30 bg-[#ef4444]/10 text-[10px] font-mono-code text-[#ef4444] uppercase font-medium">
                ANOMALY
              </span>
            )}
            {evidenceBadge && (
              <span className={`px-2 py-0.5 rounded border text-[10px] font-mono-code uppercase font-medium ${evidenceBadge.className}`}>
                {evidenceBadge.label}
              </span>
            )}
          </div>
        </div>

        <div>
          <div className="text-xs font-mono-code text-[#10b981] font-semibold">
            {selectedEvent.event_id || selectedEvent.id}
          </div>
          <h3 className="text-lg font-semibold text-primary mt-0.5">
            {selectedEvent.stage || selectedEvent.event_type}
          </h3>
          <div className="text-xs text-muted font-mono-code mt-1">
            Timestamp: {selectedEvent.timestamp || selectedEvent.time}
          </div>
        </div>

        <div className="space-y-3 pt-2 text-xs font-mono-code">
          <div className="flex justify-between py-1.5 border-b border-main/50">
            <span className="text-muted">Recorded User:</span>
            <span className="text-primary font-medium">{selectedEvent.user || 'Unknown'}</span>
          </div>
          <div className="flex justify-between py-1.5 border-b border-main/50">
            <span className="text-muted">Source Host:</span>
            <span className="text-primary font-medium">{selectedEvent.source_host || selectedEvent.host || 'N/A'}</span>
          </div>
          <div className="flex justify-between py-1.5 border-b border-main/50">
            <span className="text-muted">Destination Host:</span>
            <span className="text-primary font-medium">{selectedEvent.destination_host || selectedEvent.dest || 'N/A'}</span>
          </div>
          <div className="flex justify-between py-1.5 border-b border-main/50">
            <span className="text-muted">Severity:</span>
            <span className={`font-semibold ${
              selectedEvent.severity === 'CRITICAL' ? 'text-[#ef4444]' :
              selectedEvent.severity === 'HIGH' ? 'text-[#f59e0b]' : 'text-primary'
            }`}>
              {selectedEvent.severity || 'HIGH'}
            </span>
          </div>
        </div>

        <div className="space-y-2 pt-1">
          <span className="text-xs font-mono-code text-muted uppercase">Context Narrative</span>
          <p className="text-xs text-primary leading-relaxed bg-main/60 p-3 rounded border border-main">
            {selectedEvent.context || selectedEvent.description || `${selectedEvent.stage} event involving user ${selectedEvent.user} on host ${selectedEvent.source_host || selectedEvent.host || 'N/A'}.`}
          </p>
        </div>

        {supportingList.length > 0 && (
          <div className="space-y-2 pt-1">
            <span className="text-xs font-mono-code text-muted uppercase">Supporting Evidence Events</span>
            <div className="flex flex-wrap gap-1.5 pt-1">
              {supportingList.map(refId => (
                <button
                  key={refId}
                  onClick={() => onInspectRawEvent(refId)}
                  className="px-2 py-1 rounded bg-main border border-main text-[11px] font-mono-code text-[#10b981] hover:underline"
                >
                  {refId}
                </button>
              ))}
            </div>
          </div>
        )}

        <div className="pt-2 border-t border-main">
          <button
            onClick={() => setShowTechnicalDetails(!showTechnicalDetails)}
            className="w-full flex items-center justify-between text-xs text-muted hover:text-primary transition-colors py-1"
          >
            <span className="font-mono-code">Technical Attributes</span>
            <span>{showTechnicalDetails ? '↑' : '↓'}</span>
          </button>

          {showTechnicalDetails && (
            <div className="mt-2 p-3 bg-main/80 rounded border border-main text-[11px] font-mono-code space-y-1 text-muted">
              <div>Event Type: <span className="text-primary">{selectedEvent.event_type}</span></div>
              <div>Source Type: <span className="text-primary">{selectedEvent.source_type || 'parsed'}</span></div>
              <div>Action: <span className="text-primary">{selectedEvent.action || 'detected'}</span></div>
              <div>Sequence #: <span className="text-primary">{selectedEvent.sequence || selectedEvent.index || 'N/A'}</span></div>
            </div>
          )}
        </div>
      </div>

      <div className="pt-4 border-t border-main mt-4">
        <button
          onClick={() => onAskAI(selectedEvent)}
          className="w-full py-2 bg-surface hover:bg-surface-hover border border-main text-xs font-mono-code text-primary rounded flex items-center justify-center space-x-2 transition-colors"
        >
          <span className="material-symbols-outlined text-[16px] text-[#10b981]">psychology</span>
          <span>Ask AI About This Event</span>
        </button>
      </div>
    </aside>
  );
}
