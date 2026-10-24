import React from 'react';

export default function AnomaliesTab({ anomalies = [], onInspectRawEvent }) {
  const flagged = anomalies.filter(a => a.is_anomaly);
  const anomalyCount = flagged.length;
  const totalCount = anomalies.length;
  const anomalyRate = totalCount > 0 ? ((anomalyCount / totalCount) * 100).toFixed(1) : '0.0';

  return (
    <div className="space-y-6">
      {/* Banner */}
      <div className="p-6 border border-main bg-surface rounded-[4px] space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center space-x-3">
            <span className="material-symbols-outlined text-[#10b981] text-2xl">auto_awesome</span>
            <div>
              <h2 className="text-lg font-semibold tracking-wide text-primary uppercase font-mono-code">
                ML Anomaly Detection
              </h2>
              <p className="text-xs text-muted font-sans mt-0.5">
                Unsupervised Isolation Forest statistical outlier detection across all telemetry sources
              </p>
            </div>
          </div>
          <div className="flex items-center space-x-3 text-xs font-mono-code">
            <span className="px-2.5 py-1 rounded-[3px] bg-[#ef4444]/10 border border-[#ef4444]/30 text-[#ef4444] font-semibold">
              Flagged Outliers: {anomalyCount} / {totalCount}
            </span>
            <span className="px-2.5 py-1 rounded-[3px] bg-main border border-main text-muted">
              Rate: {anomalyRate}%
            </span>
          </div>
        </div>
      </div>

      {/* Flagged Outliers Table */}
      <div className="p-5 border border-main bg-surface rounded-[4px] space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-main">
          <span className="text-xs font-mono-code uppercase tracking-wider text-muted font-semibold">
            Statistical Telemetry Outliers ({anomalyCount})
          </span>
          <span className="text-xs font-mono-code text-muted">Model: Isolation Forest v1.0</span>
        </div>

        {flagged.length === 0 ? (
          <div className="p-6 text-center text-muted text-xs font-mono-code">
            No statistical outliers flagged by the anomaly detection engine.
          </div>
        ) : (
          <div className="divide-y divide-main max-h-96 overflow-y-auto">
            {flagged.map((item, idx) => (
              <div
                key={item.event_id || idx}
                className="py-3 px-2 flex flex-wrap items-center justify-between gap-3 text-xs hover:bg-main/40 transition-colors rounded-[3px]"
              >
                <div className="flex items-center space-x-3">
                  <button
                    onClick={() => onInspectRawEvent && onInspectRawEvent(item.event_id)}
                    className="font-mono-code text-[#10b981] font-semibold hover:underline"
                    title="Click to inspect this event in Inspector pane"
                  >
                    {item.event_id}
                  </button>
                  <div className="flex flex-wrap gap-1">
                    {item.reason_codes?.map((r, rIdx) => (
                      <span
                        key={rIdx}
                        className="px-2 py-0.5 rounded bg-main border border-main text-[10px] font-mono-code text-muted uppercase"
                      >
                        {r}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="flex items-center space-x-4 font-mono-code text-xs">
                  <div className="w-24 bg-main rounded-full h-1.5 overflow-hidden">
                    <div
                      className="bg-[#ef4444] h-1.5 rounded-full"
                      style={{ width: `${Math.round((item.anomaly_score || 0) * 100)}%` }}
                    />
                  </div>
                  <span className="text-primary w-12 text-right">
                    {Math.round((item.anomaly_score || 0) * 100)}%
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}

        <div className="p-3 bg-main/50 rounded border border-main text-[11px] font-mono-code text-muted">
          <span className="text-primary font-semibold">Investigative Semantics: </span>
          An anomaly score quantifies statistical distance from benign baseline patterns. An anomaly is an investigative lead, NOT proof of attack or compromise.
        </div>
      </div>

      {/* All Events Summary */}
      {anomalies.length > 0 && (
        <div className="p-5 border border-main bg-surface rounded-[4px] space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-main">
            <span className="text-xs font-mono-code uppercase tracking-wider text-muted font-semibold">
              All Events — Anomaly Score Distribution
            </span>
            <span className="text-xs font-mono-code text-muted">{totalCount} events scored</span>
          </div>

          <div className="grid grid-cols-3 gap-4">
            <div className="p-3 bg-main rounded border border-main text-center">
              <div className="text-2xl font-bold font-mono-code text-[#ef4444]">{anomalyCount}</div>
              <div className="text-[10px] font-mono-code text-muted uppercase mt-1">Flagged Outliers</div>
            </div>
            <div className="p-3 bg-main rounded border border-main text-center">
              <div className="text-2xl font-bold font-mono-code text-[#10b981]">{totalCount - anomalyCount}</div>
              <div className="text-[10px] font-mono-code text-muted uppercase mt-1">Normal Events</div>
            </div>
            <div className="p-3 bg-main rounded border border-main text-center">
              <div className="text-2xl font-bold font-mono-code text-primary">{anomalyRate}%</div>
              <div className="text-[10px] font-mono-code text-muted uppercase mt-1">Anomaly Rate</div>
            </div>
          </div>

          <div className="divide-y divide-main max-h-64 overflow-y-auto">
            {anomalies
              .filter(a => !a.is_anomaly)
              .slice(0, 20)
              .map((item, idx) => (
                <div
                  key={item.event_id || idx}
                  className="py-2 px-2 flex items-center justify-between gap-3 text-xs"
                >
                  <button
                    onClick={() => onInspectRawEvent && onInspectRawEvent(item.event_id)}
                    className="font-mono-code text-muted hover:text-primary hover:underline"
                  >
                    {item.event_id}
                  </button>
                  <div className="flex items-center space-x-3">
                    <div className="w-16 bg-main rounded-full h-1 overflow-hidden">
                      <div
                        className="bg-[#10b981]/60 h-1 rounded-full"
                        style={{ width: `${Math.round((item.anomaly_score || 0) * 100)}%` }}
                      />
                    </div>
                    <span className="text-muted w-10 text-right font-mono-code text-[10px]">
                      {Math.round((item.anomaly_score || 0) * 100)}%
                    </span>
                  </div>
                </div>
              ))}
            {(totalCount - anomalyCount) > 20 && (
              <div className="py-2 px-2 text-[10px] font-mono-code text-muted text-center">
                +{(totalCount - anomalyCount) - 20} more normal events not shown
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
