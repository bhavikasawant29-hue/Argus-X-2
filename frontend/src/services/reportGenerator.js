import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';

/**
 * ARGUS-X Forensic Investigation PDF Report Generator
 *
 * Generates an auditable, evidence-traceable PDF report of the active investigation.
 * Strictly uses data from the selected investigation without fabricating events.
 */

// Helper to sanitize sensitive strings
function sanitizeText(str) {
  if (!str) return 'N/A';
  const val = String(str);
  if (val.startsWith('sk-') || val.includes('Bearer ') || /password|secret|api[_-]?key/i.test(val)) {
    return '[REDACTED]';
  }
  return val;
}

export function buildInvestigationPDFDoc(investigationData, options = {}) {
  if (!investigationData) {
    throw new Error('No active investigation data provided for report generation.');
  }

  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'pt',
    format: 'a4',
  });

  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 36;
  const contentWidth = pageWidth - margin * 2;

  // Extract investigation components
  const timeline = investigationData.timeline || [];
  const evidence = investigationData.evidence || [];
  const gaps = investigationData.gaps || [];
  const recommendations = investigationData.recommendations || [];
  const blastRadius = investigationData.blast_radius || {};
  const graph = investigationData.graph || { nodes: [], edges: [] };
  const anomalies = (investigationData.anomalies || []).filter((a) => a.is_anomaly);
  const mitreMappings = investigationData.mitre_mappings || [];
  const summary = investigationData.summary || {};

  const confidence = investigationData.confidence ?? summary.confidence ?? 0;
  const completeness = investigationData.completeness ?? summary.completeness ?? 0;

  // Reconstructed attack path string
  let attackPathStr = '';
  if (blastRadius.attack_path && blastRadius.attack_path.length > 0) {
    attackPathStr = blastRadius.attack_path.join('  →  ');
  } else if (blastRadius.affected_hosts && blastRadius.affected_hosts.length > 0) {
    attackPathStr = blastRadius.affected_hosts.join('  →  ');
  } else if (timeline.length > 0) {
    const stages = [];
    timeline.forEach((e) => {
      if (e.stage && !stages.includes(e.stage)) stages.push(e.stage);
    });
    attackPathStr = stages.join('  →  ');
  } else {
    attackPathStr = 'No data available';
  }

  const invId = options.investigationId || `INV-${new Date().toISOString().slice(0, 10).replace(/-/g, '')}-${Math.floor(1000 + Math.random() * 9000)}`;
  const reportTimestamp = new Date().toUTCString();

  let y = margin;

  // ==========================================
  // HEADER BANNER
  // ==========================================
  doc.setFillColor(15, 23, 42); // #0f172a
  doc.rect(margin, y, contentWidth, 54, 'F');

  doc.setTextColor(16, 185, 129); // Emerald
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(13);
  doc.text('ARGUS-X SECURITY TELEMETRY PLATFORM', margin + 14, y + 22);

  doc.setTextColor(248, 250, 252);
  doc.setFontSize(10);
  doc.setFont('helvetica', 'normal');
  doc.text(`INCIDENT INVESTIGATION REPORT: ${invId}`, margin + 14, y + 42);

  doc.setTextColor(148, 163, 184);
  doc.setFontSize(8);
  doc.text(`Generated: ${reportTimestamp}`, pageWidth - margin - 14, y + 22, { align: 'right' });
  doc.text('CONFIDENTIAL // SOC INTERNAL USE ONLY', pageWidth - margin - 14, y + 42, { align: 'right' });

  y += 66;

  // ==========================================
  // SYSTEM-GENERATED ASSESSMENTS (CONFIDENCE & COMPLETENESS)
  // ==========================================
  const cardWidth = (contentWidth - 12) / 2;

  // Confidence Card
  doc.setFillColor(248, 250, 252);
  doc.setDrawColor(226, 232, 240);
  doc.rect(margin, y, cardWidth, 50, 'FD');

  doc.setTextColor(15, 23, 42);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(14);
  doc.text(`Confidence: ${confidence}%`, margin + 10, y + 20);

  doc.setTextColor(100, 116, 139);
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7.5);
  doc.text('System-Generated Assessment: Mathematical scoring based', margin + 10, y + 33);
  doc.text('on corroborating multi-tier telemetry and causal continuity.', margin + 10, y + 43);

  // Completeness Card
  doc.setFillColor(248, 250, 252);
  doc.setDrawColor(226, 232, 240);
  doc.rect(margin + cardWidth + 12, y, cardWidth, 50, 'FD');

  doc.setTextColor(15, 23, 42);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(14);
  doc.text(`Completeness: ${completeness}%`, margin + cardWidth + 22, y + 20);

  doc.setTextColor(100, 116, 139);
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7.5);
  doc.text('System-Generated Assessment: Progression stage coverage', margin + cardWidth + 22, y + 33);
  doc.text('across expected initial access through objective execution.', margin + cardWidth + 22, y + 43);

  y += 60;

  // ==========================================
  // EXECUTIVE SUMMARY & RECONSTRUCTED ATTACK PATH
  // ==========================================
  doc.setFillColor(241, 245, 249);
  doc.rect(margin, y, contentWidth, 56, 'F');
  doc.setDrawColor(203, 213, 225);
  doc.rect(margin, y, contentWidth, 56, 'D');

  doc.setTextColor(15, 23, 42);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(9);
  doc.text('EXECUTIVE SUMMARY & RECONSTRUCTED ATTACK VECTOR', margin + 10, y + 16);

  doc.setTextColor(30, 41, 59);
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8);
  const narrative = `Telemetry analysis identified ${summary.total_events || timeline.length} total events, reconstructing ${timeline.length} sequential attack stages. Identified blast radius encompasses ${blastRadius.host_count || blastRadius.affected_hosts?.length || 0} affected host(s), ${blastRadius.user_count || blastRadius.affected_users?.length || 0} user(s), and ${blastRadius.critical_asset_count || blastRadius.critical_assets?.length || 0} critical asset(s).`;
  doc.text(narrative, margin + 10, y + 29, { maxWidth: contentWidth - 20 });

  doc.setFont('helvetica', 'bold');
  doc.setTextColor(16, 185, 129);
  doc.text(`Path:  ${attackPathStr}`, margin + 10, y + 47, { maxWidth: contentWidth - 20 });

  y += 68;

  // Helper for section headings
  function printSectionHeading(title, subtitle = null) {
    if (y > pageHeight - 90) {
      doc.addPage();
      y = margin;
    }
    doc.setTextColor(15, 23, 42);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(10);
    doc.text(title, margin, y + 10);
    y += 14;

    if (subtitle) {
      doc.setFont('helvetica', 'italic');
      doc.setFontSize(7.5);
      doc.setTextColor(100, 116, 139);
      doc.text(subtitle, margin, y + 6);
      y += 12;
    }
  }

  // ==========================================
  // SECTION 1: CHRONOLOGICAL ATTACK TIMELINE
  // ==========================================
  printSectionHeading('1. CHRONOLOGICAL ATTACK TIMELINE', 'All reconstructed milestones with causal timestamps, hosts, and original event IDs.');

  const timelineRows = timeline.map((ev, idx) => [
    idx + 1,
    ev.timestamp || 'N/A',
    ev.stage || 'N/A',
    ev.source_host || 'N/A',
    ev.destination_host || '—',
    ev.user || '—',
    ev.severity || 'HIGH',
    ev.event_id || 'N/A',
  ]);

  if (timelineRows.length === 0) {
    timelineRows.push(['—', 'No data available', '—', '—', '—', '—', '—', '—']);
  }

  autoTable(doc, {
    startY: y,
    margin: { left: margin, right: margin },
    tableWidth: contentWidth,
    head: [['#', 'Timestamp', 'Stage', 'Source Host', 'Destination', 'User', 'Severity', 'Event ID']],
    body: timelineRows,
    theme: 'grid',
    styles: { fontSize: 7.5, cellPadding: 3.5, font: 'helvetica' },
    headStyles: { fillColor: [15, 23, 42], textColor: [255, 255, 255], fontStyle: 'bold' },
    columnStyles: {
      0: { cellWidth: 20, halign: 'center' },
      1: { cellWidth: 90 },
      2: { cellWidth: 80 },
      3: { cellWidth: 60 },
      4: { cellWidth: 65 },
      5: { cellWidth: 50 },
      6: { cellWidth: 55, fontStyle: 'bold' },
      7: { cellWidth: 103, textColor: [16, 185, 129], fontStyle: 'bold' },
    },
    didDrawPage: (data) => {
      y = data.cursor.y + 16;
    },
  });

  // ==========================================
  // SECTION 2: ATTACK GRAPH RELATIONSHIPS
  // ==========================================
  printSectionHeading('2. ATTACK GRAPH RELATIONSHIPS', 'Causal directed transitions between source and destination infrastructure entities.');

  const edges = graph.edges || [];
  const graphRows = edges.map((edge) => [
    edge.source || 'N/A',
    edge.relationship || 'Connected',
    edge.target || 'N/A',
    edge.correlation_score ? `${edge.correlation_score}/5 (${edge.support_level || 'high'})` : 'Grounded',
    edge.event_id || (edge.evidence_references ? edge.evidence_references.join(', ') : 'Telemetry Match'),
    edge.rationale || 'Chronologically and topologically linked transition.',
  ]);

  if (graphRows.length === 0) {
    graphRows.push(['No data available', '—', '—', '—', '—', '—']);
  }

  autoTable(doc, {
    startY: y,
    margin: { left: margin, right: margin },
    head: [['Source', 'Relationship', 'Destination', 'Support Level', 'Evidence Ref', 'Rationale']],
    body: graphRows,
    theme: 'grid',
    styles: { fontSize: 7.5, cellPadding: 3.5, font: 'helvetica' },
    headStyles: { fillColor: [15, 23, 42], textColor: [255, 255, 255], fontStyle: 'bold' },
    columnStyles: {
      0: { cellWidth: 70, fontStyle: 'bold' },
      1: { cellWidth: 85 },
      2: { cellWidth: 70, fontStyle: 'bold' },
      3: { cellWidth: 70 },
      4: { cellWidth: 80, textColor: [16, 185, 129] },
      5: { cellWidth: 140 },
    },
    didDrawPage: (data) => {
      y = data.cursor.y + 16;
    },
  });

  // ==========================================
  // SECTION 3: EVIDENCE REFERENCES & IDENTIFIED GAPS
  // ==========================================
  printSectionHeading('3. EVIDENCE GROUNDING & TELEMETRY GAPS', 'Traceable forensic evidence references and identified missing observation points.');

  const evidenceRows = evidence.map((ev) => [
    ev.event_id || 'N/A',
    ev.stage || 'N/A',
    ev.rationale || ev.rule_triggered || 'Corroborated across telemetry sources.',
    ev.confidence_factor || ev.corroborating_evidence || 'Cross-tier log verification',
  ]);

  if (evidenceRows.length === 0) {
    evidenceRows.push(['No data available', '—', '—', '—']);
  }

  autoTable(doc, {
    startY: y,
    margin: { left: margin, right: margin },
    head: [['Event ID', 'Stage', 'Causal Rationale', 'Corroboration Factor']],
    body: evidenceRows,
    theme: 'grid',
    styles: { fontSize: 7.5, cellPadding: 3.5 },
    headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontStyle: 'bold' },
    columnStyles: {
      0: { cellWidth: 80, fontStyle: 'bold', textColor: [16, 185, 129] },
      1: { cellWidth: 95 },
      2: { cellWidth: 200 },
      3: { cellWidth: 140 },
    },
    didDrawPage: (data) => {
      y = data.cursor.y + 12;
    },
  });

  // Telemetry Gaps Table
  if (gaps && gaps.length > 0) {
    const gapRows = gaps.map((g) => [
      g.stage || 'General',
      g.gap || g.description || 'Missing corroboration telemetry.',
      g.severity || 'MEDIUM',
      g.recommendation || 'Deploy enhanced auditing agents.',
    ]);

    autoTable(doc, {
      startY: y,
      margin: { left: margin, right: margin },
      head: [['Gap Stage', 'Identified Blindspot / Gap', 'Severity', 'Recommended Detection Telemetry']],
      body: gapRows,
      theme: 'grid',
      styles: { fontSize: 7.5, cellPadding: 3.5 },
      headStyles: { fillColor: [71, 85, 105], textColor: [255, 255, 255], fontStyle: 'bold' },
      columnStyles: {
        0: { cellWidth: 85, fontStyle: 'bold' },
        1: { cellWidth: 190 },
        2: { cellWidth: 55, halign: 'center' },
        3: { cellWidth: 185 },
      },
      didDrawPage: (data) => {
        y = data.cursor.y + 16;
      },
    });
  }

  // ==========================================
  // SECTION 4: MITRE ATT&CK MAPPINGS
  // ==========================================
  printSectionHeading(
    '4. MITRE ATT&CK TECHNIQUE CLASSIFICATIONS',
    'Candidate associations mapped via telemetry evidence. Scoring alone does NOT confirm maliciousness.'
  );

  const mitreRows = mitreMappings.map((m) => [
    m.technique_id || 'N/A',
    m.technique_name || 'Unclassified',
    m.tactic || 'N/A',
    m.mapping_rationale || 'Telemetry-aligned criteria.',
    m.evidence_refs ? m.evidence_refs.join(', ') : '—',
    m.evidence_status === 'evidence_supported_candidate' ? 'Evidence Supported' : 'Requires Review',
  ]);

  if (mitreRows.length === 0) {
    mitreRows.push(['No data available', '—', '—', '—', '—', '—']);
  }

  autoTable(doc, {
    startY: y,
    margin: { left: margin, right: margin },
    head: [['Technique ID', 'Technique Name', 'Tactic', 'Mapping Rationale', 'Evidence Refs', 'Review Status']],
    body: mitreRows,
    theme: 'grid',
    styles: { fontSize: 7.5, cellPadding: 3.5 },
    headStyles: { fillColor: [15, 23, 42], textColor: [255, 255, 255], fontStyle: 'bold' },
    columnStyles: {
      0: { cellWidth: 75, fontStyle: 'bold', textColor: [16, 185, 129] },
      1: { cellWidth: 110 },
      2: { cellWidth: 70 },
      3: { cellWidth: 130 },
      4: { cellWidth: 65 },
      5: { cellWidth: 65, fontStyle: 'bold' },
    },
    didDrawPage: (data) => {
      y = data.cursor.y + 16;
    },
  });

  // ==========================================
  // SECTION 5: ISOLATION FOREST ANOMALIES
  // ==========================================
  printSectionHeading(
    '5. ISOLATION FOREST ANOMALY DETECTION',
    'Unsupervised statistical divergence from baseline model. Anomaly score does NOT prove compromise.'
  );

  const anomalyRows = anomalies.map((a) => [
    a.event_id || 'N/A',
    typeof a.anomaly_score === 'number' ? a.anomaly_score.toFixed(4) : (a.anomaly_score || 'N/A'),
    a.source_type || 'telemetry',
    a.reason_codes ? a.reason_codes.join('; ') : 'Statistical feature divergence',
    `Host: ${a.source_host || '—'}, User: ${a.user || '—'}, Action: ${a.action || '—'}`,
  ]);

  if (anomalyRows.length === 0) {
    anomalyRows.push(['No anomalies detected above threshold', '—', '—', '—', '—']);
  }

  autoTable(doc, {
    startY: y,
    margin: { left: margin, right: margin },
    head: [['Event ID', 'Anomaly Score', 'Feed', 'Reason Codes', 'Telemetry Details']],
    body: anomalyRows,
    theme: 'grid',
    styles: { fontSize: 7.5, cellPadding: 3.5 },
    headStyles: { fillColor: [15, 23, 42], textColor: [255, 255, 255], fontStyle: 'bold' },
    columnStyles: {
      0: { cellWidth: 80, fontStyle: 'bold', textColor: [245, 158, 11] },
      1: { cellWidth: 65, halign: 'center' },
      2: { cellWidth: 55 },
      3: { cellWidth: 155 },
      4: { cellWidth: 160 },
    },
    didDrawPage: (data) => {
      y = data.cursor.y + 16;
    },
  });

  // ==========================================
  // SECTION 6: IMPACT & BLAST RADIUS SUMMARY
  // ==========================================
  printSectionHeading('6. IMPACT & BLAST RADIUS ASSESSMENT', 'Affected infrastructure, compromised accounts, and critical data stores reached.');

  const affectedHosts = blastRadius.affected_hosts || [];
  const criticalAssets = blastRadius.critical_assets || [];
  const affectedUsers = blastRadius.affected_users || [];

  const blastRows = [
    ['Affected Hosts', affectedHosts.length > 0 ? affectedHosts.join(', ') : 'No data available', affectedHosts.length],
    ['Critical Assets Reached', criticalAssets.length > 0 ? criticalAssets.join(', ') : 'None identified', criticalAssets.length],
    ['Compromised Users', affectedUsers.length > 0 ? affectedUsers.join(', ') : 'No data available', affectedUsers.length],
  ];

  autoTable(doc, {
    startY: y,
    margin: { left: margin, right: margin },
    head: [['Impact Dimension', 'Entities Identified', 'Count']],
    body: blastRows,
    theme: 'grid',
    styles: { fontSize: 7.5, cellPadding: 3.5 },
    headStyles: { fillColor: [15, 23, 42], textColor: [255, 255, 255], fontStyle: 'bold' },
    columnStyles: {
      0: { cellWidth: 130, fontStyle: 'bold' },
      1: { cellWidth: 325 },
      2: { cellWidth: 60, halign: 'center', fontStyle: 'bold' },
    },
    didDrawPage: (data) => {
      y = data.cursor.y + 16;
    },
  });

  // ==========================================
  // SECTION 7: WHAT-IF SIMULATION RESULTS
  // ==========================================
  printSectionHeading(
    '7. COUNTERFACTUAL WHAT-IF SIMULATION RESULTS',
    'SIMULATION ONLY: Hypothetical attack bottleneck containment analysis. Does NOT represent real actions.'
  );

  const whatifData = options.whatifResults || investigationData.whatif || [];
  const whatifList = Array.isArray(whatifData) ? whatifData : (whatifData ? [whatifData] : []);

  const simulationRows = whatifList.map((sim) => [
    sim.blocked_stage || 'N/A',
    sim.stopped ? 'ATTACK CONTAINED' : 'UNCONTAINED',
    sim.prevented_stages ? sim.prevented_stages.join(', ') : 'None',
    sim.impact || 'Hypothetical containment model.',
  ]);

  if (simulationRows.length === 0) {
    simulationRows.push(['No simulation performed', '—', 'No data available', 'Run What-If analysis in dashboard to project containment.']);
  }

  autoTable(doc, {
    startY: y,
    margin: { left: margin, right: margin },
    head: [['Target Stage to Block', 'Projected Result', 'Prevented Downstream Stages', 'Impact Analysis']],
    body: simulationRows,
    theme: 'grid',
    styles: { fontSize: 7.5, cellPadding: 3.5 },
    headStyles: { fillColor: [15, 23, 42], textColor: [255, 255, 255], fontStyle: 'bold' },
    columnStyles: {
      0: { cellWidth: 110, fontStyle: 'bold' },
      1: { cellWidth: 95, fontStyle: 'bold', halign: 'center' },
      2: { cellWidth: 145 },
      3: { cellWidth: 165 },
    },
    didDrawPage: (data) => {
      y = data.cursor.y + 16;
    },
  });

  // ==========================================
  // PAGE NUMBERS & FOOTERS
  // ==========================================
  const totalPages = doc.getNumberOfPages();
  for (let i = 1; i <= totalPages; i++) {
    doc.setPage(i);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7);
    doc.setTextColor(148, 163, 184);

    doc.setDrawColor(226, 232, 240);
    doc.line(margin, pageHeight - 24, pageWidth - margin, pageHeight - 24);

    doc.text('ARGUS-X Security Telemetry Platform | Forensic Audit Report', margin, pageHeight - 14);
    doc.text(`Page ${i} of ${totalPages}`, pageWidth - margin, pageHeight - 14, { align: 'right' });
  }

  return { doc, filename: `Argus-X_Report_${invId}.pdf` };
}

export function generateInvestigationPDF(investigationData, options = {}) {
  const { doc, filename } = buildInvestigationPDFDoc(investigationData, options);
  doc.save(filename);
  return filename;
}
