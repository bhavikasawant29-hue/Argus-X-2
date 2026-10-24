import React, { useState } from 'react';
import Sidebar from './Sidebar';
import EventInspector from './EventInspector';
import OverviewTab from './OverviewTab';
import TimelineTab from './TimelineTab';
import GraphTab from './GraphTab';
import EvidenceTab from './EvidenceTab';
import GapsTab from './GapsTab';
import ImpactTab from './ImpactTab';
import AIInvestigatorTab from './AIInvestigatorTab';
import WhatIfTab from './WhatIfTab';
import ReplayTab from './ReplayTab';
import InfrastructureTab from './InfrastructureTab';
import MitreTab from './MitreTab';
import AnomaliesTab from './AnomaliesTab';
import VulnCorrelationTab from './VulnCorrelationTab';

export default function DashboardView({ investigationData }) {
  const [activeTab, setActiveTab] = useState('overview');
  const [isSidebarCollapsed, setIsSidebarCollapsed] = useState(false);
  const [selectedEvent, setSelectedEvent] = useState(() => {
    return investigationData?.timeline?.[0] || null;
  });

  if (!investigationData) {
    return <div className="p-8 text-center text-muted text-xs font-mono-code">No investigation data available.</div>;
  }

  const timeline = investigationData.timeline || [];
  const evidence = investigationData.evidence || [];
  const graph = investigationData.graph || { nodes: [], edges: [] };
  const gaps = investigationData.gaps || [];
  const recommendations = investigationData.recommendations || [];
  const blastRadius = investigationData.blast_radius || {};
  const infrastructure = investigationData.infrastructure || {};
  const replay = investigationData.replay || [];
  const mitreMappings = investigationData.mitre_mappings || [];
  const anomalies = investigationData.anomalies || [];
  const vulnCorrelations = investigationData.vuln_correlations || null;

  const handleInspectRawEvent = (refId) => {
    const found = timeline.find(e => e.event_id === refId) || evidence.find(e => e.event_id === refId);
    if (found) {
      setSelectedEvent(found);
    }
  };

  const handleAskAIAboutEvent = (event) => {
    setSelectedEvent(event);
    setActiveTab('ai');
  };

  const renderActiveTab = () => {
    switch (activeTab) {
      case 'overview':
        return <OverviewTab data={investigationData} selectedEvent={selectedEvent} onSelectEvent={setSelectedEvent} />;
      case 'timeline':
        return <TimelineTab timeline={timeline} selectedEvent={selectedEvent} onSelectEvent={setSelectedEvent} />;
      case 'graph':
        return (
          <GraphTab
            graph={graph}
            timeline={timeline}
            selectedEvent={selectedEvent}
            onSelectEvent={setSelectedEvent}
            infrastructure={infrastructure}
            blastRadius={blastRadius}
          />
        );
      case 'evidence':
        return <EvidenceTab evidence={evidence} timeline={timeline} onInspectRawEvent={handleInspectRawEvent} />;
      case 'gaps':
        return <GapsTab gaps={gaps} recommendations={recommendations} />;
      case 'impact':
        return (
          <ImpactTab
            blastRadius={blastRadius}
            timeline={timeline}
            selectedEvent={selectedEvent}
            onSelectEvent={setSelectedEvent}
            infrastructure={infrastructure}
          />
        );
      case 'mitre':
        return <MitreTab mitreMappings={mitreMappings} onInspectRawEvent={handleInspectRawEvent} />;
      case 'anomalies':
        return <AnomaliesTab anomalies={anomalies} onInspectRawEvent={handleInspectRawEvent} />;
      case 'vulncorr':
        return (
          <VulnCorrelationTab
            vulnCorrelations={vulnCorrelations}
            onInspectRawEvent={handleInspectRawEvent}
            onGoToTimeline={() => setActiveTab('timeline')}
          />
        );
      case 'ai':
        return (
          <AIInvestigatorTab
            timeline={timeline}
            evidence={evidence}
            gaps={gaps}
            blastRadius={blastRadius}
            onInspectRawEvent={handleInspectRawEvent}
          />
        );
      case 'whatif':
        return <WhatIfTab timeline={timeline} />;
      case 'replay':
        return <ReplayTab replay={replay} onSelectEvent={setSelectedEvent} />;
      case 'infra':
        return <InfrastructureTab infrastructure={infrastructure} blastRadius={blastRadius} />;
      default:
        return <OverviewTab data={investigationData} selectedEvent={selectedEvent} onSelectEvent={setSelectedEvent} />;
    }
  };

  return (
    <div className="flex-1 flex overflow-hidden bg-main">
      {/* Collapsible Sidebar Nav */}
      <Sidebar
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        isCollapsed={isSidebarCollapsed}
        onToggleCollapse={() => setIsSidebarCollapsed(!isSidebarCollapsed)}
        stats={{
          confidence: investigationData.confidence ?? 0,
          completeness: investigationData.completeness ?? 0,
        }}
      />

      {/* Main Workspace Pane */}
      <main className="flex-1 overflow-y-auto p-6 space-y-6">
        {renderActiveTab()}
      </main>

      {/* Persistent Event Inspector Pane */}
      <EventInspector
        selectedEvent={selectedEvent}
        onInspectRawEvent={handleInspectRawEvent}
        onAskAI={handleAskAIAboutEvent}
      />
    </div>
  );
}
