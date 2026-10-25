import React, { useState, useRef, useEffect, useCallback, useMemo } from 'react';

export default function GraphTab({
  graph,
  timeline = [],
  selectedEvent,
  onSelectEvent,
  infrastructure = {},
  blastRadius = {},
}) {
  const containerRef = useRef(null);
  const [layoutDirection, setLayoutDirection] = useState('horizontal');
  const [zoomLevel, setZoomLevel] = useState(1);
  const [panOffset, setPanOffset] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const [selectedEdgeInfo, setSelectedEdgeInfo] = useState(null);

  const affectedHosts = blastRadius.affected_hosts || [];
  const criticalAssets = blastRadius.critical_assets || [];
  const affectedUsers = blastRadius.affected_users || [];

  // ==========================================
  // 1. EXTRACT & CLASSIFY ENTITIES
  // ==========================================
  const { entityNodes, graphEdges, attackPathNodeIds, observedOnlyNodeIds } = useMemo(() => {
    const entityMap = new Map();
    const attackPathSet = new Set();

    // Determine users involved in incident
    const timelineUsers = Array.from(new Set(timeline.map((e) => e.user).filter(Boolean)));
    const usersToInclude = affectedUsers.length > 0 ? affectedUsers : (timelineUsers.length > 0 ? timelineUsers : ['arjun']);

    usersToInclude.forEach((user) => {
      const id = `user:${user}`;
      entityMap.set(id, {
        id,
        name: user,
        type: 'user',
        label: 'User Account',
        status: 'USER',
        icon: 'person',
        color: 'green',
        events: timeline.filter((e) => e.user === user),
      });
      attackPathSet.add(id);
    });

    // Add hosts involved in reconstructed attack timeline
    timeline.forEach((event) => {
      const srcHost = event.source_host;
      const destHost = event.destination_host;

      [srcHost, destHost].forEach((host) => {
        if (host && !entityMap.has(`host:${host}`)) {
          const isCritical = criticalAssets.includes(host) || host.toUpperCase().startsWith('DB');
          const isCompromised = affectedHosts.includes(host) || timeline.some((e) => e.source_host === host || e.destination_host === host);

          let icon = 'desktop_windows';
          let subLabel = 'Workstation';
          const upper = host.toUpperCase();
          if (upper.startsWith('DB') || upper.includes('DATABASE')) {
            icon = 'database';
            subLabel = 'Database Server';
          } else if (upper.startsWith('SRV') || upper.includes('APP') || upper.includes('SERVER')) {
            icon = 'dns';
            subLabel = 'App Server';
          } else if (upper.startsWith('DC') || upper.includes('DOMAIN')) {
            icon = 'domain';
            subLabel = 'Domain Controller';
          }

          entityMap.set(`host:${host}`, {
            id: `host:${host}`,
            name: host,
            type: 'host',
            label: subLabel,
            status: isCritical ? 'CRITICAL ASSET' : isCompromised ? 'COMPROMISED' : 'INVOLVED',
            icon,
            color: isCritical ? 'red' : isCompromised ? 'red' : 'amber',
            events: timeline.filter((e) => e.source_host === host || e.destination_host === host),
          });
          attackPathSet.add(`host:${host}`);
        }
      });
    });

    // Build directed edges from actual reconstructed events
    const edges = [];
    const firstEvent = timeline.find((e) => e.user && e.source_host) || timeline[0];
    if (firstEvent && firstEvent.user && firstEvent.source_host) {
      const timeStr = firstEvent.timestamp ? (firstEvent.timestamp.includes('T') ? firstEvent.timestamp.split('T')[1].replace('Z', '') : firstEvent.timestamp) : '';
      edges.push({
        id: `edge:user->${firstEvent.source_host}`,
        source: `user:${firstEvent.user}`,
        target: `host:${firstEvent.source_host}`,
        relationship: 'Authenticates',
        timestamp: timeStr,
        event: firstEvent,
        type: 'user-auth',
      });
    }

    // Host -> Host Transitions
    timeline.forEach((event) => {
      const srcHost = event.source_host;
      const destHost = event.destination_host;

      if (srcHost && destHost && srcHost !== destHost) {
        const edgeId = `edge:${srcHost}->${destHost}`;
        if (!edges.some((e) => e.id === edgeId)) {
          let relLabel = 'Lateral Movement';
          const dUpper = destHost.toUpperCase();
          if (dUpper.startsWith('DB') || event.stage === 'Database Access') {
            relLabel = 'Database Connection';
          } else if (event.stage === 'Privilege Escalation') {
            relLabel = 'Privilege Escalation';
          } else if (event.stage === 'Initial Access') {
            relLabel = 'Initial Access';
          } else if (event.stage === 'Credential Access') {
            relLabel = 'Credential Access';
          }

          const timeStr = event.timestamp ? (event.timestamp.includes('T') ? event.timestamp.split('T')[1].replace('Z', '') : event.timestamp) : '';

          edges.push({
            id: edgeId,
            source: `host:${srcHost}`,
            target: `host:${destHost}`,
            relationship: relLabel,
            timestamp: timeStr,
            event: event,
            type: 'host-transition',
          });
        }
      }
    });

    // Add observed-only infrastructure from infrastructure.hosts and infrastructure.source_ips
    const allInfraHosts = infrastructure.hosts || [];
    const allInfraIPs = infrastructure.source_ips || [];
    const observedSet = new Set();

    [...allInfraHosts, ...allInfraIPs].forEach((item) => {
      if (!item) return;
      const nodeId = `host:${item}`;
      if (!entityMap.has(nodeId)) {
        let icon = 'computer';
        let subLabel = 'Host';
        const itemUpper = item.toUpperCase();

        if (itemUpper.startsWith('APP')) {
          icon = 'dns';
          subLabel = 'App Server';
        } else if (itemUpper.startsWith('DC')) {
          icon = 'domain';
          subLabel = 'Domain Controller';
        } else if (itemUpper.startsWith('WS') || itemUpper.startsWith('PC')) {
          icon = 'desktop_windows';
          subLabel = 'Workstation';
        } else if (item.includes('.') && item.split('.').length === 4) {
          icon = 'language';
          subLabel = 'External IP';
        }

        entityMap.set(nodeId, {
          id: nodeId,
          name: item,
          type: 'observed',
          label: subLabel,
          status: 'OBSERVED',
          icon,
          color: 'blue',
          events: [],
        });
        observedSet.add(nodeId);
      }
    });

    return {
      entityNodes: Array.from(entityMap.values()),
      graphEdges: edges,
      attackPathNodeIds: attackPathSet,
      observedOnlyNodeIds: observedSet,
    };
  }, [timeline, blastRadius, infrastructure]);

  // ==========================================
  // 2. TOPOLOGICAL & HIERARCHICAL LAYOUT
  // ==========================================
  const { nodePositions, observedClusterBounds, layoutBounds } = useMemo(() => {
    const positions = new Map();

    // Separate attack-path chain vs observed-only nodes
    const userNodes = entityNodes.filter((n) => n.type === 'user');
    const attackHostNodes = entityNodes.filter((n) => n.type !== 'user' && attackPathNodeIds.has(n.id));
    const observedNodes = entityNodes.filter((n) => observedOnlyNodeIds.has(n.id));

    // Sort attack hosts in topological order according to edge transitions
    const orderedAttackHosts = [];
    const visited = new Set();

    // Start with hosts that user directly authenticates with
    const initialHosts = graphEdges
      .filter((e) => e.type === 'user-auth')
      .map((e) => e.target);

    const queue = [...initialHosts];
    while (queue.length > 0) {
      const currentId = queue.shift();
      if (!visited.has(currentId)) {
        visited.add(currentId);
        const node = attackHostNodes.find((h) => h.id === currentId);
        if (node) orderedAttackHosts.push(node);

        // Find outgoing targets from currentId
        graphEdges
          .filter((e) => e.source === currentId)
          .forEach((e) => {
            if (!visited.has(e.target)) queue.push(e.target);
          });
      }
    }

    // Add any remaining attack hosts that were not traversed
    attackHostNodes.forEach((node) => {
      if (!visited.has(node.id)) {
        visited.add(node.id);
        orderedAttackHosts.push(node);
      }
    });

    const primaryChain = [...userNodes, ...orderedAttackHosts];

    let minX = Infinity;
    let maxX = -Infinity;
    let minY = Infinity;
    let maxY = -Infinity;

    let obsBounds = null;

    if (layoutDirection === 'horizontal') {
      const startX = 120;
      const attackPathY = 140;
      const stepX = 230;

      // 1. Position Primary Continuous Attack Chain horizontally
      primaryChain.forEach((node, idx) => {
        const x = startX + idx * stepX;
        const y = attackPathY;
        positions.set(node.id, { x, y });

        minX = Math.min(minX, x - 65);
        maxX = Math.max(maxX, x + 65);
        minY = Math.min(minY, y - 65);
        maxY = Math.max(maxY, y + 65);
      });

      // 2. Position Observed-Only Cluster neatly in secondary lower region
      if (observedNodes.length > 0) {
        const chainMidX = primaryChain.length > 0
          ? (startX + (primaryChain.length - 1) * stepX) / 2
          : 300;
        const observedY = attackPathY + 180;
        const obsStepX = 170;
        const totalObsWidth = Math.max(340, (observedNodes.length - 1) * obsStepX + 160);
        const obsStartX = chainMidX - ((observedNodes.length - 1) * obsStepX) / 2;

        observedNodes.forEach((node, idx) => {
          const x = obsStartX + idx * obsStepX;
          const y = observedY + 36;
          positions.set(node.id, { x, y });

          minX = Math.min(minX, x - 65);
          maxX = Math.max(maxX, x + 65);
          minY = Math.min(minY, y - 65);
          maxY = Math.max(maxY, y + 65);
        });

        obsBounds = {
          x: chainMidX - totalObsWidth / 2,
          y: observedY - 14,
          width: totalObsWidth,
          height: 120,
          labelX: chainMidX,
          labelY: observedY + 6,
        };

        minX = Math.min(minX, obsBounds.x);
        maxX = Math.max(maxX, obsBounds.x + obsBounds.width);
        minY = Math.min(minY, obsBounds.y);
        maxY = Math.max(maxY, obsBounds.y + obsBounds.height);
      }
    } else {
      // Vertical Hierarchical Layout
      const startY = 90;
      const attackPathX = 200;
      const stepY = 160;

      primaryChain.forEach((node, idx) => {
        const x = attackPathX;
        const y = startY + idx * stepY;
        positions.set(node.id, { x, y });

        minX = Math.min(minX, x - 65);
        maxX = Math.max(maxX, x + 65);
        minY = Math.min(minY, y - 65);
        maxY = Math.max(maxY, y + 65);
      });

      // Position Observed Nodes in column to the right
      if (observedNodes.length > 0) {
        const obsX = attackPathX + 220;
        const obsStartY = startY + 40;
        const obsStepY = 140;
        const totalObsHeight = Math.max(260, (observedNodes.length - 1) * obsStepY + 160);

        observedNodes.forEach((node, idx) => {
          const x = obsX + 50;
          const y = obsStartY + idx * obsStepY;
          positions.set(node.id, { x, y });

          minX = Math.min(minX, x - 65);
          maxX = Math.max(maxX, x + 65);
          minY = Math.min(minY, y - 65);
          maxY = Math.max(maxY, y + 65);
        });

        obsBounds = {
          x: obsX - 20,
          y: obsStartY - 40,
          width: 140,
          height: totalObsHeight,
          labelX: obsX + 50,
          labelY: obsStartY - 20,
        };

        minX = Math.min(minX, obsBounds.x);
        maxX = Math.max(maxX, obsBounds.x + obsBounds.width);
        minY = Math.min(minY, obsBounds.y);
        maxY = Math.max(maxY, obsBounds.y + obsBounds.height);
      }
    }

    if (!isFinite(minX)) {
      minX = 0;
      maxX = 800;
      minY = 0;
      maxY = 400;
    }

    return {
      nodePositions: positions,
      observedClusterBounds: obsBounds,
      layoutBounds: {
        minX,
        maxX,
        minY,
        maxY,
        width: Math.max(400, maxX - minX + 120),
        height: Math.max(300, maxY - minY + 120),
      },
    };
  }, [entityNodes, graphEdges, attackPathNodeIds, observedOnlyNodeIds, layoutDirection]);

  // ==========================================
  // 3. FIT TO VIEW & RESPONSIVE CENTERING
  // ==========================================
  const fitToView = useCallback(() => {
    if (!containerRef.current) return;
    const container = containerRef.current;
    const containerW = container.clientWidth || 900;
    const containerH = container.clientHeight || 450;

    const pad = 48;
    const scaleX = (containerW - pad * 2) / layoutBounds.width;
    const scaleY = (containerH - pad * 2) / layoutBounds.height;
    const targetScale = Math.min(1.05, Math.max(0.65, Math.min(scaleX, scaleY)));

    const scaledW = layoutBounds.width * targetScale;
    const scaledH = layoutBounds.height * targetScale;

    const offsetX = (containerW - scaledW) / 2 - (layoutBounds.minX - 60) * targetScale;
    const offsetY = (containerH - scaledH) / 2 - (layoutBounds.minY - 50) * targetScale;

    setZoomLevel(targetScale);
    setPanOffset({ x: offsetX, y: offsetY });
  }, [layoutBounds]);

  // Auto-fit on initial render or resize
  useEffect(() => {
    fitToView();
    const handleResize = () => fitToView();
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, [fitToView]);

  // ==========================================
  // 4. PAN & ZOOM HANDLERS
  // ==========================================
  const handleMouseDown = (e) => {
    if (e.target.closest('.interactive-node') || e.target.closest('.interactive-edge')) {
      return;
    }
    setIsDragging(true);
    setDragStart({ x: e.clientX - panOffset.x, y: e.clientY - panOffset.y });
  };

  const handleMouseMove = (e) => {
    if (!isDragging) return;
    setPanOffset({
      x: e.clientX - dragStart.x,
      y: e.clientY - dragStart.y,
    });
  };

  const handleMouseUp = () => setIsDragging(false);

  const handleWheel = (e) => {
    e.preventDefault();
    const zoomFactor = e.deltaY < 0 ? 1.08 : 0.92;
    setZoomLevel((prev) => Math.min(1.6, Math.max(0.5, prev * zoomFactor)));
  };

  // Node & Edge Clicks
  const handleNodeClick = (node) => {
    setSelectedEdgeInfo(null);
    if (node.events && node.events.length > 0 && onSelectEvent) {
      onSelectEvent(node.events[0]);
    }
  };

  const handleEdgeClick = (edge) => {
    setSelectedEdgeInfo(edge);
    if (edge.event && onSelectEvent) {
      onSelectEvent(edge.event);
    }
  };

  const handleEventRowClick = (eventNode) => {
    setSelectedEdgeInfo(null);
    const ev = timeline.find((item) => item.event_id === eventNode.id);
    if (ev && onSelectEvent) onSelectEvent(ev);
  };

  if (!graph || !graph.nodes) {
    return <div className="p-6 text-muted text-xs font-mono-code">No graph data available.</div>;
  }

  const nodes = graph.nodes || [];

  return (
    <div className="border border-main bg-surface p-6 rounded space-y-6">
      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-main gap-4">
        <div className="space-y-0.5">
          <h2 className="text-base font-bold text-primary flex items-center space-x-2">
            <span>Infrastructure Attack Graph</span>
          </h2>
          <p className="text-xs text-muted">
            Continuous reconstructed attack path with isolated observed infrastructure cluster
          </p>
        </div>

        {/* Legend Badges & Controls */}
        <div className="flex flex-wrap items-center gap-3 text-xs font-mono-code">
          {/* Legend Items */}
          <div className="flex items-center space-x-3 bg-main/80 border border-main px-3 py-1.5 rounded">
            <span className="flex items-center space-x-1">
              <span className="w-2.5 h-2.5 rounded-full bg-[#ef4444] shadow-[0_0_6px_#ef4444]" />
              <span className="text-muted">Compromised</span>
            </span>
            <span className="flex items-center space-x-1">
              <span className="w-2.5 h-2.5 rounded-full bg-[#ef4444] border border-white" />
              <span className="text-muted">Critical Asset</span>
            </span>
            <span className="flex items-center space-x-1">
              <span className="w-2.5 h-2.5 rounded-full bg-[#3b82f6]" />
              <span className="text-muted">Observed</span>
            </span>
            <span className="flex items-center space-x-1">
              <span className="w-2.5 h-2.5 rounded-full bg-[#10b981]" />
              <span className="text-muted">User</span>
            </span>
          </div>

          {/* Controls */}
          <div className="flex items-center space-x-2">
            <select
              value={layoutDirection}
              onChange={(e) => {
                setLayoutDirection(e.target.value);
                setTimeout(fitToView, 50);
              }}
              className="bg-main border border-main text-primary text-xs rounded px-2.5 py-1 font-mono-code focus:outline-none"
            >
              <option value="horizontal">Layout: Horizontal</option>
              <option value="vertical">Layout: Vertical</option>
            </select>

            <button
              onClick={() => setZoomLevel((z) => Math.min(z + 0.1, 1.6))}
              className="p-1 bg-main hover:bg-surface border border-main rounded text-primary text-xs"
              title="Zoom In"
            >
              <span className="material-symbols-outlined text-sm">add</span>
            </button>
            <button
              onClick={() => setZoomLevel((z) => Math.max(z - 0.1, 0.5))}
              className="p-1 bg-main hover:bg-surface border border-main rounded text-primary text-xs"
              title="Zoom Out"
            >
              <span className="material-symbols-outlined text-sm">remove</span>
            </button>
            <button
              onClick={fitToView}
              className="p-1 bg-main hover:bg-surface border border-[#10b981]/50 text-[#10b981] rounded text-xs"
              title="Fit to View (Center Graph)"
            >
              <span className="material-symbols-outlined text-sm">crop_free</span>
            </button>
          </div>
        </div>
      </div>

      {/* Main Interactive Node-Edge SVG + Canvas Viewport */}
      <div
        ref={containerRef}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
        onWheel={handleWheel}
        className={`relative bg-main/90 border border-main rounded-lg overflow-hidden min-h-[460px] h-[520px] select-none ${
          isDragging ? 'cursor-grabbing' : 'cursor-grab'
        }`}
      >
        {/* Canvas World Transform Container */}
        <div
          className="absolute inset-0 origin-top-left transition-transform duration-75"
          style={{
            transform: `translate(${panOffset.x}px, ${panOffset.y}px) scale(${zoomLevel})`,
          }}
        >
          {/* SVG Connector & Cluster Box Layer */}
          <svg
            className="absolute inset-0 pointer-events-none z-0"
            style={{
              width: `${Math.max(layoutBounds.width + 500, 2000)}px`,
              height: `${Math.max(layoutBounds.height + 500, 1600)}px`,
            }}
          >
            <defs>
              <marker
                id="arrow-green"
                viewBox="0 0 10 10"
                refX="26"
                refY="5"
                markerWidth="6"
                markerHeight="6"
                orient="auto-start-reverse"
              >
                <path d="M 0 0 L 10 5 L 0 10 z" fill="#10b981" />
              </marker>
              <marker
                id="arrow-red"
                viewBox="0 0 10 10"
                refX="28"
                refY="5"
                markerWidth="6"
                markerHeight="6"
                orient="auto-start-reverse"
              >
                <path d="M 0 0 L 10 5 L 0 10 z" fill="#ef4444" />
              </marker>
            </defs>

            {/* Observed-Only Cluster Region Card */}
            {observedClusterBounds && (
              <g className="transition-all">
                <rect
                  x={observedClusterBounds.x}
                  y={observedClusterBounds.y}
                  width={observedClusterBounds.width}
                  height={observedClusterBounds.height}
                  rx="8"
                  fill="rgba(59, 130, 246, 0.03)"
                  stroke="rgba(59, 130, 246, 0.35)"
                  strokeWidth="1.5"
                  strokeDasharray="5 5"
                />
                <text
                  x={observedClusterBounds.labelX}
                  y={observedClusterBounds.labelY}
                  textAnchor="middle"
                  fill="#60a5fa"
                  fontSize="8.5"
                  fontFamily="JetBrains Mono, monospace"
                  fontWeight="600"
                  letterSpacing="0.05em"
                >
                  OBSERVED INFRASTRUCTURE (MONITORED TELEMETRY · NO ATTACK PATH CONNECTION)
                </text>
              </g>
            )}

            {/* Directed Edge Connectors */}
            {graphEdges.map((edge) => {
              const srcPos = nodePositions.get(edge.source);
              const destPos = nodePositions.get(edge.target);

              if (!srcPos || !destPos) return null;

              const isSelected = selectedEdgeInfo && selectedEdgeInfo.id === edge.id;
              const markerId = edge.type === 'user-auth' ? 'url(#arrow-green)' : 'url(#arrow-red)';
              const strokeColor = isSelected
                ? '#10b981'
                : edge.type === 'user-auth'
                ? '#10b981'
                : '#ef4444';

              const midX = (srcPos.x + destPos.x) / 2;
              const midY = (srcPos.y + destPos.y) / 2;

              const labelText = edge.relationship || 'Connected';
              const pillWidth = Math.max(96, labelText.length * 7.5 + 24);

              return (
                <g
                  key={edge.id}
                  className="interactive-edge pointer-events-auto cursor-pointer"
                  onClick={() => handleEdgeClick(edge)}
                >
                  <line
                    x1={srcPos.x}
                    y1={srcPos.y}
                    x2={destPos.x}
                    y2={destPos.y}
                    stroke={strokeColor}
                    strokeWidth={isSelected ? 3.5 : 2}
                    strokeDasharray={edge.type === 'user-auth' ? '4,4' : 'none'}
                    markerEnd={markerId}
                    className="transition-all hover:stroke-width-3"
                  />

                  {/* Edge Label Pill */}
                  <g transform={`translate(${midX}, ${midY - 14})`}>
                    <rect
                      x={-pillWidth / 2}
                      y="-10"
                      width={pillWidth}
                      height="20"
                      rx="4"
                      fill="#13151b"
                      stroke={isSelected ? '#10b981' : '#2d3342'}
                      strokeWidth="1.2"
                    />
                    <text
                      x="0"
                      y="3.5"
                      textAnchor="middle"
                      fill={isSelected ? '#10b981' : '#cbd5e1'}
                      fontSize="9"
                      fontFamily="JetBrains Mono, monospace"
                      fontWeight="600"
                    >
                      {labelText}
                    </text>
                  </g>

                  {/* Timestamp Sublabel */}
                  {edge.timestamp && (
                    <text
                      x={midX}
                      y={midY + 16}
                      textAnchor="middle"
                      fill="#64748b"
                      fontSize="8"
                      fontFamily="JetBrains Mono, monospace"
                    >
                      {edge.timestamp}
                    </text>
                  )}
                </g>
              );
            })}
          </svg>

          {/* HTML Node Elements Layer */}
          <div className="absolute inset-0 pointer-events-none z-10">
            {entityNodes.map((node) => {
              const pos = nodePositions.get(node.id) || { x: 100, y: 140 };
              const isSelected =
                selectedEvent &&
                (selectedEvent.user === node.name ||
                  selectedEvent.source_host === node.name ||
                  selectedEvent.destination_host === node.name);

              const isCritical = node.status === 'CRITICAL ASSET';
              const isCompromised = node.status === 'COMPROMISED';
              const isUser = node.type === 'user';
              const isObserved = node.status === 'OBSERVED';

              return (
                <div
                  key={node.id}
                  onClick={() => handleNodeClick(node)}
                  style={{
                    position: 'absolute',
                    left: `${pos.x}px`,
                    top: `${pos.y}px`,
                    transform: 'translate(-50%, -50%)',
                  }}
                  className="interactive-node pointer-events-auto cursor-pointer group flex flex-col items-center select-none"
                >
                  {/* Circular Node Symbol */}
                  <div
                    className={`w-14 h-14 rounded-full flex items-center justify-center transition-all duration-300 ${
                      isCritical
                        ? isSelected
                          ? 'bg-[#ef4444]/35 border-2 border-[#ef4444] shadow-[0_0_25px_rgba(239,68,68,0.7)]'
                          : 'bg-[#ef4444]/20 border-2 border-[#ef4444] shadow-[0_0_15px_rgba(239,68,68,0.4)]'
                        : isCompromised
                        ? isSelected
                          ? 'bg-[#ef4444]/35 border-2 border-[#ef4444] shadow-[0_0_20px_rgba(239,68,68,0.6)]'
                          : 'bg-[#ef4444]/20 border-2 border-[#ef4444]/90'
                        : isUser
                        ? isSelected
                          ? 'bg-[#10b981]/35 border-2 border-[#10b981] shadow-[0_0_20px_rgba(16,185,129,0.6)]'
                          : 'bg-[#10b981]/20 border-2 border-[#10b981]'
                        : isObserved
                        ? 'bg-surface border-2 border-[#3b82f6]/70 hover:border-[#3b82f6] shadow-sm'
                        : 'bg-surface border-2 border-[#f59e0b]/70 hover:border-[#f59e0b]'
                    }`}
                  >
                    <span
                      className={`material-symbols-outlined text-2xl ${
                        isCritical || isCompromised
                          ? 'text-[#ef4444]'
                          : isUser
                          ? 'text-[#10b981]'
                          : isObserved
                          ? 'text-[#3b82f6]'
                          : 'text-[#f59e0b]'
                      }`}
                    >
                      {node.icon}
                    </span>
                  </div>

                  {/* Entity Label below circle */}
                  <div className="mt-2 text-center flex flex-col items-center max-w-[140px]">
                    <span className="text-xs font-bold font-mono-code text-primary tracking-wide truncate w-full" title={node.name}>
                      {node.name}
                    </span>
                    <span className="text-[10px] font-mono-code text-muted truncate w-full">
                      {node.label}
                    </span>

                    {/* Status Pill */}
                    <span
                      className={`mt-1 text-[8px] font-mono-code px-2 py-0.5 rounded font-bold uppercase tracking-wider ${
                        isCritical
                          ? 'bg-[#ef4444] text-white shadow-sm'
                          : isCompromised
                          ? 'bg-[#ef4444]/20 border border-[#ef4444]/50 text-[#ef4444]'
                          : isUser
                          ? 'bg-[#10b981]/20 border border-[#10b981]/40 text-[#10b981]'
                          : isObserved
                          ? 'bg-[#3b82f6]/15 border border-[#3b82f6]/40 text-[#60a5fa]'
                          : 'bg-main border border-main text-muted'
                      }`}
                    >
                      {node.status}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Edge Details Card */}
      {selectedEdgeInfo && (
        <div className="p-4 border border-[#10b981]/40 bg-[#10b981]/10 rounded space-y-1 text-xs font-mono-code flex items-center justify-between">
          <div>
            <div className="font-semibold text-primary">
              Causal Relationship: <span className="text-[#10b981]">{selectedEdgeInfo.source}</span> → <span className="text-[#10b981]">{selectedEdgeInfo.target}</span>
            </div>
            <div className="text-muted mt-0.5">
              Type: <span className="font-bold text-primary">{selectedEdgeInfo.relationship}</span> | Triggering Event: <span className="text-[#10b981]">{selectedEdgeInfo.event?.event_id}</span>
            </div>
          </div>
          <button
            onClick={() => setSelectedEdgeInfo(null)}
            className="text-xs text-muted hover:text-primary underline px-2 py-1"
          >
            Clear
          </button>
        </div>
      )}

      {/* Secondary Section: Event Correlation Roster */}
      <div className="space-y-3 pt-2">
        <div className="flex items-center justify-between">
          <span className="text-xs font-mono-code text-muted uppercase">
            EVENT CORRELATION TELEMETRY ROSTER ({nodes.length} EVENTS)
          </span>
          <span className="text-[10px] font-mono-code text-muted">
            Click row to inspect in Event Inspector
          </span>
        </div>

        <div className="overflow-x-auto border border-main rounded">
          <table className="w-full text-left text-xs font-mono-code">
            <thead className="bg-main/90 border-b border-main text-muted">
              <tr>
                <th className="p-2.5">Event ID</th>
                <th className="p-2.5">Stage</th>
                <th className="p-2.5">Event Type</th>
                <th className="p-2.5">Source Host</th>
                <th className="p-2.5">Destination Host</th>
                <th className="p-2.5">Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-main bg-surface">
              {nodes.map((node) => {
                const isSelected = selectedEvent && (selectedEvent.event_id === node.id || selectedEvent.id === node.id);

                return (
                  <tr
                    key={node.id}
                    onClick={() => handleEventRowClick(node)}
                    className={`cursor-pointer transition-colors ${
                      isSelected
                        ? 'bg-[#10b981]/15 font-semibold text-primary'
                        : 'hover:bg-main/50 text-muted'
                    }`}
                  >
                    <td className="p-2.5 text-[#10b981] font-semibold">{node.id}</td>
                    <td className="p-2.5 text-primary">{node.stage}</td>
                    <td className="p-2.5">{node.label}</td>
                    <td className="p-2.5 text-primary">{node.host || 'N/A'}</td>
                    <td className="p-2.5 text-primary">{node.destination || 'N/A'}</td>
                    <td className="p-2.5">{node.timestamp}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
