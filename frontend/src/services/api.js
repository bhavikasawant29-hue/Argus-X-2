const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

export async function checkHealth() {
  try {
    const response = await fetch(`${API_BASE_URL}/api/health`);
    if (!response.ok) throw new Error(`Health check failed with status ${response.status}`);
    return await response.json();
  } catch (error) {
    throw new Error(`Backend unavailable: ${error.message}`);
  }
}

export async function fetchDemoIncident() {
  try {
    const response = await fetch(`${API_BASE_URL}/api/demo`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
    });
    if (!response.ok) {
      const errData = await response.json().catch(() => ({ detail: 'Unknown backend error' }));
      throw new Error(errData.detail || `Demo request failed with status ${response.status}`);
    }
    return await response.json();
  } catch (error) {
    throw new Error(error.message || 'Failed to load demo incident from backend');
  }
}

export async function analyzeTelemetry(fileMap) {
  try {
    const formData = new FormData();
    if (fileMap.authentication) formData.append('authentication', fileMap.authentication);
    if (fileMap.endpoint) formData.append('endpoint', fileMap.endpoint);
    if (fileMap.network) formData.append('network', fileMap.network);
    if (fileMap.application) formData.append('application', fileMap.application);

    const response = await fetch(`${API_BASE_URL}/api/analyze`, {
      method: 'POST',
      body: formData,
    });

    if (!response.ok) {
      const errData = await response.json().catch(() => ({ detail: 'Analysis failed' }));
      throw new Error(errData.detail || `Analysis failed with status ${response.status}`);
    }

    return await response.json();
  } catch (error) {
    throw new Error(error.message || 'Failed to analyze telemetry');
  }
}

export async function runAIInvestigation(query, selectedEvent = null, context = null) {
  try {
    const response = await fetch(`${API_BASE_URL}/api/investigate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        question: query,
        selected_event: selectedEvent,
        context: context,
      }),
    });

    if (!response.ok) {
      const errData = await response.json().catch(() => ({ detail: 'AI investigation request failed' }));
      throw new Error(errData.detail || `AI investigation failed with status ${response.status}`);
    }

    return await response.json();
  } catch (error) {
    throw new Error(error.message || 'Failed to communicate with AI investigator');
  }
}

export async function runCounterfactual(blockedStage) {
  try {
    const response = await fetch(`${API_BASE_URL}/api/counterfactual`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        blocked_stage: blockedStage,
      }),
    });

    if (!response.ok) {
      const errData = await response.json().catch(() => ({ detail: 'Counterfactual simulation failed' }));
      throw new Error(errData.detail || `Simulation failed with status ${response.status}`);
    }

    return await response.json();
  } catch (error) {
    throw new Error(error.message || 'Failed to execute counterfactual simulation');
  }
}

export async function fetchAnomalies(events = null, contamination = 0.05) {
  try {
    const response = await fetch(`${API_BASE_URL}/api/ml/anomalies`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ events, contamination }),
    });
    if (!response.ok) {
      const err = await response.json().catch(() => ({ detail: 'Anomaly detection failed' }));
      throw new Error(err.detail || `Anomaly request failed with status ${response.status}`);
    }
    return await response.json();
  } catch (error) {
    throw new Error(error.message || 'Failed to detect anomalies');
  }
}

export async function fetchVulnCorrelations() {
  try {
    const response = await fetch(`${API_BASE_URL}/api/vulnerabilities/correlate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });
    if (!response.ok) {
      const err = await response.json().catch(() => ({ detail: 'Correlation failed' }));
      throw new Error(err.detail || `Correlation request failed with status ${response.status}`);
    }
    return await response.json();
  } catch (error) {
    throw new Error(error.message || 'Failed to fetch vulnerability correlations');
  }
}

export async function fetchMitreTechniques(params = {}) {
  try {
    const query = new URLSearchParams();
    if (params.tactic) query.append('tactic', params.tactic);
    if (params.query) query.append('query', params.query);
    if (params.limit) query.append('limit', params.limit);

    const response = await fetch(`${API_BASE_URL}/api/mitre/techniques?${query.toString()}`);
    if (!response.ok) throw new Error(`MITRE query failed with status ${response.status}`);
    return await response.json();
  } catch (error) {
    throw new Error(error.message || 'Failed to fetch MITRE techniques');
  }
}

export async function mapMitreEvents(payload = {}) {
  try {
    const response = await fetch(`${API_BASE_URL}/api/mitre/map`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      const err = await response.json().catch(() => ({ detail: 'MITRE mapping failed' }));
      throw new Error(err.detail || `MITRE mapping request failed with status ${response.status}`);
    }
    return await response.json();
  } catch (error) {
    throw new Error(error.message || 'Failed to map events to MITRE ATT&CK');
  }
}
