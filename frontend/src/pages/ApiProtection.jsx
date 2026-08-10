import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Activity, BarChart2, Clock, Globe, ShieldCheck } from 'lucide-react';
import { PieChart, Pie, Cell, Tooltip as RechartsTooltip, ResponsiveContainer } from 'recharts';
import { getApiProtectionAnalytics, getDiscoveredEndpoints, getRecentlyDiscoveredEndpoints } from '../services/api';

export default function ApiProtection() {
  const [loading, setLoading] = useState(true);
  const [endpoints, setEndpoints] = useState([]);
  const [recentlyDiscovered, setRecentlyDiscovered] = useState([]);
  const [analytics, setAnalytics] = useState(null);
  const [activeTab, setActiveTab] = useState('inventory'); // 'inventory', 'recent'
  const [topListTab, setTopListTab] = useState('consumed'); // 'consumed', 'resource'

  const fetchData = async () => {
    try {
      const [epsData, recentData, analyticsData] = await Promise.all([
        getDiscoveredEndpoints(),
        getRecentlyDiscoveredEndpoints(),
        getApiProtectionAnalytics()
      ]);
      setEndpoints(epsData);
      setRecentlyDiscovered(recentData);
      setAnalytics(analyticsData);
    } catch (err) {
      console.error("Failed to fetch API protection data", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const timer = setTimeout(() => {
      fetchData();
    }, 0);
    const interval = setInterval(fetchData, 10000); // refresh every 10 seconds
    return () => {
      clearTimeout(timer);
      clearInterval(interval);
    };
  }, []);

  if (loading && !analytics) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '300px', color: '#a1a1aa', gap: '12px' }}>
        <Activity className="animate-spin" size={24} color="#3b82f6" />
        <span>Loading API Protection statistics & inventory...</span>
      </div>
    );
  }

  // Define grade colors
  const getGradeStyle = (grade) => {
    switch (grade) {
      case 'A': return { color: '#10b981', backgroundColor: 'rgba(16, 185, 129, 0.1)' };
      case 'B': return { color: '#3b82f6', backgroundColor: 'rgba(59, 130, 246, 0.1)' };
      case 'C': return { color: '#fbbf24', backgroundColor: 'rgba(251, 191, 36, 0.1)' };
      case 'D': return { color: '#f97316', backgroundColor: 'rgba(249, 115, 22, 0.1)' };
      default: return { color: '#ef4444', backgroundColor: 'rgba(239, 68, 68, 0.1)' };
    }
  };

  const getMethodStyle = (method) => {
    switch (method) {
      case 'GET': return { color: '#10b981', fontWeight: 'bold' };
      case 'POST': return { color: '#3b82f6', fontWeight: 'bold' };
      case 'PUT': return { color: '#fbbf24', fontWeight: 'bold' };
      case 'DELETE': return { color: '#ef4444', fontWeight: 'bold' };
      default: return { color: '#a1a1aa', fontWeight: 'bold' };
    }
  };

  const trafficData = analytics ? [
    { name: 'Normal', value: analytics.traffic_bands.normal, color: '#10b981' },
    { name: 'Suspicious', value: analytics.traffic_bands.suspicious, color: '#fbbf24' },
    { name: 'Malicious', value: analytics.traffic_bands.malicious, color: '#ef4444' }
  ] : [];

  return (
    <motion.div
      className="api-protection-container animate-fade-in"
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
      style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}
    >
      {/* Analytics Cards Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '16px' }}>
        <div className="glass-panel" style={{ padding: '20px', display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div style={{ padding: '12px', borderRadius: '12px', backgroundColor: 'rgba(59, 130, 246, 0.1)', color: '#3b82f6' }}>
            <Globe size={24} />
          </div>
          <div>
            <div style={{ fontSize: '13px', color: '#a1a1aa' }}>Total Discovered Endpoints</div>
            <div style={{ fontSize: '24px', fontWeight: 700, color: '#f4f4f5' }}>{analytics?.total_endpoints_count || 0}</div>
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '20px', display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div style={{ padding: '12px', borderRadius: '12px', backgroundColor: 'rgba(16, 185, 129, 0.1)', color: '#10b981' }}>
            <Clock size={24} />
          </div>
          <div>
            <div style={{ fontSize: '13px', color: '#a1a1aa' }}>Avg API Response Time</div>
            <div style={{ fontSize: '24px', fontWeight: 700, color: '#f4f4f5' }}>{analytics?.avg_response_time_ms || 0} ms</div>
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '20px', display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div style={{ padding: '12px', borderRadius: '12px', backgroundColor: 'rgba(239, 68, 68, 0.1)', color: '#ef4444' }}>
            <ShieldCheck size={24} />
          </div>
          <div>
            <div style={{ fontSize: '13px', color: '#a1a1aa' }}>WAF Intercepts (Malicious)</div>
            <div style={{ fontSize: '24px', fontWeight: 700, color: '#f4f4f5' }}>{analytics?.traffic_bands.malicious || 0}</div>
          </div>
        </div>
      </div>

      {/* Charts Section */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: '16px' }}>
        {/* Traffic Bands Chart */}
        <div className="glass-panel chart-card" style={{ gridColumn: 'span 5', padding: '20px' }}>
          <div style={{ fontSize: '16px', fontWeight: 600, color: '#f4f4f5', display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '16px' }}>
            <ShieldCheck size={18} color="#10b981" />
            <span>Traffic Classification Bands</span>
          </div>
          <div style={{ height: '200px', display: 'flex', justifyContent: 'center', alignItems: 'center' }}>
            {trafficData.some(d => d.value > 0) ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={trafficData.filter(d => d.value > 0)}
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={70}
                    paddingAngle={4}
                    dataKey="value"
                  >
                    {trafficData.filter(d => d.value > 0).map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <RechartsTooltip
                    contentStyle={{ backgroundColor: 'rgba(15, 16, 22, 0.95)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '8px' }}
                    itemStyle={{ color: '#fff' }}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ color: '#a1a1aa', fontSize: '13px' }}>No traffic data available</div>
            )}
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-around', marginTop: '16px' }}>
            {trafficData.map(t => (
              <div key={t.name} style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px' }}>
                <div style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: t.color }}></div>
                <span style={{ color: '#a1a1aa' }}>{t.name}:</span>
                <span style={{ color: '#f4f4f5', fontWeight: 600 }}>{t.value}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Top Lists Card */}
        <div className="glass-panel" style={{ gridColumn: 'span 7', padding: '20px', display: 'flex', flexDirection: 'column' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
            <div style={{ fontSize: '16px', fontWeight: 600, color: '#f4f4f5', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <BarChart2 size={18} color="#3b82f6" />
              <span>Endpoint Analytics Overview</span>
            </div>
            <div className="btn-group" style={{ display: 'flex', gap: '8px', padding: '2px', backgroundColor: 'rgba(255,255,255,0.03)', borderRadius: '6px' }}>
              <button
                className={`tab-btn ${topListTab === 'consumed' ? 'active' : ''}`}
                onClick={() => setTopListTab('consumed')}
                style={{
                  border: 'none',
                  padding: '6px 12px',
                  borderRadius: '4px',
                  fontSize: '12px',
                  cursor: 'pointer',
                  backgroundColor: topListTab === 'consumed' ? 'rgba(59, 130, 246, 0.15)' : 'transparent',
                  color: topListTab === 'consumed' ? '#3b82f6' : '#a1a1aa',
                  fontWeight: topListTab === 'consumed' ? 600 : 500
                }}
              >
                Most Consumed
              </button>
              <button
                className={`tab-btn ${topListTab === 'resource' ? 'active' : ''}`}
                onClick={() => setTopListTab('resource')}
                style={{
                  border: 'none',
                  padding: '6px 12px',
                  borderRadius: '4px',
                  fontSize: '12px',
                  cursor: 'pointer',
                  backgroundColor: topListTab === 'resource' ? 'rgba(59, 130, 246, 0.15)' : 'transparent',
                  color: topListTab === 'resource' ? '#3b82f6' : '#a1a1aa',
                  fontWeight: topListTab === 'resource' ? 600 : 500
                }}
              >
                Slowest (Resource-Intensive)
              </button>
            </div>
          </div>

          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '10px', justifyContent: 'center' }}>
            {topListTab === 'consumed' ? (
              analytics?.most_consumed.length > 0 ? (
                analytics.most_consumed.map((ep, idx) => (
                  <div key={idx} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 14px', backgroundColor: 'rgba(255,255,255,0.02)', borderRadius: '6px' }}>
                    <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
                      <span style={getMethodStyle(ep.method)}>{ep.method}</span>
                      <span style={{ color: '#f4f4f5', fontSize: '13px', fontFamily: 'monospace' }}>{ep.uri}</span>
                    </div>
                    <div style={{ display: 'flex', gap: '16px', alignItems: 'center' }}>
                      <span style={{ fontSize: '12px', color: '#a1a1aa' }}>Hits: <strong style={{ color: '#f4f4f5' }}>{ep.hit_count}</strong></span>
                      <span style={{ padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 600, ...getGradeStyle(ep.grade) }}>Grade {ep.grade}</span>
                    </div>
                  </div>
                ))
              ) : (
                <div style={{ color: '#a1a1aa', fontSize: '13px', textAlign: 'center' }}>No endpoints discovered yet</div>
              )
            ) : (
              analytics?.resource_intensive.length > 0 ? (
                analytics.resource_intensive.map((ep, idx) => (
                  <div key={idx} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 14px', backgroundColor: 'rgba(255,255,255,0.02)', borderRadius: '6px' }}>
                    <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
                      <span style={getMethodStyle(ep.method)}>{ep.method}</span>
                      <span style={{ color: '#f4f4f5', fontSize: '13px', fontFamily: 'monospace' }}>{ep.uri}</span>
                    </div>
                    <div style={{ display: 'flex', gap: '16px', alignItems: 'center' }}>
                      <span style={{ fontSize: '12px', color: '#a1a1aa' }}>Latency: <strong style={{ color: '#ef4444' }}>{ep.avg_response_time_ms} ms</strong></span>
                      <span style={{ padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 600, ...getGradeStyle(ep.grade) }}>Grade {ep.grade}</span>
                    </div>
                  </div>
                ))
              ) : (
                <div style={{ color: '#a1a1aa', fontSize: '13px', textAlign: 'center' }}>No resource-intensive endpoints detected</div>
              )
            )}
          </div>
        </div>
      </div>

      {/* Main Inventory Section */}
      <div className="glass-panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div className="btn-group" style={{ display: 'flex', gap: '8px', padding: '2px', backgroundColor: 'rgba(255,255,255,0.03)', borderRadius: '6px' }}>
            <button
              className={`tab-btn ${activeTab === 'inventory' ? 'active' : ''}`}
              onClick={() => setActiveTab('inventory')}
              style={{
                border: 'none',
                padding: '8px 16px',
                borderRadius: '4px',
                fontSize: '13px',
                cursor: 'pointer',
                backgroundColor: activeTab === 'inventory' ? 'rgba(59, 130, 246, 0.15)' : 'transparent',
                color: activeTab === 'inventory' ? '#3b82f6' : '#a1a1aa',
                fontWeight: activeTab === 'inventory' ? 600 : 500
              }}
            >
              API Inventory
            </button>
            <button
              className={`tab-btn ${activeTab === 'recent' ? 'active' : ''}`}
              onClick={() => setActiveTab('recent')}
              style={{
                border: 'none',
                padding: '8px 16px',
                borderRadius: '4px',
                fontSize: '13px',
                cursor: 'pointer',
                backgroundColor: activeTab === 'recent' ? 'rgba(59, 130, 246, 0.15)' : 'transparent',
                color: activeTab === 'recent' ? '#3b82f6' : '#a1a1aa',
                fontWeight: activeTab === 'recent' ? 600 : 500
              }}
            >
              Recently Discovered (Last 48h)
            </button>
          </div>
          <button className="refresh-btn" onClick={fetchData} style={{ padding: '6px 12px', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.08)', backgroundColor: 'transparent', color: '#f4f4f5', cursor: 'pointer', fontSize: '12px' }}>
            Scan Logs Now
          </button>
        </div>

        {/* Table representation */}
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '13px' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.08)', color: '#a1a1aa' }}>
                <th style={{ padding: '12px 8px' }}>Method</th>
                <th style={{ padding: '12px 8px' }}>Endpoint URI</th>
                <th style={{ padding: '12px 8px' }}>Avg Latency</th>
                <th style={{ padding: '12px 8px' }}>Requests</th>
                <th style={{ padding: '12px 8px' }}>Traffic Source</th>
                <th style={{ padding: '12px 8px' }}>TLS</th>
                <th style={{ padding: '12px 8px' }}>Compression</th>
                <th style={{ padding: '12px 8px' }}>Score</th>
                <th style={{ padding: '12px 8px' }}>Grade</th>
              </tr>
            </thead>
            <tbody>
              {(activeTab === 'inventory' ? endpoints : recentlyDiscovered).length > 0 ? (
                (activeTab === 'inventory' ? endpoints : recentlyDiscovered).map((ep, idx) => {
                  // Traffic Source badge styles
                  const trafficSource = ep.traffic_source || 'Unknown';
                  const trafficBadgeStyle = (() => {
                    switch (trafficSource) {
                      case 'External': return { color: '#60a5fa', background: 'rgba(59,130,246,0.12)', border: '1px solid rgba(59,130,246,0.3)' };
                      case 'Internal': return { color: '#34d399', background: 'rgba(16,185,129,0.12)', border: '1px solid rgba(16,185,129,0.3)' };
                      case 'Mixed': return { color: '#fbbf24', background: 'rgba(251,191,36,0.12)', border: '1px solid rgba(251,191,36,0.3)' };
                      default: return { color: '#71717a', background: 'rgba(113,113,122,0.12)', border: '1px solid rgba(113,113,122,0.3)' };
                    }
                  })();
                  const trafficIcon = { External: '🌐', Internal: '🏠', Mixed: '🔀', Unknown: '❓' }[trafficSource] || '❓';

                  return (
                    <tr key={idx} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)', color: '#e4e4e7' }}>
                      <td style={{ padding: '12px 8px', ...getMethodStyle(ep.method) }}>{ep.method}</td>
                      <td style={{ padding: '12px 8px', fontFamily: 'monospace' }}>{ep.uri}</td>
                      <td style={{ padding: '12px 8px' }}>{ep.avg_response_time_ms} ms</td>
                      <td style={{ padding: '12px 8px' }}>{ep.hit_count}</td>
                      <td style={{ padding: '12px 8px' }}>
                        <span style={{
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '4px',
                          padding: '3px 10px',
                          borderRadius: '6px',
                          fontSize: '11px',
                          fontWeight: 600,
                          ...trafficBadgeStyle,
                        }}>
                          {trafficIcon} {trafficSource}
                        </span>
                      </td>
                      <td style={{ padding: '12px 8px', color: ep.has_https ? '#10b981' : '#ef4444' }}>
                        {ep.has_https ? 'HTTPS' : 'HTTP'}
                      </td>
                      <td style={{ padding: '12px 8px', color: ep.content_encoding && ep.content_encoding !== 'none' ? '#10b981' : '#a1a1aa' }}>
                        {ep.content_encoding || 'none'}
                      </td>
                      <td style={{ padding: '12px 8px', fontWeight: 600 }}>{ep.score} / 100</td>
                      <td style={{ padding: '12px 8px' }}>
                        <span style={{ padding: '3px 10px', borderRadius: '6px', fontSize: '11px', fontWeight: 700, ...getGradeStyle(ep.grade) }}>
                          {ep.grade}
                        </span>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan="9" style={{ padding: '32px 8px', textAlign: 'center', color: '#a1a1aa' }}>
                    No discovered endpoints listed.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

      </div>
    </motion.div>
  );
}

