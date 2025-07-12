"use client";
import { useEffect, useState, useMemo } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { 
  Box, Paper, Typography, Card, CardContent, Alert, CircularProgress,
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
  Chip, IconButton, Tooltip, Collapse
} from "@mui/material";
import Grid from '@mui/material/Grid';
import { 
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, 
  ResponsiveContainer, PieChart, Pie, Cell, LineChart, Line, Brush
} from "recharts";
import {
  Security as SecurityIcon,
  Warning as WarningIcon,
  TrendingUp as TrendingUpIcon,
  Computer as ComputerIcon,
  ExpandMore as ExpandMoreIcon,
  ExpandLess as ExpandLessIcon
} from "@mui/icons-material";
import React from 'react';
import api from "../../lib/api";

interface DashboardMetrics {
  total_logs: number;
  total_anomalies: number;
  anomalies_by_type: Record<string, number>;
  anomalies_by_severity: Record<string, number>;
  top_source_ips: Array<{ip: string; count: number}>;
  top_domains: Array<{domain: string; count: number}>;
  anomalies_over_time: Array<{date: string; count: number}>;
  timeline_data: Array<{
    id: string; // Added id for mapping
    timestamp: string;
    time: string; // Added time property for chart display
    bytes_sent: number;
    src_ip: string;
    domain: string;
    status_code: string;
    is_anomaly: boolean;
    anomaly_type?: string; // Added anomaly_type
    threat_category?: string; // Added threat_category
  }>;
  recent_anomalies: Array<{
    timestamp: string;
    type: string;
    severity: string | null;
    src_ip: string;
    domain: string;
    explanation: string;
  }>;
  blocked_vs_allowed: Record<string, number>;
  top_methods_in_anomalies: Record<string, number>;
  top_status_codes_in_anomalies: Record<string, number>;
  summary_report: {
    summary: string;
    mitigations: Array<{
      title: string;
      summary: string;
      actions: string[];
      examples: string[];
    }>;
  };
}

const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#8884D8'];

// Helper functions removed as they are not used

export default function DashboardPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const fileId = searchParams.get("file_id");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);
  const [hoveredDot, setHoveredDot] = useState<DashboardMetrics['timeline_data'][0] | null>(null);
  const [anomalyPage, setAnomalyPage] = useState(1);
  const [summaryExpanded, setSummaryExpanded] = useState(false);
  const anomaliesPerPage = 10;

  // Memoize timelineChartData at the very top to avoid hook order issues
  const timelineChartData = useMemo(() => {
    if (!metrics || !metrics.timeline_data) return [];
    return metrics.timeline_data.map((entry) => ({
      id: entry.id,
      name: (() => {
        try {
          const date = new Date(entry.timestamp);
          if (!isNaN(date.getTime())) {
            return date.toLocaleTimeString('en-US', {
              hour12: false,
              hour: '2-digit',
              minute: '2-digit',
              second: '2-digit',
            });
          }
        } catch {}
        return entry.timestamp;
      })(),
      time: entry.timestamp,
      bytes_sent: entry.bytes_sent,
      is_anomaly: entry.is_anomaly,
      src_ip: entry.src_ip,
      domain: entry.domain,
      status_code: entry.status_code,
      anomaly_type: entry.anomaly_type,
      threat_category: entry.threat_category
    }));
  }, [metrics]);

  // Dynamic chart settings for large datasets
  const logCount = timelineChartData.length;
  const xAxisInterval = logCount > 200 ? Math.ceil(logCount / 20) : logCount > 100 ? Math.ceil(logCount / 10) : logCount > 40 ? 5 : 0;
  const chartHeight = logCount > 200 ? 600 : logCount > 100 ? 500 : 450;

  useEffect(() => {
    const token = window.localStorage.getItem("token");
    if (!token) {
      router.replace("/login");
      return;
    }
    if (!fileId) {
      setError("No file selected. Please upload a log file first.");
      setLoading(false);
      return;
    }
    const fetchDashboard = async () => {
      try {
        const res = await api.get(
          `/api/analysis/dashboard/${fileId}`,
          {
            headers: { Authorization: `Bearer ${token}` },
          }
        );
        setMetrics(res.data);
      } catch (err: any) { // eslint-disable-line @typescript-eslint/no-explicit-any
        setError(err?.response?.data?.msg || "Failed to fetch dashboard metrics");
      } finally {
        setLoading(false);
      }
    };
    fetchDashboard();
  }, [router, fileId]);

  useEffect(() => {
    setAnomalyPage(1);
  }, [metrics]);

  const getSeverityColor = (severity: string | null) => {
    switch (severity?.toLowerCase()) {
      case 'high': return 'error';
      case 'medium': return 'warning';
      case 'low': return 'info';
      default: return 'default';
    }
  };

  // Helper functions removed as they are not used

  // Add this color map near the top of the file
  const categoryColorMap: Record<string, string> = {
    'Brute Force': '#f44336',         // red
    'Automation/Bot': '#ff9800',      // orange
    'Malware/Phishing': '#9c27b0',    // purple
    'Unusual Activity': '#2196f3',    // blue
    'Data Exfiltration': '#e91e63',   // pink
    'Anomalous Behavior': '#607d8b',  // blue-grey
    'Unusual Data Volume': '#e91e63', // pink (same as Data Exfiltration)
    'Unusual Status Code': '#3f51b5', // indigo
    'Rare User Agent': '#009688',     // teal
    'Blocked Request': '#795548',     // brown
    'Unusual Pattern': '#607d8b',     // blue-grey
    'Other': '#bdbdbd'                // grey
  };

  // Helper function to extract explanation from anomaly object
  const getAnomalyExplanation = (anomaly: any): string => { // eslint-disable-line @typescript-eslint/no-explicit-any
    // First, try to get explanation from top level
    let explanation = anomaly.explanation || '';
    
    // If not found, try to get from security anomalies
    if (!explanation && anomaly.security_anomalies && anomaly.security_anomalies.length > 0) {
      explanation = anomaly.security_anomalies[0].explanation || '';
    }
    
    // If still not found, try to get from ML reasoning
    if (!explanation && anomaly.reasoning) {
      const isoReasons = anomaly.reasoning.isolation_forest?.reasons || [];
      const lofReasons = anomaly.reasoning.lof?.reasons || [];
      if (isoReasons.length > 0) {
        explanation = isoReasons[0];
      } else if (lofReasons.length > 0) {
        explanation = lofReasons[0];
      }
    }
    
    // Final fallback
    return explanation || "No explanation available";
  };

  // Use all anomalies for pagination (if not present, fallback to recent_anomalies)
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const allAnomalies = Array.isArray((metrics as any)?.anomalies) ? (metrics as any).anomalies : (metrics?.recent_anomalies || []);
  const totalAnomalyPages = Math.ceil(allAnomalies.length / anomaliesPerPage);
  const paginatedAnomalies = allAnomalies.slice((anomalyPage - 1) * anomaliesPerPage, anomalyPage * anomaliesPerPage);

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="100vh">
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="100vh">
        <Alert severity="error">{error}</Alert>
      </Box>
    );
  }

  if (!metrics) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="100vh">
        <Alert severity="info">No dashboard data available.</Alert>
      </Box>
    );
  }

  // Prepare chart data - removed unused typeChartData

  const severityChartData = Object.entries(metrics.anomalies_by_severity).map(([severity, count]) => ({
    name: severity.toUpperCase(),
    value: count
  }));

  // Prepare threat category chart data
  const threatCategoryCounts: Record<string, number> = {};
  metrics.recent_anomalies.forEach(a => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const cat = (a as any).threat_category || 'Other';
    threatCategoryCounts[cat] = (threatCategoryCounts[cat] || 0) + 1;
  });
  const threatCategoryChartData = Object.entries(threatCategoryCounts).map(([cat, count]) => ({
    name: cat,
    value: count
  }));

  // Prepare blocked vs allowed actions chart data
  const blockedVsAllowedData = Object.entries(metrics.blocked_vs_allowed || {})
    .filter(([, count]) => count > 0) // Filter out zero values
    .map(([action, count]) => ({
      name: action,
      value: count
    }));

  // Prepare top methods in anomalies chart data
  const topMethodsData = Object.entries(metrics.top_methods_in_anomalies || {}).map(([method, count]) => ({
    name: method,
    value: count
  }));

  // Prepare top status codes in anomalies chart data
  const topStatusCodesData = Object.entries(metrics.top_status_codes_in_anomalies || {}).map(([status, count]) => ({
    name: status,
    value: count
  }));

  return (
    <Box sx={{ p: 4, bgcolor: '#f7f8fa', minHeight: '100vh', display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
      <Box sx={{ width: '100%', maxWidth: 1200, mx: 'auto' }}>
        <Typography variant="h4" fontWeight={700} gutterBottom sx={{ mb: 3 }}>
          Security Operations Center Dashboard
        </Typography>

        {/* Key Metrics Cards */}
        <Grid container spacing={3} sx={{ mb: 3 }}>
          <Grid sx={{ flex: 1, minWidth: 0, maxWidth: '25%' }}>
            <Card sx={{ bgcolor: 'primary.light', borderRadius: 2 }}>
              <CardContent>
                <Box display="flex" alignItems="center">
                  <ComputerIcon sx={{ fontSize: 40, color: 'primary.main', mr: 2 }} />
                  <Box>
                    <Typography variant="h4" fontWeight={700}>
                      {metrics.total_logs}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Total Log Entries
                    </Typography>
                  </Box>
                </Box>
              </CardContent>
            </Card>
          </Grid>

          <Grid sx={{ flex: 1, minWidth: 0, maxWidth: '25%' }}>
            <Card sx={{ bgcolor: 'error.light', borderRadius: 2 }}>
              <CardContent>
                <Box display="flex" alignItems="center">
                  <WarningIcon sx={{ fontSize: 40, color: 'error.main', mr: 2 }} />
                  <Box>
                    <Typography variant="h4" fontWeight={700}>
                      {metrics.total_anomalies}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Anomalies Detected
                    </Typography>
                  </Box>
                </Box>
              </CardContent>
            </Card>
          </Grid>

          <Grid sx={{ flex: 1, minWidth: 0, maxWidth: '25%' }}>
            <Card sx={{ bgcolor: 'warning.light', borderRadius: 2 }}>
              <CardContent>
                <Box display="flex" alignItems="center">
                  <SecurityIcon sx={{ fontSize: 40, color: 'warning.main', mr: 2 }} />
                  <Box>
                    <Typography variant="h4" fontWeight={700}>
                      {Object.keys(metrics.anomalies_by_type).length}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Threat Types
                    </Typography>
                  </Box>
                </Box>
              </CardContent>
            </Card>
          </Grid>

          <Grid sx={{ flex: 1, minWidth: 0, maxWidth: '25%' }}>
            <Card sx={{ bgcolor: 'info.light', borderRadius: 2 }}>
              <CardContent>
                <Box display="flex" alignItems="center">
                  <TrendingUpIcon sx={{ fontSize: 40, color: 'info.main', mr: 2 }} />
                  <Box>
                    <Typography variant="h4" fontWeight={700}>
                      {metrics.top_source_ips.length}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Suspicious IPs
                    </Typography>
                  </Box>
                </Box>
              </CardContent>
            </Card>
          </Grid>
        </Grid>

        {/* Summary Report Section */}
        {metrics.summary_report && metrics.summary_report.summary && (
          <Paper sx={{ 
            p: summaryExpanded ? 4 : 2, 
            mb: 3, 
            borderRadius: 2, 
            boxShadow: '0 4px 16px rgba(0,0,0,0.08), 0 0 0 1px rgba(76, 175, 80, 0.2), 0 2px 8px rgba(76, 175, 80, 0.1)',
            background: '#e0e3e8',
            color: '#232526',
            border: '2px solid rgba(76, 175, 80, 0.4)',
            position: 'relative',
            transition: 'padding 0.3s ease',
            '&::before': {
              content: '""',
              position: 'absolute',
              top: 0,
              left: 0,
              right: 0,
              bottom: 0,
              borderRadius: 2,
              background: 'linear-gradient(135deg, rgba(76, 175, 80, 0.1) 0%, rgba(76, 175, 80, 0.05) 100%)',
              pointerEvents: 'none',
              zIndex: 0
            }
          }}>
            <Box sx={{ 
              display: 'flex', 
              alignItems: 'center', 
              justifyContent: 'space-between',
              cursor: 'pointer'
            }} onClick={() => setSummaryExpanded(!summaryExpanded)}>
              <Box sx={{ flex: 1, display: 'flex', justifyContent: 'center', alignItems: 'center' }}>
                <Box sx={{ textAlign: 'center' }}>
                  <Typography variant="h6" fontWeight={700} sx={{ color: '#232526', mb: summaryExpanded ? 0.5 : 0 }}>
                    AI Security Analysis
                  </Typography>
                  <Typography variant="body2" sx={{ color: '#232526', mb: summaryExpanded ? 2 : 0 }}>
                    View AI-powered threat assessment and recommendations
                  </Typography>
                </Box>
              </Box>
              <IconButton 
                sx={{ 
                  color: '#232526',
                  transition: 'all 0.3s ease',
                  transform: summaryExpanded ? 'rotate(180deg)' : 'rotate(0deg)',
                  position: 'absolute',
                  right: 16,
                  bgcolor: 'rgba(76, 175, 80, 0.1)',
                  border: '2px solid rgba(76, 175, 80, 0.3)',
                  borderRadius: '50%',
                  width: 48,
                  height: 48,
                  '&:hover': {
                    bgcolor: 'rgba(76, 175, 80, 0.2)',
                    border: '2px solid rgba(76, 175, 80, 0.5)',
                    transform: summaryExpanded ? 'rotate(180deg) scale(1.1)' : 'rotate(0deg) scale(1.1)',
                  }
                }}
              >
                {summaryExpanded ? <ExpandLessIcon sx={{ fontSize: 28 }} /> : <ExpandMoreIcon sx={{ fontSize: 28 }} />}
              </IconButton>
            </Box>
            <Collapse in={summaryExpanded} timeout={300}>
              <Box sx={{ 
                p: 3, 
                background: '#f5f6fa',
                borderRadius: 2, 
                backdropFilter: 'blur(10px)',
                border: '1px solid rgba(255,255,255,0.2)',
                maxHeight: 400,
                overflow: 'auto',
                '&::-webkit-scrollbar': {
                  width: '8px',
                },
                '&::-webkit-scrollbar-track': {
                  background: 'rgba(255,255,255,0.1)',
                  borderRadius: '4px',
                },
                '&::-webkit-scrollbar-thumb': {
                  background: 'rgba(255,255,255,0.3)',
                  borderRadius: '4px',
                  '&:hover': {
                    background: 'rgba(255,255,255,0.5)',
                  },
                },
              }}>
                {/* Render summary string */}
                <Typography variant="body1" sx={{ color: '#232526', mb: 2, fontSize: '1rem', textShadow: '0 2px 8px rgba(30,40,80,0.08), 0 1px 1px rgba(0,0,0,0.06)', fontWeight: 400 }}>
                  {metrics.summary_report.summary}
                </Typography>
                {/* Render mitigations array */}
                {Array.isArray(metrics.summary_report.mitigations) && metrics.summary_report.mitigations.length > 0 ? (
                  <Box>
                    {metrics.summary_report.mitigations.map((mit, idx) => (
                      <Paper key={idx} sx={{
                        p: 3,
                        mb: 3,
                        borderRadius: 3,
                        background: 'rgba(255,255,255,0.10)',
                        color: '#333',
                        boxShadow: '0 8px 32px 0 rgba(30,40,80,0.08)',
                        borderLeft: '6px solid #4CAF50', // Always green
                        position: 'relative',
                        overflow: 'visible',
                        backdropFilter: 'blur(12px)',
                      }}>
                        <Typography variant="subtitle1" sx={{ fontWeight: 700, fontSize: '1.15rem', mb: 1, display: 'flex', alignItems: 'center', color: '#232526', textShadow: '0 2px 8px rgba(30,40,80,0.08)' }}>
                          {mit.title}
                        </Typography>
                        <Typography variant="body1" sx={{ mb: 1.5, color: '#333', fontWeight: 500, textShadow: '0 2px 8px rgba(30,40,80,0.08)' }}>
                          {mit.summary}
                        </Typography>
                        {Array.isArray(mit.actions) && mit.actions.length > 0 && (
                          <Box sx={{ mb: 1.5 }}>
                            <Typography variant="body2" sx={{ fontWeight: 700, color: '#232526', mb: 0.5, letterSpacing: 0.5 }}>Actions:</Typography>
                            <ul style={{ margin: 0, paddingLeft: 22 }}>
                              {mit.actions.map((action, i) => (
                                <li key={i} style={{ marginBottom: 2, color: '#333', fontWeight: 500, fontSize: '1.01rem', textShadow: '0 2px 8px rgba(30,40,80,0.08)' }}>{action}</li>
                              ))}
                            </ul>
                          </Box>
                        )}
                        {Array.isArray(mit.examples) && mit.examples.length > 0 && (
                          <Box>
                            <Typography variant="body2" sx={{ fontWeight: 700, color: '#232526', mb: 0.5, letterSpacing: 0.5 }}>Examples:</Typography>
                            <ul style={{ margin: 0, paddingLeft: 22 }}>
                              {mit.examples.map((ex, i) => (
                                <li key={i} style={{ marginBottom: 2 }}>
                                  <code style={{ background: 'rgba(30,40,80,0.08)', color: '#232526', borderRadius: 4, padding: '2px 8px', fontSize: '0.92em', fontFamily: 'monospace', boxShadow: '0 1px 4px 0 rgba(30,40,80,0.06)' }}>{ex}</code>
                                </li>
                              ))}
                            </ul>
                          </Box>
                        )}
                      </Paper>
                    ))}
                  </Box>
                ) : (
                  <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.8)' }}>
                    No mitigations found.
                  </Typography>
                )}
              </Box>
            </Collapse>
          </Paper>
        )}

        {/* Charts Row */}
        <Grid container spacing={3} sx={{ mb: 3, flexWrap: 'nowrap' }}>
          <Grid sx={{ flex: 2, minWidth: 0 }}>
            <Paper sx={{ p: 3, borderRadius: 1, boxShadow: 2 }}>
              <Typography variant="h6" fontWeight={600} gutterBottom>
                Threat Category Breakdown
              </Typography>
              <ResponsiveContainer width="100%" height={350}>
                <PieChart>
                  <Pie
                    data={threatCategoryChartData}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={({ name, percent }) => `${name} ${percent !== undefined ? (percent * 100).toFixed(0) : 0}%`}
                    outerRadius={100}
                    fill="#8884d8"
                    dataKey="value"
                  >
                    {threatCategoryChartData.map((entry, index) => (
                      <Cell key={`cat-cell-${index}`} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Pie>
                  <RechartsTooltip />
                </PieChart>
              </ResponsiveContainer>
            </Paper>
          </Grid>
          <Grid sx={{ flex: 1, minWidth: 0 }}>
            <Paper sx={{ p: 3, borderRadius: 1, boxShadow: 2 }}>
              <Typography variant="h6" fontWeight={600} gutterBottom>
                Anomalies by Severity
              </Typography>
              <ResponsiveContainer width="100%" height={350}>
                <BarChart data={severityChartData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="name" />
                  <YAxis />
                  <RechartsTooltip />
                  <Bar dataKey="value" fill="#8884d8" />
                </BarChart>
              </ResponsiveContainer>
            </Paper>
          </Grid>
        </Grid>

        {/* New Security Analytics Charts */}
        <Grid container spacing={3} sx={{ mb: 3 }}>
          <Grid sx={{ flex: 1, minWidth: 0 }}>
            <Paper sx={{ p: 3, borderRadius: 1, boxShadow: 2, height: 400 }}>
              <Typography variant="h6" fontWeight={600} gutterBottom>
                Blocked vs Allowed Actions
              </Typography>
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={blockedVsAllowedData}
                    cx="50%"
                    cy="35%"
                    labelLine={false}
                    label={false}
                    outerRadius={80}
                    fill="#8884d8"
                    dataKey="value"
                  >
                    {blockedVsAllowedData.map((entry, index) => (
                      <Cell 
                        key={`blocked-cell-${index}`} 
                        fill={entry.name === 'Blocked' ? '#f44336' : entry.name === 'Allowed' ? '#4caf50' : '#ff9800'} 
                      />
                    ))}
                  </Pie>
                  <RechartsTooltip />
                </PieChart>
              </ResponsiveContainer>
              {/* Custom legend at bottom */}
              <Box sx={{ mt: 0, mb: 0, display: 'flex', justifyContent: 'center', flexWrap: 'wrap', gap: 2 }}>
                {blockedVsAllowedData.map((entry, index) => {
                  const total = blockedVsAllowedData.reduce((sum, item) => sum + item.value, 0);
                  const percentage = total > 0 ? ((entry.value / total) * 100).toFixed(1) : 0;
                  return (
                    <Box key={`legend-${index}`} sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <Box 
                        sx={{ 
                          width: 12, 
                          height: 12, 
                          borderRadius: '50%',
                          bgcolor: entry.name === 'Blocked' ? '#f44336' : entry.name === 'Allowed' ? '#4caf50' : '#ff9800'
                        }} 
                      />
                      <Typography variant="body2">
                        {entry.name} ({percentage}%)
                      </Typography>
                    </Box>
                  );
                })}
              </Box>
            </Paper>
          </Grid>

          <Grid sx={{ flex: 1, minWidth: 0 }}>
            <Paper sx={{ p: 3, borderRadius: 1, boxShadow: 2, height: 400 }}>
              <Typography variant="h6" fontWeight={600} gutterBottom>
                Top HTTP Methods in Anomalies
              </Typography>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={topMethodsData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="name" />
                  <YAxis />
                  <RechartsTooltip />
                  <Bar dataKey="value" fill="#2196f3" />
                </BarChart>
              </ResponsiveContainer>
            </Paper>
          </Grid>

          <Grid sx={{ flex: 1, minWidth: 0 }}>
            <Paper sx={{ p: 3, borderRadius: 1, boxShadow: 2, height: 400 }}>
              <Typography variant="h6" fontWeight={600} gutterBottom>
                Top Status Codes in Anomalies
              </Typography>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={topStatusCodesData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="name" />
                  <YAxis />
                  <RechartsTooltip />
                  <Bar dataKey="value" fill="#ff9800" />
                </BarChart>
              </ResponsiveContainer>
            </Paper>
          </Grid>
        </Grid>

        {/* Timeline Chart */}
        <Paper sx={{ p: 3, mb: 3, borderRadius: 1, boxShadow: 2 }}>
          <Typography variant="h6" fontWeight={600} gutterBottom>
            Timeline - Bytes Sent Over Time
          </Typography>
          <ResponsiveContainer width="100%" height={chartHeight}>
            <LineChart data={timelineChartData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis 
                dataKey="name" 
                angle={-45}
                textAnchor="end"
                height={80}
                interval={xAxisInterval}
              />
              <YAxis />
              <RechartsTooltip 
                content={() => {
                  if (!hoveredDot) return null;
                  const data = hoveredDot;
                  return (
                    <Box sx={{ bgcolor: 'white', p: 2, border: 1, borderColor: 'grey.300' }}>
                      <Typography variant="body2"><strong>Time:</strong> {data.time}</Typography>
                      <Typography variant="body2"><strong>Bytes Sent:</strong> {data.bytes_sent}</Typography>
                      <Typography variant="body2"><strong>Source IP:</strong> {data.src_ip}</Typography>
                      <Typography variant="body2"><strong>Domain:</strong> {data.domain}</Typography>
                      <Typography variant="body2"><strong>Status:</strong> {data.status_code}</Typography>
                      <Typography variant="body2" color={data.is_anomaly ? 'error.main' : 'success.main'}>
                        <strong>Anomaly:</strong> {data.is_anomaly ? 'Yes' : 'No'}
                      </Typography>
                      {data.is_anomaly && data.anomaly_type && (
                        <Typography variant="body2" color="error.main">
                          <strong>Category:</strong> {data.threat_category}
                        </Typography>
                      )}
                    </Box>
                  );
                }}
              />
              <Line 
                type="monotone" 
                dataKey="bytes_sent" 
                stroke="#8884d8" 
                strokeWidth={2}
                dot={(props) => {
                  const { cx, cy, payload, index } = props;
                  const isAnomalyBoolean = payload.is_anomaly === true;
                  const isHovered = hoveredDot && hoveredDot.id === payload.id;
                  const color = isAnomalyBoolean ? '#f44336' : '#8884d8';

                  if (isAnomalyBoolean && isHovered) {
                    // Draw a red circle with a white ring and a blue center on hover
                    return (
                      <g key={`dot-group-${payload.id || index}`}>
                        {/* Red outer ring */}
                        <circle
                          key={`dot-outer-${payload.id || index}`}
                          cx={cx}
                          cy={cy}
                          r={8}
                          fill="#f44336"
                          stroke="#f44336"
                          strokeWidth={2}
                        />
                        {/* White middle ring */}
                        <circle
                          key={`dot-middle-${payload.id || index}`}
                          cx={cx}
                          cy={cy}
                          r={5.5}
                          fill="#fff"
                          stroke="#fff"
                          strokeWidth={1}
                        />
                        {/* Blue center */}
                        <circle
                          key={`dot-inner-${payload.id || index}`}
                          cx={cx}
                          cy={cy}
                          r={3.5}
                          fill="#8884d8"
                          stroke="#8884d8"
                          strokeWidth={1}
                        />
                      </g>
                    );
                  }

                  // Normal rendering
                  return (
                    <circle
                      key={`dot-${payload.id || index}`}
                      cx={cx}
                      cy={cy}
                      r={isAnomalyBoolean ? 6 : 4}
                      fill={color}
                      stroke={color}
                      strokeWidth={isAnomalyBoolean ? 2 : 1}
                      onMouseEnter={() => setHoveredDot(payload)}
                      onMouseLeave={() => setHoveredDot(null)}
                      style={{ cursor: 'pointer' }}
                    />
                  );
                }}
              />
              <Brush dataKey="name" height={30} stroke="#8884d8" />
            </LineChart>
          </ResponsiveContainer>
        </Paper>
        {/* Tables Row */}
        <Grid container spacing={3} sx={{ mb: 3 }}>
          <Grid sx={{ flex: 1, minWidth: 0, maxWidth: '50%' }}>
            <Paper sx={{ p: 3, borderRadius: 1, boxShadow: 2 }}>
              <Typography variant="h6" fontWeight={600} gutterBottom>
                Top Source IPs
              </Typography>
              <TableContainer>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>IP Address</TableCell>
                      <TableCell align="right">Anomaly Count</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {metrics.top_source_ips.map((row, index) => (
                      <TableRow key={index}>
                        <TableCell>{row.ip}</TableCell>
                        <TableCell align="right">{row.count}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Paper>
          </Grid>

          <Grid sx={{ flex: 1, minWidth: 0, maxWidth: '50%' }}>
            <Paper sx={{ p: 3, borderRadius: 1, boxShadow: 2 }}>
              <Typography variant="h6" fontWeight={600} gutterBottom>
                Top Domains
              </Typography>
              <TableContainer>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Domain</TableCell>
                      <TableCell align="right">Anomaly Count</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {metrics.top_domains.map((row, index) => (
                      <TableRow key={index}>
                        <TableCell>{row.domain}</TableCell>
                        <TableCell align="right">{row.count}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Paper>
          </Grid>
        </Grid>

        {/* Paginated Anomalies Table */}
        <Paper sx={{ p: 3, borderRadius: 1, boxShadow: 2, mt: 3 }}>
          <Typography variant="h6" fontWeight={600} gutterBottom>
            All Anomalies
          </Typography>
          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Timestamp</TableCell>
                  <TableCell>Category</TableCell>
                  <TableCell>Severity</TableCell>
                  <TableCell>Confidence</TableCell>
                  <TableCell>Source IP</TableCell>
                  <TableCell>Domain</TableCell>
                  <TableCell>Explanation</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {paginatedAnomalies.map((row: any, index: number) => ( // eslint-disable-line @typescript-eslint/no-explicit-any
                  <TableRow key={index}>
                    <TableCell>{row.timestamp}</TableCell>
                    <TableCell>
                      <Chip 
                        label={row.threat_category || 'Other'} 
                        size="small"
                        sx={{
                          bgcolor: categoryColorMap[row.threat_category || 'Other'],
                          color: '#fff',
                          fontWeight: 600,
                          fontSize: '0.85rem',
                          letterSpacing: 0.5,
                          borderRadius: 1,
                        }}
                      />
                    </TableCell>
                    <TableCell>
                      {row.severity ? (
                        <Chip 
                          label={row.severity} 
                          color={getSeverityColor(row.severity) as 'error' | 'warning' | 'info' | 'default'}
                          size="small"
                        />
                      ) : (
                        <Chip label="Unknown" color="default" size="small" />
                      )}
                    </TableCell>
                    <TableCell>
                      {row.confidence_score ? (
                        <Chip 
                          label={`${(row.confidence_score * 100).toFixed(1)}%`}
                          size="small"
                          sx={{
                            bgcolor: row.confidence_score >= 0.8 ? '#4caf50' : 
                                     row.confidence_score >= 0.6 ? '#ff9800' : '#f44336',
                            color: '#fff',
                            fontWeight: 600,
                            fontSize: '0.85rem',
                          }}
                        />
                      ) : (
                        <Chip label="N/A" color="default" size="small" />
                      )}
                    </TableCell>
                    <TableCell>{row.src_ip}</TableCell>
                    <TableCell>{row.domain}</TableCell>
                    <TableCell>
                      <Tooltip 
                        title={
                          <Box sx={{ p: 1, maxWidth: 400 }}>
                            <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap', lineHeight: 1.4 }}>
                              {getAnomalyExplanation(row)}
                            </Typography>
                          </Box>
                        }
                        placement="top-start"
                        arrow
                      >
                        <Typography 
                          variant="body2" 
                          sx={{ 
                            maxWidth: 300,
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap',
                            cursor: 'pointer',
                            '&:hover': {
                              textDecoration: 'underline'
                            }
                          }}
                        >
                          {getAnomalyExplanation(row)}
                        </Typography>
                      </Tooltip>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
          {/* Pagination Controls */}
          <Box display="flex" justifyContent="space-between" alignItems="center" mt={2}>
            <Box>
              <Typography variant="body2" color="text.secondary">
                Page {anomalyPage} of {totalAnomalyPages}
              </Typography>
            </Box>
            <Box>
              <Chip
                label={`Total: ${allAnomalies.length}`}
                size="small"
                sx={{ ml: 2, bgcolor: '#eee', color: '#333', fontWeight: 600 }}
              />
              <IconButton
                onClick={() => setAnomalyPage(anomalyPage - 1)}
                disabled={anomalyPage === 1}
                sx={{ ml: 2 }}
              >
                {'<'}
              </IconButton>
              <IconButton
                onClick={() => setAnomalyPage(anomalyPage + 1)}
                disabled={anomalyPage >= totalAnomalyPages}
              >
                {'>'}
              </IconButton>
            </Box>
          </Box>
        </Paper>


      </Box>
    </Box>
  );
} 