const Alert = require('../models/Alert');
const Incident = require('../models/Incident');

/**
 * GET /api/dashboard/summary
 * Returns the DashboardSummary shape used by the frontend.
 */
exports.getDashboardSummary = async (req, res, next) => {
  try {
    const [totalOpen, critical, incidentCount, falsePositiveReview] = await Promise.all([
      Alert.countDocuments({ status: 'open' }),
      Alert.countDocuments({ severity: 'critical' }),
      Incident.countDocuments(),
      Alert.countDocuments({ status: 'false-positive' }),
    ]);

    res.json({ totalOpen, critical, incidentCount, falsePositiveReview });
  } catch (err) {
    next(err);
  }
};

/**
 * GET /api/dashboard/system-status
 * Returns system health indicators (demo data).
 */
exports.getSystemStatus = async (_req, res) => {
  res.json([
    { id: 'siem', name: 'SIEM ingestion', detail: 'QRadar · healthy · 12s lag', health: 'healthy' },
    { id: 'edr', name: 'Endpoint detection', detail: 'All agents reporting', health: 'healthy' },
    {
      id: 'network',
      name: 'Network sensors',
      detail: 'Segment 4 degraded · 1 sensor offline',
      health: 'degraded',
    },
    {
      id: 'threatintel',
      name: 'Threat intel feed',
      detail: 'Last update 3 min ago',
      health: 'healthy',
    },
    {
      id: 'correlation',
      name: 'Correlation engine',
      detail: 'Jobs running normally',
      health: 'operational',
    },
  ]);
};
