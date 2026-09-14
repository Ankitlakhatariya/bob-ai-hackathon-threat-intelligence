const Alert = require('../models/Alert');

/**
 * GET /api/alerts
 * Query params: severity, status, source (all optional filters)
 */
exports.getAlerts = async (req, res, next) => {
  try {
    const filter = {};
    if (req.query.severity) filter.severity = req.query.severity;
    if (req.query.status) filter.status = req.query.status;
    if (req.query.source) filter.source = req.query.source;

    const alerts = await Alert.find(filter).sort({ timestamp: -1 });
    res.json(alerts);
  } catch (err) {
    next(err);
  }
};

/**
 * GET /api/alerts/:id
 */
exports.getAlertById = async (req, res, next) => {
  try {
    const alert = await Alert.findOne({ alertId: req.params.id });
    if (!alert) {
      return res.status(404).json({
        error: { code: 'NOT_FOUND', message: `Alert ${req.params.id} not found` },
      });
    }
    res.json(alert);
  } catch (err) {
    next(err);
  }
};

/**
 * POST /api/alerts
 */
exports.createAlert = async (req, res, next) => {
  try {
    const alert = await Alert.create({ ...req.body, alertId: req.body.id || req.body.alertId });
    res.status(201).json(alert);
  } catch (err) {
    next(err);
  }
};

/**
 * PATCH /api/alerts/:id
 * Partial update (e.g. change status).
 */
exports.updateAlert = async (req, res, next) => {
  try {
    const alert = await Alert.findOneAndUpdate(
      { alertId: req.params.id },
      req.body,
      { new: true, runValidators: true }
    );
    if (!alert) {
      return res.status(404).json({
        error: { code: 'NOT_FOUND', message: `Alert ${req.params.id} not found` },
      });
    }
    res.json(alert);
  } catch (err) {
    next(err);
  }
};

/**
 * DELETE /api/alerts/:id
 */
exports.deleteAlert = async (req, res, next) => {
  try {
    const alert = await Alert.findOneAndDelete({ alertId: req.params.id });
    if (!alert) {
      return res.status(404).json({
        error: { code: 'NOT_FOUND', message: `Alert ${req.params.id} not found` },
      });
    }
    res.json({ message: `Alert ${req.params.id} deleted` });
  } catch (err) {
    next(err);
  }
};

/**
 * GET /api/alerts/trend?range=24h|7d|30d
 * Returns pre-computed trend data. In a real system this would aggregate from
 * the database; here we return the same demo data the frontend used to mock.
 */
exports.getAlertTrend = async (req, res, next) => {
  try {
    const range = req.query.range || '24h';
    const trendData = {
      '24h': [
        { label: '00:00', alerts: 42, incidents: 3 },
        { label: '04:00', alerts: 28, incidents: 2 },
        { label: '08:00', alerts: 61, incidents: 5 },
        { label: '12:00', alerts: 74, incidents: 6 },
        { label: '16:00', alerts: 67, incidents: 5 },
        { label: '20:00', alerts: 83, incidents: 7 },
      ],
      '7d': [
        { label: 'Mon', alerts: 612, incidents: 34 },
        { label: 'Tue', alerts: 540, incidents: 29 },
        { label: 'Wed', alerts: 683, incidents: 41 },
        { label: 'Thu', alerts: 498, incidents: 26 },
        { label: 'Fri', alerts: 746, incidents: 44 },
        { label: 'Sat', alerts: 422, incidents: 23 },
        { label: 'Sun', alerts: 388, incidents: 21 },
      ],
      '30d': [
        { label: 'W1', alerts: 3900, incidents: 168 },
        { label: 'W2', alerts: 4210, incidents: 185 },
        { label: 'W3', alerts: 3540, incidents: 152 },
        { label: 'W4', alerts: 4480, incidents: 201 },
      ],
    };

    const data = trendData[range];
    if (!data) {
      return res.status(400).json({
        error: { code: 'INVALID_RANGE', message: `Range must be one of: 24h, 7d, 30d` },
      });
    }
    res.json(data);
  } catch (err) {
    next(err);
  }
};
