const Incident = require('../models/Incident');

/**
 * GET /api/incidents
 * Query params: severity, status (optional filters)
 */
exports.getIncidents = async (req, res, next) => {
  try {
    const filter = {};
    if (req.query.severity) filter.severity = req.query.severity;
    if (req.query.status) filter.status = req.query.status;

    const incidents = await Incident.find(filter).sort({ openedAt: -1 });
    res.json(incidents);
  } catch (err) {
    next(err);
  }
};

/**
 * GET /api/incidents/:id
 */
exports.getIncidentById = async (req, res, next) => {
  try {
    const incident = await Incident.findOne({ incidentId: req.params.id });
    if (!incident) {
      return res.status(404).json({
        error: { code: 'NOT_FOUND', message: `Incident ${req.params.id} not found` },
      });
    }
    res.json(incident);
  } catch (err) {
    next(err);
  }
};

/**
 * POST /api/incidents
 */
exports.createIncident = async (req, res, next) => {
  try {
    const incident = await Incident.create({
      ...req.body,
      incidentId: req.body.id || req.body.incidentId,
    });
    res.status(201).json(incident);
  } catch (err) {
    next(err);
  }
};

/**
 * PATCH /api/incidents/:id
 */
exports.updateIncident = async (req, res, next) => {
  try {
    const incident = await Incident.findOneAndUpdate(
      { incidentId: req.params.id },
      req.body,
      { new: true, runValidators: true }
    );
    if (!incident) {
      return res.status(404).json({
        error: { code: 'NOT_FOUND', message: `Incident ${req.params.id} not found` },
      });
    }
    res.json(incident);
  } catch (err) {
    next(err);
  }
};

/**
 * DELETE /api/incidents/:id
 */
exports.deleteIncident = async (req, res, next) => {
  try {
    const incident = await Incident.findOneAndDelete({ incidentId: req.params.id });
    if (!incident) {
      return res.status(404).json({
        error: { code: 'NOT_FOUND', message: `Incident ${req.params.id} not found` },
      });
    }
    res.json({ message: `Incident ${req.params.id} deleted` });
  } catch (err) {
    next(err);
  }
};
