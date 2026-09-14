const Brief = require('../models/Brief');

/**
 * GET /api/briefs
 */
exports.getBriefs = async (req, res, next) => {
  try {
    const briefs = await Brief.find().sort({ incidentId: 1 });
    // Return as a map keyed by incidentId to match the frontend's Record<string, MitreBrief>
    const map = {};
    briefs.forEach((b) => {
      const obj = b.toJSON();
      map[obj.incidentId] = {
        bottomLine: obj.bottomLine,
        impact: obj.impact,
        keyEvidence: obj.keyEvidence,
        recommendedFocus: obj.recommendedFocus,
      };
    });
    res.json(map);
  } catch (err) {
    next(err);
  }
};

/**
 * GET /api/briefs/:incidentId
 */
exports.getBriefByIncidentId = async (req, res, next) => {
  try {
    const brief = await Brief.findOne({ incidentId: req.params.incidentId });
    if (!brief) {
      return res.status(404).json({
        error: {
          code: 'NOT_FOUND',
          message: `Brief for incident ${req.params.incidentId} not found`,
        },
      });
    }
    res.json(brief);
  } catch (err) {
    next(err);
  }
};

/**
 * POST /api/briefs
 */
exports.createBrief = async (req, res, next) => {
  try {
    const brief = await Brief.create(req.body);
    res.status(201).json(brief);
  } catch (err) {
    next(err);
  }
};
