const MitreTechnique = require('../models/MitreTechnique');

/**
 * GET /api/mitre
 * Query params: tactic (optional filter)
 */
exports.getTechniques = async (req, res, next) => {
  try {
    const filter = {};
    if (req.query.tactic) filter.tactics = req.query.tactic;

    const techniques = await MitreTechnique.find(filter).sort({ techniqueId: 1 });
    res.json(techniques);
  } catch (err) {
    next(err);
  }
};

/**
 * GET /api/mitre/:id
 */
exports.getTechniqueById = async (req, res, next) => {
  try {
    const technique = await MitreTechnique.findOne({ techniqueId: req.params.id });
    if (!technique) {
      return res.status(404).json({
        error: { code: 'NOT_FOUND', message: `Technique ${req.params.id} not found` },
      });
    }
    res.json(technique);
  } catch (err) {
    next(err);
  }
};
