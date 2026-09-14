const express = require('express');
const router = express.Router();
const {
  getIncidents,
  getIncidentById,
  createIncident,
  updateIncident,
  deleteIncident,
} = require('../controllers/incidentController');

router.get('/', getIncidents);
router.get('/:id', getIncidentById);
router.post('/', createIncident);
router.patch('/:id', updateIncident);
router.delete('/:id', deleteIncident);

module.exports = router;
