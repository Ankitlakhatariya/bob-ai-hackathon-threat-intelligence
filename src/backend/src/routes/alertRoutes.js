const express = require('express');
const router = express.Router();
const {
  getAlerts,
  getAlertById,
  createAlert,
  updateAlert,
  deleteAlert,
  getAlertTrend,
} = require('../controllers/alertController');

// Trend must be defined before :id so "trend" isn't captured as an id param
router.get('/trend', getAlertTrend);

router.get('/', getAlerts);
router.get('/:id', getAlertById);
router.post('/', createAlert);
router.patch('/:id', updateAlert);
router.delete('/:id', deleteAlert);

module.exports = router;
