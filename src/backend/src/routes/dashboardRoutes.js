const express = require('express');
const router = express.Router();
const { getDashboardSummary, getSystemStatus } = require('../controllers/dashboardController');

router.get('/summary', getDashboardSummary);
router.get('/system-status', getSystemStatus);

module.exports = router;
