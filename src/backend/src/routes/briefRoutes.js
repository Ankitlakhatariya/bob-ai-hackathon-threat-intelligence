const express = require('express');
const router = express.Router();
const { getBriefs, getBriefByIncidentId, createBrief } = require('../controllers/briefController');

router.get('/', getBriefs);
router.get('/:incidentId', getBriefByIncidentId);
router.post('/', createBrief);

module.exports = router;
