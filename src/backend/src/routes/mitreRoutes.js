const express = require('express');
const router = express.Router();
const { getTechniques, getTechniqueById } = require('../controllers/mitreController');

router.get('/', getTechniques);
router.get('/:id', getTechniqueById);

module.exports = router;
