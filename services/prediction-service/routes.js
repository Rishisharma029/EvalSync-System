const express = require('express');

const router = express.Router();

function checkAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  return res.status(401).json({ error: 'Authentication required' });
}

// 1. Fetch AI load and capacity forecasts
router.get('/forecast', checkAuth, (req, res) => {
  const tomorrow = new Date();
  tomorrow.setDate(tomorrow.getDate() + 1);

  return res.status(200).json({
    timestamp: tomorrow.toISOString(),
    expectedSubmissions: 45000 + Math.floor(Math.random() * 5000),
    peakTrafficRps: 45 + Math.floor(Math.random() * 10),
    recommendedWorkers: 16,
    storageUsageGbForecast: 142.6,
    bandwidthForecastMbps: 250,
    confidenceIndex: 94.5
  });
});

module.exports = router;
