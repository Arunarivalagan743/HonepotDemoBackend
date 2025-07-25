const express = require('express');
const { auth, adminOnly } = require('../middleware/auth');
const router = express.Router();

// Enhanced dummy data for the SIEM dashboard
const generateDummyLogs = () => {
  const attackTypes = [
    'SSH Brute Force', 'SQL Injection', 'XSS Attack', 'DDoS Attack',
    'Port Scan', 'Malware Upload', 'Credential Stuffing', 'Directory Traversal',
    'Remote Code Execution', 'Buffer Overflow', 'CSRF Attack', 'Man-in-the-Middle'
  ];

  const ipRanges = [
    '192.168.1.', '10.0.0.', '172.16.0.', '203.0.113.', '198.51.100.',
    '185.220.101.', '91.198.174.', '78.46.244.', '46.101.169.'
  ];

  const ports = [22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 6379, 8080];

  const logs = [];
  const now = new Date();

  for (let i = 1; i <= 50; i++) {
    const attackType = attackTypes[Math.floor(Math.random() * attackTypes.length)];
    const ipBase = ipRanges[Math.floor(Math.random() * ipRanges.length)];
    const ipEnd = Math.floor(Math.random() * 255) + 1;
    const port = ports[Math.floor(Math.random() * ports.length)];
    
    // 70% chance of malicious for more realistic threat environment
    const mlPrediction = Math.random() > 0.3 ? 'Malicious' : 'Benign';
    
    // Generate timestamp within last 24 hours
    const hoursAgo = Math.floor(Math.random() * 24);
    const minutesAgo = Math.floor(Math.random() * 60);
    const timestamp = new Date(now.getTime() - (hoursAgo * 60 * 60 * 1000) - (minutesAgo * 60 * 1000));

    logs.push({
      id: i,
      ipAddress: `${ipBase}${ipEnd}`,
      port,
      attackType,
      mlPrediction,
      timestamp: timestamp.toISOString(),
      severity: mlPrediction === 'Malicious' ? 
        ['High', 'Medium', 'Critical'][Math.floor(Math.random() * 3)] : 'Low',
      country: ['Unknown', 'Russia', 'China', 'USA', 'Germany', 'Brazil'][Math.floor(Math.random() * 6)],
      blocked: Math.random() > 0.2 // 80% of attacks are blocked
    });
  }

  return logs.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
};

// @route   GET /api/dashboard
// @desc    Get dashboard data (protected route)
// @access  Private (Admin only)
router.get('/', auth, adminOnly, async (req, res) => {
  try {
    const logs = generateDummyLogs();
    const maliciousLogs = logs.filter(log => log.mlPrediction === 'Malicious');
    const benignLogs = logs.filter(log => log.mlPrediction === 'Benign');
    
    // Calculate threat statistics
    const totalAttacks = logs.length;
    const activeThreats = maliciousLogs.length;
    const blockedAttacks = logs.filter(log => log.blocked).length;
    const criticalThreats = maliciousLogs.filter(log => log.severity === 'Critical').length;
    
    // Calculate threat level
    const threatPercentage = (activeThreats / totalAttacks) * 100;
    let threatLevel = 'LOW';
    if (threatPercentage > 70) threatLevel = 'CRITICAL';
    else if (threatPercentage > 50) threatLevel = 'HIGH';
    else if (threatPercentage > 30) threatLevel = 'MEDIUM';

    // Get top attack types
    const attackTypeCount = {};
    maliciousLogs.forEach(log => {
      attackTypeCount[log.attackType] = (attackTypeCount[log.attackType] || 0) + 1;
    });

    const topAttackTypes = Object.entries(attackTypeCount)
      .sort(([,a], [,b]) => b - a)
      .slice(0, 5)
      .map(([type, count]) => ({ type, count }));

    // Get geographic distribution
    const geoDistribution = {};
    maliciousLogs.forEach(log => {
      geoDistribution[log.country] = (geoDistribution[log.country] || 0) + 1;
    });

    const dashboardData = {
      success: true,
      timestamp: new Date().toISOString(),
      admin: {
        email: req.admin.email,
        lastLogin: req.admin.lastLogin
      },
      stats: {
        totalAttacks,
        activeThreats,
        benignEvents: benignLogs.length,
        blockedAttacks,
        criticalThreats,
        detectionRate: Math.round((activeThreats / totalAttacks) * 100),
        threatLevel
      },
      logs: logs.slice(0, 20), // Return only first 20 for table
      allLogs: logs, // All logs for charts
      analytics: {
        topAttackTypes,
        geoDistribution,
        hourlyActivity: generateHourlyActivity(),
        threatTrends: generateThreatTrends()
      }
    };

    res.json(dashboardData);

  } catch (error) {
    console.error('Dashboard data error:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching dashboard data'
    });
  }
});

// @route   GET /api/dashboard/logs
// @desc    Get all logs with pagination
// @access  Private (Admin only)
router.get('/logs', auth, adminOnly, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 25;
    const filter = req.query.filter || 'all'; // all, malicious, benign
    
    let logs = generateDummyLogs();
    
    // Apply filter
    if (filter === 'malicious') {
      logs = logs.filter(log => log.mlPrediction === 'Malicious');
    } else if (filter === 'benign') {
      logs = logs.filter(log => log.mlPrediction === 'Benign');
    }

    // Calculate pagination
    const startIndex = (page - 1) * limit;
    const endIndex = page * limit;
    const totalLogs = logs.length;
    const totalPages = Math.ceil(totalLogs / limit);

    const paginatedLogs = logs.slice(startIndex, endIndex);

    res.json({
      success: true,
      logs: paginatedLogs,
      pagination: {
        page,
        limit,
        totalLogs,
        totalPages,
        hasNext: endIndex < totalLogs,
        hasPrev: startIndex > 0
      }
    });

  } catch (error) {
    console.error('Logs fetch error:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching logs'
    });
  }
});

// Helper function to generate hourly activity data
function generateHourlyActivity() {
  const hours = [];
  for (let i = 0; i < 24; i++) {
    hours.push({
      hour: i,
      attacks: Math.floor(Math.random() * 20) + 1,
      blocked: Math.floor(Math.random() * 15) + 1
    });
  }
  return hours;
}

// Helper function to generate threat trends (last 7 days)
function generateThreatTrends() {
  const days = [];
  const today = new Date();
  
  for (let i = 6; i >= 0; i--) {
    const date = new Date(today);
    date.setDate(date.getDate() - i);
    
    days.push({
      date: date.toISOString().split('T')[0],
      threats: Math.floor(Math.random() * 50) + 20,
      blocked: Math.floor(Math.random() * 40) + 15
    });
  }
  return days;
}

module.exports = router;
