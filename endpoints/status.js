// index.js

const {
  CloudFunctionsServiceClient
} = require('@google-cloud/functions-framework')

// HTTP Cloud Function to handle attack report submissions
CloudFunctionsServiceClient.http('status', async (req, res) => {
  if (req.method !== 'POST') {
    return res.status(405).send('Only POST requests are allowed')
  }

  const report = req.body

  // Log the incoming status report details
  console.log('Received status report from node:', report.node, report)

  // Simulated global blacklist - replace this with real data as needed
  const blacklistedIPs = ['192.168.1.10', '203.0.113.42', '198.51.100.23']

  // Create response object with the blacklist
  const response = {
    blacklisted_ips: blacklistedIPs
  }

  res.setHeader('Content-Type', 'application/json')
  res.status(200).json(response)
})
