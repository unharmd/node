// server.js
const express = require('express')
const axios = require('axios')
const app = express()
app.use(express.json())

// Configuration
const GEMINI_API_URL = 'https://gemini.googleapis.com/v1/models/llm' // Replace with the correct Gemini endpoint
const API_KEY = 'YOUR_GOOGLE_CLOUD_API_KEY'
const PORT = process.env.PORT || 8080

// Endpoint to analyze payload using Gemini (LLM) model
app.post('/llm', async (req, res) => {
  const { input_hex, service, protocol } = req.body

  try {
    // Convert hex-encoded input to a human-readable string for Gemini
    const decodedInput = Buffer.from(input_hex, 'hex').toString('utf-8')

    // Prepare the request body for Gemini
    const geminiRequest = {
      model: 'gemini-llm-model', // Replace with actual model ID
      prompt: `Analyze this request: "${decodedInput}" for service: "${service}", protocol: "${protocol}". 
      Detect if it is malicious, and provide a response and attack classification if necessary.`,
      temperature: 0.7,
      max_tokens: 150
    }

    // Send request to Gemini
    const geminiResponse = await axios.post(
      `${GEMINI_API_URL}:predict`,
      geminiRequest,
      {
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${API_KEY}`
        }
      }
    )

    const {
      is_attack,
      attack_type,
      response,
      attack_group_key,
      additional_notes
    } = parseGeminiResponse(geminiResponse.data)

    // Respond back with structured data
    res.json({
      is_attack,
      attack_type,
      response_hex: Buffer.from(response).toString('hex'),
      attack_group_key,
      additional_notes
    })
  } catch (error) {
    console.error('Error querying Gemini:', error.message)
    res.status(500).json({ error: 'Failed to analyze payload with Gemini' })
  }
})

// Helper function to parse Gemini response
function parseGeminiResponse (geminiData) {
  // Customize this parser based on Gemini's response structure
  const is_attack = geminiData.includes('attack')
  const attack_type = is_attack ? 'Detected' : 'None'
  const response = is_attack ? 'Respond with delay' : 'Respond normally'
  const attack_group_key = is_attack ? 'group-attack' : ''
  const additional_notes = is_attack
    ? 'Potential malicious activity detected.'
    : 'No suspicious activity.'

  return {
    is_attack,
    attack_type,
    response,
    attack_group_key,
    additional_notes
  }
}

// Endpoint to log attack data
app.post('/report', (req, res) => {
  const attackData = req.body
  console.log('Attack report received:', JSON.stringify(attackData, null, 2))

  // Here, you can save `attackData` to a database or log file
  res.json({ message: 'Attack report logged successfully' })
})

// Start the server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
})
