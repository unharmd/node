// index.js

const { PredictionServiceClient } = require('@google-cloud/aiplatform')
const { locationPath } = require('@google-cloud/aiplatform').v1
const functions = require('@google-cloud/functions-framework')
const Buffer = require('buffer').Buffer

// Environment variables for configuration
const projectId = process.env.PROJECT_ID
const location = process.env.REGION || 'us-central1'
const modelName =
  process.env.MODEL_NAME ||
  'projects/YOUR_PROJECT_ID/locations/YOUR_REGION/publishers/google/models/gemini-bison@001'

// Initialize the Vertex AI Prediction client
const client = new PredictionServiceClient()

async function predictContent (inputText) {
  const endpoint = `projects/${projectId}/locations/${location}/publishers/google/models/${modelName}`

  const instance = { content: inputText }
  const parameters = { temperature: 0.2, maxOutputTokens: 100 }

  const request = {
    endpoint,
    instances: [instance],
    parameters
  }

  // Send the prediction request to the model
  const [response] = await client.predict(request)
  return response.predictions[0].content
}

// HTTP Cloud Function to handle requests
functions.http('predict', async (req, res) => {
  try {
    // Parse the JSON request payload
    const { node_uuid, token, input_hex, service, protocol, port } = req.body

    // Validate input fields
    if (!node_uuid || !token || !input_hex || !service || !protocol || !port) {
      return res.status(400).send('Missing required fields')
    }

    // Decode the hex input to plain text
    const inputText = Buffer.from(input_hex, 'hex').toString('utf-8')

    // Call the predict function with the decoded input
    const responseText = await predictContent(inputText)

    // Convert the response back to hex
    const responseHex = Buffer.from(responseText, 'utf-8').toString('hex')

    // Simulated attack detection logic (for demonstration purposes)
    const isAttack = responseText.toLowerCase().includes('malicious')
    const attackType = isAttack ? 'Suspicious Activity' : 'None'

    // Construct the response
    const response = {
      is_attack: isAttack,
      attack_type: attackType,
      response_hex: responseHex,
      attack_group_key: isAttack ? 'group-123' : '',
      additional_notes: isAttack
        ? 'Potential threat detected based on content analysis.'
        : ''
    }

    // Send the JSON response
    res.status(200).json(response)
  } catch (error) {
    console.error('Error processing request:', error)
    res.status(500).send(`Error: ${error.message}`)
  }
})
