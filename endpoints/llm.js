// index.js

const { PredictionServiceClient } = require('@google-cloud/aiplatform').v1
const {
  CloudFunctionsServiceClient
} = require('@google-cloud/functions-framework')
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
CloudFunctionsServiceClient.http('predict', async (req, res) => {
  try {
    // Parse the JSON request payload
    const { node_uuid, token, input_hex, service, protocol, port } = req.body

    // Validate input fields
    if (!node_uuid || !token || !input_hex || !service || !protocol || !port) {
      return res.status(400).json({ error: 'Missing required fields' })
    }

    // Decode the hex input to plain text
    const inputText = Buffer.from(input_hex, 'hex').toString('utf-8')

    // Call the predict function with the decoded input
    const responseText = await predictContent(inputText)

    // Convert the response back to hex
    const responseHex = Buffer.from(responseText, 'utf-8').toString('hex')

    // Construct the honeypot-compatible response
    const response = {
      response: responseHex, // Hex-encoded response text
      delay: 1000, // 1-second delay (for example)
      continue: true // Allow continuation (for demonstration)
    }

    // Send the JSON response
    res.status(200).json(response)
  } catch (error) {
    console.error('Error processing request:', error)
    res.status(500).json({ error: `Error: ${error.message}` })
  }
})
