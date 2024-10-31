// index.js

const { Firestore } = require('@google-cloud/firestore')
const functions = require('@google-cloud/functions-framework')

// Initialize Firestore client
const firestore = new Firestore()

// Firestore collection name for storing attack reports
const COLLECTION_NAME = 'attack_reports'

// HTTP Cloud Function to handle attack report submissions
functions.http('report', async (req, res) => {
  try {
    // Parse the JSON request payload
    const {
      node_uuid,
      token,
      input_hex,
      service,
      protocol,
      port,
      attack_type,
      attack_group_key,
      timestamp,
      additional_notes,
      source_ip
    } = req.body

    // Validate required fields
    if (
      !node_uuid ||
      !token ||
      !input_hex ||
      !service ||
      !protocol ||
      !port ||
      !attack_type ||
      !timestamp ||
      !source_ip
    ) {
      return res.status(400).send('Missing required fields')
    }

    // Create a Firestore document with the attack report data
    const reportData = {
      node_uuid,
      token,
      input_hex,
      service,
      protocol,
      port,
      attack_type,
      attack_group_key,
      timestamp,
      additional_notes,
      source_ip,
      created_at: Firestore.FieldValue.serverTimestamp()
    }

    // Save the attack report to Firestore
    await firestore.collection(COLLECTION_NAME).add(reportData)

    // Respond with a success message
    res.status(200).send('Attack report saved successfully')
  } catch (error) {
    console.error('Error saving attack report:', error)
    res.status(500).send(`Error: ${error.message}`)
  }
})
