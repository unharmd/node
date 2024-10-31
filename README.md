# Unharmd Edge Node

This project is a honeypot edge designed to simulate network services, monitor interactions, and detect potential malicious activity using a Language Model (LLM). By analyzing incoming payloads, the honeypot can identify attack attempts and respond accordingly. It also caches responses to reduce LLM usage and includes session tracking for comprehensive attack reports.

## Features

- **LLM-Based Attack Detection**: Uses a Language Model to analyze payloads, identify attacks, and generate appropriate responses.
- **Session Tracking**: Logs each client request and server response to enable detailed session reporting.
- **Dynamic Blacklisting**: Automatically blocks IP addresses that exceed a configurable connection limit.
- **Caching**: Implements an LRU (Least Recently Used) cache to avoid redundant queries to the LLM, optimizing for both performance and cost.
- **Configurable Protocols**: Supports both TCP and UDP protocols, allowing a wide range of service simulations.

## Requirements

- **Go 1.18+**
- **LLM API Endpoint**: Requires access to a Language Model API (e.g., Google Gemini).
- **Reporting API**: An endpoint to log detected attacks and maintain a centralized attack database.

## Configuration

### Environment Variables

- `LLM_API_URL` – URL of the LLM API for payload analysis.
- `REPORT_API_URL` – URL of the API to report detected attacks.
- `API_KEY` – API key for authenticating with the LLM and reporting APIs.
- `AUTH_TOKEN` – Authentication token for verifying the node's identity with the API.
- `NODE_UUID` – Unique identifier for the honeypot instance, generated externally and passed to the honeypot on startup.

### Command-Line Flags

- `-services` – List of services to simulate in `port/protocol/service` format, separated by commas. Example: `-services=80/tcp/HTTP,22/tcp/SSH`.
- `-config` – Path to a JSON configuration file defining services.
- `-llm-api` – URL of the LLM API (overrides environment variable).
- `-report-api` – URL of the reporting API (overrides environment variable).
- `-api-key` – API key for authenticating with APIs (overrides environment variable).
- `-auth-token` – Token for authenticating the node (overrides environment variable).
- `-node-uuid` – UUID for the honeypot instance, allowing central tracking (must be unique).
- `-log-file` – Path to save the attack log file.
- `-conn-limit` – Maximum concurrent connections per IP.
- `-cache-limit` – Maximum number of entries in the response cache.

## Usage

After building the binary, run the honeypot with the desired configuration:

```bash
./unharmed-node-${arch} \
    -services="80/tcp/HTTP,22/tcp/SSH" \
    -llm-api="http://localhost:8080/llm" \
    -report-api="http://localhost:8080/report" \
    -api-key="YOUR_API_KEY" \
    -auth-token="YOUR_AUTH_TOKEN" \
    -node-uuid="YOUR_UNIQUE_NODE_UUID" \
    -log-file="attacks.log" \
    -conn-limit=5 \
    -cache-limit=100
```

## Google Cloud Functions for Backend

This project includes two Google Cloud Functions that provide essential backend services for the honeypot application. These functions are designed to be lightweight, flexible, and easy to deploy on Google Cloud, supporting both the LLM prediction and attack reporting functionalities.

### Functions Overview

1. **LLM Prediction Function (`llmPredict`)**

   - **Purpose**: Acts as an interface for sending payloads to a Language Learning Model (LLM) like Google’s Gemini Flash to analyze potential threats based on the content.
   - **Endpoint**: Receives hex-encoded payload data and metadata, decodes it, forwards it to the model, and returns a structured response indicating whether an attack is suspected.
   - **Environment Variables**:
     - `PROJECT_ID`: Google Cloud Project ID.
     - `REGION`: Google Cloud region where the model is hosted.
     - `MODEL_NAME`: Path to the LLM model (e.g., `projects/YOUR_PROJECT_ID/locations/YOUR_REGION/publishers/google/models/gemini-bison@001`).

2. **Attack Report Function (`report`)**
   - **Purpose**: Stores attack data sent from the honeypot in Google Cloud Firestore, providing centralized logging of potential threats.
   - **Endpoint**: Receives JSON-formatted reports from the honeypot application, verifies required fields, and saves the information in the Firestore `attack_reports` collection.
   - **Firestore Collection**: `attack_reports`

### Deployment Instructions

1. **Set Up Google Cloud Project**: Ensure that you have a Google Cloud project set up, with the Vertex AI API enabled for `llmPredict` and Firestore API enabled for `report`.
2. **Service Account Permissions**: The service account for these functions needs `aiplatform.models.predict` permission for the `llmPredict` function and `datastore.databases.write` permission for the `report` function.
3. **Deploy the Functions**:

   ```bash
   # Deploy the LLM Prediction function
   gcloud functions deploy llmPredict \
       --runtime nodejs20 \
       --trigger-http \
       --allow-unauthenticated \
       --region YOUR_REGION \
       --set-env-vars PROJECT_ID=YOUR_PROJECT_ID,MODEL_NAME=projects/YOUR_PROJECT_ID/locations/YOUR_REGION/publishers/google/models/gemini-bison@001

   # Deploy the Attack Report function
   gcloud functions deploy report \
       --runtime nodejs20 \
       --trigger-http \
       --allow-unauthenticated \
       --region YOUR_REGION
   ```

## Contributing

Contributions are welcome! Feel free to submit pull requests or open issues for improvements and bug fixes.

# Dual License

This project is licensed under a dual-license model. Individuals and organizations may use this project under the terms of the Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0) license for non-commercial purposes. Commercial entities wishing to use, distribute, or modify this project must obtain a separate commercial license. The owner reserves the right to change these terms at any stage which will apply for subsequent releases.

## Non-Commercial License (CC BY-NC 4.0)

**License Summary**: This software is licensed for non-commercial use under the Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0) License. You may copy, distribute, and adapt the work as long as you credit the original work and do not use it for commercial purposes. Full license details can be found at:
[https://creativecommons.org/licenses/by-nc/4.0/](https://creativecommons.org/licenses/by-nc/4.0/)

### Key Terms

- **Attribution**: You must give appropriate credit, provide a link to the license, and indicate if changes were made. You may do so in any reasonable manner, but not in any way that suggests the licensor endorses you or your use.
- **Non-Commercial**: You may not use the material for commercial purposes.
- **No Additional Restrictions**: You may not apply legal terms or technological measures that legally restrict others from doing anything the license permits.

### Disclaimer

This software is provided "as is," without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and non-infringement. In no event shall the authors or copyright holders be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software.

## Commercial License

For commercial use of this software, including but not limited to usage within a business, incorporation into a commercial product, or for-profit activities, you are required to obtain a commercial license. Please contact the authors at sales@unharmd.com to discuss licensing terms and fees.

Unauthorized commercial use of this software constitutes a violation of this license. Failure to obtain a commercial license may result in legal action.
