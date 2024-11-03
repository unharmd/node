<p align="center">
  <img src="https://cdn.unharmd.com/logo.png" alt="Unharmd Logo" width="256" title="Unharmd Logo">
</p>

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

# Honeypot Configuration and Command-Line Flags

## Configuration

## Command-Line Flags

- **-services** – List of services to simulate in `port/protocol/uid` format, separated by commas.  
  Example: `-services=80/tcp/HTTP,22/tcp/SSH`.
- **-config** – Path to a JSON configuration file defining services.
- **-llm-api** – URL of the LLM API (overrides environment variable).
- **-report-api** – URL of the reporting API (overrides environment variable).
- **-api-key** – API key for authenticating with APIs (overrides environment variable).
- **-auth-token** – Token for authenticating the node (overrides environment variable).
- **-node-uuid** – UUID for the honeypot instance, allowing central tracking (must be unique).
- **-log-file** – Path to save the attack log file.
- **-conn-limit** – Maximum concurrent connections per IP.
- **-cache-limit** – Maximum number of entries in the response cache.
- **-global-limit** – Maximum global concurrent requests allowed across all connections.

## Example Usage

````bash
./honeypot -services="80/tcp/HTTP,22/tcp/SSH" \
           -llm-api="https://api.example.com/llm" \
           -report-api="https://api.example.com/report" \
           -api-key="YOUR_API_KEY" \
           -auth-token="YOUR_AUTH_TOKEN" \
           -node-uuid="unique-node-1234" \
           -log-file="/var/log/honeypot.log" \
           -conn-limit=10 \
           -cache-limit=50 \
           -global-limit=100


## Google Cloud Functions for Backend

This project includes two Google Cloud Functions that provide essential backend services for the honeypot application. These functions are designed to be lightweight, flexible, and easy to deploy on Google Cloud, supporting both the LLM prediction and node status reporting features.

### Deployment Instructions

1. **Set Up Google Cloud Project**: Ensure that you have a Google Cloud project set up, with the Vertex AI API enabled for `llmPredict` and Firestore API enabled for `report`.
2. **Service Account Permissions**: The service account for these functions needs `aiplatform.models.predict` permission for the `llmPredict` function and `datastore.databases.write` permission for the `report` function.
3. **Deploy the Functions**:

   ```bash
   # Deploy the LLM Prediction function
   gcloud functions deploy predict \
    --runtime nodejs20 \
    --trigger-http \
    --allow-unauthenticated \
    --entry-point predict

   # Deploy the Attack Report function
   gcloud functions deploy status \
    --runtime nodejs20 \
    --trigger-http \
    --allow-unauthenticated \
    --entry-point predict
````

> These functions serve as samples, you can build your own business logic it like we did at https://unharmd.com

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
