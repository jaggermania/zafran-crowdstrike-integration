# CrowdStrike Integration Script

This directory contains a Starlark script designed to integrate CrowdStrike with the Zafran platform.

## Overview

The `crowdstrike.star` script automates the retrieval of asset devices and open vulnerabilities from CrowdStrike APIs, processes them, and ingests them into Zafran.

Specifically, the script shows how to:
- Authenticate against CrowdStrike's OAuth2 endpoint using a client ID and client secret.
- Fetch device assets using CrowdStrike's paginated endpoint (`/devices/combined/devices/v1`).
- Fetch open vulnerabilities using CrowdStrike's Spotlight API (`/spotlight/combined/vulnerabilities/v1`).
- Transform CrowdStrike's API responses into Zafran proto formats (`InstanceData` and `Vulnerability`).
- Handle network resilience with an exponential backoff mechanism for retryable status codes.

## How to Use This Script

1. **Verify API Access** - Ensure you have valid CrowdStrike Falcon API credentials (`client_id` and `client_secret`) with read scopes for both **Devices** and **Spotlight vulnerabilities**.

2. **Adjust Pagination Limits** - The script includes defensive caps for page limits to optimize API execution (capped at `10000` for assets and `5000` for vulnerabilities). You can adjust default values by passing a `page_size` parameter during manual testing.

## Script Structure

| Function | Purpose                                                                                                                                          |
|----------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| `main` | Entry point that orchestrates parameters, executes authentication, pulls assets/vulnerabilities, and invokes the parsing pipelines.              |
| `get_bearer_token` | Handles OAuth2 token exchange with the `/oauth2/token` CrowdStrike API endpoint.                                                                 |
| `fetch_all_assets` | Iterates and fetches all assets using an offset-based pagination loop.                                                                           |
| `parse_to_instance` | Converts raw asset items into Zafran `InstanceData` proto messages, extracting hostnames, operating systems, and UUID identifiers.               |
| `fetch_all_vulnerabilities` | Pulls all open vulnerability entries from CrowdStrike Spotlight using the cursor-based `after` token parameter.                                  |
| `parse_to_vulnerability` | Maps Falcon Spotlight vulnerabilities to Zafran `Vulnerability` proto schemas including CVSS v3.1 arrays, product scopes, and remediation rules. |
| `fetch_page` | Core HTTP wrapper that safely fires requests, captures status errors, and implements an exponential retry backoff mechanism.                     |
| `get_retry_delay` | Determines delay timings using HTTP `Retry-After` headers if provided by the CrowdStrike Gateway API.                                            |

## Running the Script

You can test the script locally using the Starlark runner binary:

```bash
# Linux execution example
./starlark-runner -script crowdstrike.star -params "api_url=https://api.us-2.crowdstrike.com,client_id=your_client_id,client_secret=your_client_secret"
