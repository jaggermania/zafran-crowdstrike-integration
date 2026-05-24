load("zafran", "zafran")
load("http", "http")
load("json", "json")
load("log", "log")
load("time", "time")

MAX_RETRIES = 5
INITIAL_BACKOFF = 1
MAX_BACKOFF = 60
RETRYABLE_STATUS_CODES = [
    429,
    500,
    502,
    503,
    504,
]
FATAL_STATUS_CODES = {
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
}

def main(**kwargs):
    """
    Main.

    Args:
        kwargs: Dynamic keyword arguments.
    """

    log.info("Get parameters ...")
    api_url = kwargs.get("api_url", "https://api.us-2.crowdstrike.com/").rstrip("/")
    client_id = kwargs.get("client_id", "1f23eafd83114c8f85bd53ce0e1323cd")
    client_secret_secret = kwargs.get("client_secret_secret", "QHtdI9mOi1hb7l5jkEvy3xGVXNsTR4Sf806z2peM")
    page_size = int(kwargs.get("page_size", "100"))

    log.info("Starting integration with API:", api_url)

    pb = zafran.proto_file

    log.info("Get bearer token ...")
    bearer_token = get_bearer_token(api_url, client_id, client_secret_secret)
    if not bearer_token:
        log.error("Failed to get bearer token.")
        return None

    log.info("Fetching assets ...")
    all_assets = fetch_all_assets(api_url, bearer_token, page_size)
    log.info("Found %d assets" % len(all_assets))

    log.info("Fetching vunerabilities ...")
    all_vunerabilities = fetch_all_vulnerabilities(api_url, bearer_token, page_size)
    log.info("Found %d vunerabilities" % len(all_vunerabilities))

    log.info("Parsing and collecting assets ...")
    for raw_asset in all_assets:
        instance = parse_to_instance(raw_asset, pb)
        if instance:
            zafran.collect_instance(instance)
            log.info("Collected instance:", instance.name)

    log.info("Parsing and collecting vunerabilities...")
    for raw_vuln in all_vunerabilities:
        vulnerability = parse_to_vulnerability(raw_vuln, pb)
        if vulnerability:
            zafran.collect_vulnerability(vulnerability)
            log.info("Collected vulnerability:", vulnerability.cve)

def get_bearer_token(api_url, client_id, client_secret):
    """
    Get bearer token.

    Args:
        api_url: Base API URL
        client_id: Client ID.
        client_secret: Client secret.

    Returns:
        str | None: Access token if successful, otherwise None.
    """
    log.info("Requesting OAuth token...")

    response = http.post(
        api_url + "/oauth2/token",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
        body="client_id=%s&client_secret=%s" % (client_id, client_secret),
    )

    status = response.get("status_code")

    if status != 201:
        log.error("Failed to get token.")
        log.error("Status code: %s", status)
        log.error("Response: %s", response.get("body", "")[:500])
        return None

    data = json.decode(response.get("body", ""))
    token = data.get("access_token")

    if not token:
        log.error("No access_token in response")
        return None

    log.info("Successfully obtained token")

    return token

def fetch_all_assets(api_url, bearer_token, page_size = 10):
    """
    Fetch all assets using paginated API requests.

    Args:
        api_url: Base API URL.
        bearer_token: OAuth bearer token.
        page_size: Number of assets per request.

    Returns:
        list: List of all asset resources.
    """

    url = api_url + "/devices/combined/devices/v1"

    headers = {
        "Authorization": "Bearer " + bearer_token,
        "Accept": "application/json",
    }
    page_size = 10000 if page_size > 10000 else page_size
    all_items = []
    offset = None

    while True:
        # Build paginated URL

        if offset:
            paginated_url = "%s?limit=%d&offset=%s" % (url, page_size, offset)
        else:
            paginated_url = "%s?limit=%d" % (url, page_size)

        response = fetch_page(paginated_url, headers)

        data = json.decode(response.get("body"))

        offset = data.get("meta", {}).get("pagination", {}).get("next")
        all_items.extend(data["resources"])

        if not offset:
            break

    return all_items

def parse_to_instance(raw_instance, pb):
    """
    Parse raw asset data into an InstanceData proto message.

    Args:
        raw_instance: Raw instance dictionary from the API.
        pb: Proto types from zafran.proto_file.

    Returns:
        InstanceData | None: Parsed instance proto message,
        or None if the instance is invalid.
    """

    instance_id = raw_instance.get("device_id", "")
    if not instance_id:
        log.warn("Instance missing ID, skipping")
        return None

    # Extract fields from raw data
    name = raw_instance.get("hostname", "")
    os = raw_instance.get("os", raw_instance.get("os_version", ""))

    # Build identifiers list
    identifiers = [
        pb.InstanceIdentifier(
            key = pb.IdentifierType.LINUX_UUID,
            value = instance_id
        )
    ]
    ips = []
    macs = []
    key_value_tags = []
    labels = []

    instance = pb.InstanceData(
        instance_id = instance_id,
        name = name,
        operating_system = os,
        asset_information = pb.AssetInstanceInformation(
            ip_addresses = ips,
            mac_addresses = macs
        ),
        identifiers = identifiers,
        labels = labels,
        key_value_tags = key_value_tags
    )

    return instance

def fetch_all_vulnerabilities(api_url, bearer_token, page_size = 1000):
    """
    Fetch all open vulnerabilities using paginated API requests.

    Args:
        api_url: Base API URL.
        bearer_token: OAuth bearer token.
        page_size: Number of vulnerabilities per request.

    Returns:
        list:
    """

    url = api_url + "/spotlight/combined/vulnerabilities/v1"

    headers = {
        "Authorization": "Bearer " + bearer_token,
        "Accept": "application/json",
    }

    all_items = []
    after = None

    page_size = 5000 if page_size > 5000 else page_size

    while True:
        if after:
            paginated_url = "%s?filter=%s&limit=%d&after=%s" % (url, "status:'open'", page_size, after)
        else:
            paginated_url = "%s?filter=%s&limit=%d" % (url, "status:'open'", page_size)

        response = fetch_page(paginated_url, headers)

        data = json.decode(response.get("body"))
        after = data.get("meta", {}).get("pagination", {}).get("after")

        all_items.extend(data["resources"])

        if not after:
            break

    return all_items

def parse_to_vulnerability(raw_vuln, pb):
    """
    Parse raw vulnerability data into a Vulnerability proto message.

    Args:
        raw_vuln: Raw vulnerability dictionary from the API.
        pb: Proto types from zafran.proto_file.

    Returns:
        Vulnerability | None: Parsed vulnerability proto message,
        or None if the vulnerability is invalid.
    """

    cve = raw_vuln.get("cve", {}).get("id")
    if not cve:
        log.warn("Vulnerability missing CVE, skipping")
        return None

    # Extract fields from raw data
    instance_id = raw_vuln.get("id", "")
    description = raw_vuln.get("vulnerability_id", "")

    # OVO RESITI
    product = raw_vuln.get("apps", [])[0]["product_name_normalized"]
    vendor = raw_vuln.get("apps", [])[0]["vendor_normalized"]
    version = raw_vuln.get("version", "")
    score = raw_vuln.get("score")
    vector = raw_vuln.get("vector", "")
    fix = raw_vuln.get("fix", "")

    # Build CVSS list
    cvss_list = []
    if score and vector:
        cvss_list.append(pb.CVSS(
            base_score = float(score),
            vector = vector,
            version = "3.1"
        ))

    # Create and return the Vulnerability proto
    vulnerability = pb.Vulnerability(
        instance_id = instance_id,
        cve = cve,
        description = description,
        in_runtime = True,
        component = pb.Component(
            product = product,
            vendor = vendor,
            version = version,
            type = pb.ComponentType.LIBRARY
        ),
        CVSS = cvss_list,
        remediation = pb.Remediation(
            suggestion = fix,
            source = "Example Scanner"
        )
    )

    return vulnerability

def min_value(a, b):
    """
    Return the smaller of two numbers.

    Args:
        a: First number.
        b: Second.

    Returns:
        The minimum of a and b.
    """

    return a if a < b else b

def get_retry_delay(response, current_delay):
    """
    Get retry delay.

    Args:
        response: Http response.
        current_delay: Delay that will be retruned if no retry header.

    Returns:
        int: Retry delay in seconds.
    """
    headers = response.get("headers", {})

    # Use Retry-After header if present
    if "Retry-After" in headers:
        return int(headers["Retry-After"])

    return current_delay

def fetch_page(url, headers):
    """
    Fetch page.

    Args:
        url: Page url.
        headers: Http header of request.

    Returns:
        dict: HTTP response object.

    Raises:
        RuntimeError: If the request fails permanently or maximum retries are exceeded.
    """
    retries = 0
    backoff = INITIAL_BACKOFF

    while True:
        log.info("Fetching: %s" % url)

        response = http.get(url, headers = headers)

        status = response.get("status_code")

        # Success
        if status == 200:
            return response

        # Retryable errors
        if status in RETRYABLE_STATUS_CODES:
            retries += 1

            if retries > MAX_RETRIES:
                fail("Max retries exceeded for %s (status %d)" % (url, status))

            delay = get_retry_delay(response, backoff)

            log.info("Retry %d/%d after %d seconds (status %d)" % (retries, MAX_RETRIES, delay, status))
            time.sleep(delay)

            # Exponential backoff
            backoff = min_value(backoff * 2, MAX_BACKOFF)
            continue

        # Fatal client errorFATAL CLIENT ERRORS
        if status in FATAL_STATUS_CODES:
            fail("%s (%d)\nResponse: %s" % (FATAL_STATUS_CODES[status], status, response.get("body", "")[:500]))

        # Unknown status
        fail("Unexpected status code: %d\nResponse: %s" % (status, response.get("body", "")[:500]))
