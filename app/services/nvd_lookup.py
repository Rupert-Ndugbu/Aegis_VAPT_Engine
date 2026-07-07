import httpx

async def fetch_vulnerabilities(service_name: str):
    # Using the official NVD API structure
    # You will need an API Key for higher rate limits if you scale this
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": service_name}
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(base_url, params=params, timeout=10.0)
            if response.status_code == 200:
                data = response.json()
                # Parse the response to return a meaningful summary
                vulnerabilities = data.get("vulnerabilities", [])
                if vulnerabilities:
                    cve_id = vulnerabilities[0]["cve"]["id"]
                    return f"{cve_id}: Found real vulnerability data via NVD."
                return "No CVEs found for this service."
            return "NVD API unavailable."
        except Exception as e:
            return f"Error connecting to NVD: {str(e)}"
