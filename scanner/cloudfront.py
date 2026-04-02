def scan_cloudfront(session) -> list[dict]:
    """Return all CloudFront distributions (global service)."""
    try:
        client = session.client("cloudfront")
        response = client.list_distributions()
        items = response.get("DistributionList", {}).get("Items", [])
        distributions = []
        for dist in items:
            distributions.append({
                "id": dist["Id"],
                "name": dist["DomainName"],
                "type": "Distribution",
                "state": dist["Status"],
                "active": dist["Status"] == "Deployed" and dist.get("Enabled", False),
                "region": "global",
                "launched": str(dist.get("LastModifiedTime", "N/A")),
                "service": "CloudFront",
                "extra": {
                    "Enabled": "Yes" if dist.get("Enabled") else "No",
                    "Origins": len(dist.get("Origins", {}).get("Items", []))
                }
            })
        return distributions
    except Exception as e:
        return [{"error": str(e), "region": "global", "service": "CloudFront"}]
