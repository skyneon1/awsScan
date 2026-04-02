def scan_cloudfront(session) -> list[dict]:
    """Return all CloudFront distributions (global service)."""
    try:
        client = session.client("cloudfront")
        response = client.list_distributions()
        items = response.get("DistributionList", {}).get("Items", [])
        if not items:
            return []
        distributions = []
        for dist in items:
            # FIX: 'Enabled' lives inside DistributionConfig, not at top level
            enabled = dist.get("DistributionConfig", {}).get("Enabled", False)
            status  = dist.get("Status", "")
            distributions.append({
                "id":       dist["Id"],
                "name":     dist.get("DomainName", dist["Id"]),
                "type":     "Distribution",
                "state":    status,
                "active":   status == "Deployed" and enabled,
                "region":   "global",
                "launched": str(dist.get("LastModifiedTime", "N/A")),
                "service":  "CloudFront",
                "extra": {
                    "Enabled": "Yes" if enabled else "No",
                    "Origins": len(dist.get("Origins", {}).get("Items", [])),
                }
            })
        return distributions
    except Exception as e:
        return [{"error": str(e), "region": "global", "service": "CloudFront"}]
