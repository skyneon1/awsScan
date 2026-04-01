def scan_s3(session) -> list[dict]:
    """Return all S3 buckets (S3 is global)."""
    try:
        client = session.client("s3")
        response = client.list_buckets()
        buckets = []
        for bucket in response.get("Buckets", []):
            buckets.append({
                "id": bucket["Name"],
                "name": bucket["Name"],
                "type": "S3 Bucket",
                "state": "active",
                "active": True,
                "region": "global",
                "launched": str(bucket.get("CreationDate", "N/A")),
                "service": "S3"
            })
        return buckets
    except Exception as e:
        return [{"error": str(e), "region": "global", "service": "S3"}]
