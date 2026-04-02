def scan_lambda(session, region: str) -> list[dict]:
    """Return all Lambda functions in a region."""
    try:
        client = session.client("lambda", region_name=region)
        response = client.list_functions()
        functions = []
        for fn in response.get("Functions", []):
            functions.append({
                "id": fn["FunctionArn"],
                "name": fn["FunctionName"],
                "type": fn["Runtime"],
                "state": "active",
                "active": True,
                "region": region,
                "launched": str(fn.get("LastModified", "N/A")),
                "service": "Lambda",
                "extra": {
                    "Memory": f"{fn.get('MemorySize', 'N/A')} MB",
                    "Timeout": f"{fn.get('Timeout', 'N/A')}s",
                    "Handler": fn.get("Handler", "N/A")
                }
            })
        return functions
    except Exception as e:
        return [{"error": str(e), "region": region, "service": "Lambda"}]
