def scan_dynamodb(session, region: str) -> list[dict]:
    """Return all DynamoDB tables in a region."""
    try:
        client = session.client("dynamodb", region_name=region)
        tables = []
        paginator = client.get_paginator('list_tables')
        for page in paginator.paginate():
            for table_name in page.get("TableNames", []):
                # Try to get extra info, but swallow exceptions per table if needed
                try:
                    table = client.describe_table(TableName=table_name)["Table"]
                    tables.append({
                        "id": table_name,
                        "name": table_name,
                        "type": "Table",
                        "state": table["TableStatus"].lower(),
                        "active": table["TableStatus"] == "ACTIVE",
                        "region": region,
                        "launched": str(table.get("CreationDateTime", "N/A")),
                        "service": "DynamoDB",
                        "extra": {
                            "Item Count": table.get("ItemCount", 0),
                            "Size (Bytes)": table.get("TableSizeBytes", 0)
                        }
                    })
                except Exception:
                    # Still add the table even if describe_table fails
                    tables.append({
                        "id": table_name,
                        "name": table_name,
                        "type": "Table",
                        "state": "unknown",
                        "active": True,
                        "region": region,
                        "launched": "N/A",
                        "service": "DynamoDB"
                    })
        return tables
    except Exception as e:
        return [{"error": str(e), "region": region, "service": "DynamoDB"}]
