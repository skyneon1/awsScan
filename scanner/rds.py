def scan_rds(session, region: str) -> list[dict]:
    """Return all RDS instances in a region."""
    try:
        client = session.client("rds", region_name=region)
        response = client.describe_db_instances()
        instances = []
        for db in response.get("DBInstances", []):
            state = db["DBInstanceStatus"]
            instances.append({
                "id": db["DBInstanceIdentifier"],
                "name": db["DBInstanceIdentifier"],
                "type": db["DBInstanceClass"],
                "state": state,
                "active": state == "available",
                "region": region,
                "launched": str(db.get("InstanceCreateTime", "N/A")),
                "service": "RDS"
            })
        return instances
    except Exception as e:
        return [{"error": str(e), "region": region, "service": "RDS"}]
