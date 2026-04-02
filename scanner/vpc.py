def scan_vpc(session, region: str) -> list[dict]:
    """Return all VPCs in a region."""
    try:
        client = session.client("ec2", region_name=region)
        response = client.describe_vpcs()
        vpcs = []
        for vpc in response.get("Vpcs", []):
            name = ""
            for tag in vpc.get("Tags", []):
                if tag["Key"] == "Name":
                    name = tag["Value"]
            vpcs.append({
                "id": vpc["VpcId"],
                "name": name or vpc["VpcId"],
                "type": "VPC",
                "state": vpc["State"],
                "active": vpc["State"] == "available",
                "region": region,
                "launched": "N/A",
                "service": "VPC",
                "extra": {
                    "CIDR Block": vpc.get("CidrBlock", "N/A"),
                    "Is Default": "Yes" if vpc.get("IsDefault") else "No"
                }
            })
        return vpcs
    except Exception as e:
        return [{"error": str(e), "region": region, "service": "VPC"}]
