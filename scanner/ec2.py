def scan_ec2(session, region: str) -> list[dict]:
    """Return all EC2 instances in a region with status info."""
    try:
        ec2 = session.client("ec2", region_name=region)
        response = ec2.describe_instances()
        instances = []
        for reservation in response["Reservations"]:
            for inst in reservation["Instances"]:
                name = ""
                for tag in inst.get("Tags", []):
                    if tag["Key"] == "Name":
                        name = tag["Value"]
                instances.append({
                    "id": inst["InstanceId"],
                    "name": name or inst["InstanceId"],
                    "type": inst["InstanceType"],
                    "state": inst["State"]["Name"],
                    "active": inst["State"]["Name"] == "running",
                    "region": region,
                    "launched": str(inst.get("LaunchTime", "N/A")),
                    "service": "EC2",
                    "extra": {
                        "Public IP": inst.get("PublicIpAddress", "None"),
                        "Private IP": inst.get("PrivateIpAddress", "None"),
                        "VPC ID": inst.get("VpcId", "None")
                    }
                })
        return instances
    except Exception as e:
        return [{"error": str(e), "region": region, "service": "EC2"}]


# The code here is for testing purposes only of staging environment
