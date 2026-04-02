def scan_ebs(session, region: str) -> list[dict]:
    """Return all EBS volumes in a region, identifying unattached ones."""
    try:
        client = session.client("ec2", region_name=region)
        response = client.describe_volumes()
        volumes = []
        for vol in response.get("Volumes", []):
            name = ""
            for tag in vol.get("Tags", []):
                if tag["Key"] == "Name":
                    name = tag["Value"]
            
            # A volume is 'active' (in use) or 'available' (unattached/wasted)
            state = vol["State"].lower()
            active = state == "in-use"
            
            volumes.append({
                "id": vol["VolumeId"],
                "name": name or vol["VolumeId"],
                "type": vol["VolumeType"],
                "state": state,
                "active": active,
                "region": region,
                "launched": str(vol.get("CreateTime", "N/A")),
                "service": "EBS",
                "extra": {
                    "Size": f"{vol.get('Size', 0)} GiB",
                    "IOPS": vol.get("Iops", "N/A"),
                    "Encrypted": "Yes" if vol.get("Encrypted") else "No"
                }
            })
        return volumes
    except Exception as e:
        return [{"error": str(e), "region": region, "service": "EBS"}]
