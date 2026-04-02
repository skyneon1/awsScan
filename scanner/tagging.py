def _check_tags(tags: list, required: list) -> list:
    existing = {t["Key"] for t in (tags or [])}
    return [k for k in required if k not in existing]

def scan_tag_compliance(session, required_tags: list = None) -> list[dict]:
    required = required_tags or ["Name", "Environment", "Owner", "Project"]
    records = []

    try:
        from scanner.base import get_all_regions
        regions = get_all_regions(session)
    except Exception:
        regions = ["us-east-1"]

    for region in regions:

        # EC2 instances
        try:
            ec2 = session.client("ec2", region_name=region)
            for res in ec2.describe_instances()["Reservations"]:
                for inst in res["Instances"]:
                    tags = inst.get("Tags", [])
                    missing = _check_tags(tags, required)
                    name = next((t["Value"] for t in tags if t["Key"] == "Name"), inst["InstanceId"])
                    records.append({
                        "service": "EC2",
                        "id": inst["InstanceId"],
                        "name": name,
                        "region": region,
                        "compliant": len(missing) == 0,
                        "missing_tags": missing,
                        "existing_tags": {t["Key"]: t["Value"] for t in tags},
                    })
        except Exception:
            pass

        # Lambda functions
        try:
            lam = session.client("lambda", region_name=region)
            for fn in lam.list_functions().get("Functions", []):
                try:
                    tag_resp = lam.list_tags(Resource=fn["FunctionArn"])
                    raw_tags = [{"Key": k, "Value": v} for k, v in tag_resp.get("Tags", {}).items()]
                except Exception:
                    raw_tags = []
                missing = _check_tags(raw_tags, required)
                records.append({
                    "service": "Lambda",
                    "id": fn["FunctionArn"],
                    "name": fn["FunctionName"],
                    "region": region,
                    "compliant": len(missing) == 0,
                    "missing_tags": missing,
                    "existing_tags": {t["Key"]: t["Value"] for t in raw_tags},
                })
        except Exception:
            pass

        # RDS
        try:
            rds = session.client("rds", region_name=region)
            for db in rds.describe_db_instances().get("DBInstances", []):
                try:
                    tag_resp = rds.list_tags_for_resource(ResourceName=db["DBInstanceArn"])
                    raw_tags = tag_resp.get("TagList", [])
                except Exception:
                    raw_tags = []
                missing = _check_tags(raw_tags, required)
                records.append({
                    "service": "RDS",
                    "id": db["DBInstanceIdentifier"],
                    "name": db["DBInstanceIdentifier"],
                    "region": region,
                    "compliant": len(missing) == 0,
                    "missing_tags": missing,
                    "existing_tags": {t["Key"]: t["Value"] for t in raw_tags},
                })
        except Exception:
            pass

    return records
