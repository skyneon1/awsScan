"""
Cost estimation scanner — returns rough monthly cost estimates
using publicly known on-demand pricing for common resource types.
This does NOT call the AWS Pricing API; it uses a bundled lookup table
so it works without needing extra IAM permissions.
"""

# ─── EC2 On-Demand pricing (us-east-1, Linux, partial list) ────────────────
EC2_HOURLY_USD = {
    "t2.nano": 0.0058, "t2.micro": 0.0116, "t2.small": 0.023,
    "t2.medium": 0.0464, "t2.large": 0.0928, "t2.xlarge": 0.1856,
    "t3.nano": 0.0052, "t3.micro": 0.0104, "t3.small": 0.0208,
    "t3.medium": 0.0416, "t3.large": 0.0832, "t3.xlarge": 0.1664,
    "t3.2xlarge": 0.3328,
    "t3a.nano": 0.0047, "t3a.micro": 0.0094, "t3a.small": 0.0188,
    "t3a.medium": 0.0376, "t3a.large": 0.0752,
    "m5.large": 0.096, "m5.xlarge": 0.192, "m5.2xlarge": 0.384,
    "m5.4xlarge": 0.768, "m5.8xlarge": 1.536,
    "m6i.large": 0.096, "m6i.xlarge": 0.192, "m6i.2xlarge": 0.384,
    "c5.large": 0.085, "c5.xlarge": 0.17, "c5.2xlarge": 0.34,
    "c6i.large": 0.085, "c6i.xlarge": 0.17,
    "r5.large": 0.126, "r5.xlarge": 0.252, "r5.2xlarge": 0.504,
    "r6i.large": 0.126, "r6i.xlarge": 0.252,
    "p3.2xlarge": 3.06, "p3.8xlarge": 12.24, "p3.16xlarge": 24.48,
    "g4dn.xlarge": 0.526, "g4dn.2xlarge": 0.752,
    "inf1.xlarge": 0.228, "inf1.2xlarge": 0.362,
}

# ─── RDS On-Demand pricing (us-east-1, MySQL, single-AZ) ───────────────────
RDS_HOURLY_USD = {
    "db.t2.micro": 0.017, "db.t2.small": 0.034, "db.t2.medium": 0.068,
    "db.t3.micro": 0.017, "db.t3.small": 0.034, "db.t3.medium": 0.068,
    "db.t3.large": 0.136, "db.t3.xlarge": 0.272,
    "db.m5.large": 0.171, "db.m5.xlarge": 0.342, "db.m5.2xlarge": 0.684,
    "db.m6g.large": 0.162, "db.m6g.xlarge": 0.325,
    "db.r5.large": 0.24, "db.r5.xlarge": 0.48, "db.r5.2xlarge": 0.96,
    "db.r6g.large": 0.228, "db.r6g.xlarge": 0.456,
}

HOURS_PER_MONTH = 730


def estimate_ec2_cost(instance_type: str, state: str) -> dict:
    if state != "running":
        return {"hourly_usd": 0.0, "monthly_usd": 0.0, "note": "Stopped (no compute charge)"}
    hourly = EC2_HOURLY_USD.get(instance_type)
    if hourly is None:
        return {"hourly_usd": None, "monthly_usd": None, "note": "Pricing unavailable for this type"}
    return {
        "hourly_usd": round(hourly, 4),
        "monthly_usd": round(hourly * HOURS_PER_MONTH, 2),
        "note": "On-demand, Linux, us-east-1 estimate",
    }


def estimate_rds_cost(db_class: str) -> dict:
    hourly = RDS_HOURLY_USD.get(db_class)
    if hourly is None:
        return {"hourly_usd": None, "monthly_usd": None, "note": "Pricing unavailable for this class"}
    return {
        "hourly_usd": round(hourly, 4),
        "monthly_usd": round(hourly * HOURS_PER_MONTH, 2),
        "note": "On-demand, MySQL Single-AZ, us-east-1 estimate",
    }


def estimate_lambda_cost(monthly_invocations: int = 0, avg_duration_ms: int = 200,
                          memory_mb: int = 128) -> dict:
    """
    Lambda pricing: $0.20 per 1M requests + $0.0000166667 per GB-second.
    Default assumes no CloudWatch data available, returns a sample estimate.
    """
    req_cost = (monthly_invocations / 1_000_000) * 0.20
    gb_seconds = (avg_duration_ms / 1000) * (memory_mb / 1024) * monthly_invocations
    compute_cost = gb_seconds * 0.0000166667
    total = req_cost + compute_cost
    return {
        "monthly_usd": round(total, 4),
        "note": f"Estimate based on {monthly_invocations:,} req/mo, {avg_duration_ms}ms, {memory_mb}MB",
    }


def scan_costs(session) -> dict:
    """
    Pull resource inventory and attach cost estimates.
    Returns { "ec2": [...], "rds": [...], "total_monthly_usd": float }
    """
    result = {"ec2": [], "rds": [], "total_monthly_usd": 0.0, "breakdown": {}}

    try:
        from scanner.base import get_all_regions
        regions = get_all_regions(session)
    except Exception:
        regions = ["us-east-1"]

    total = 0.0
    breakdown = {}

    for region in regions:
        # EC2
        try:
            ec2 = session.client("ec2", region_name=region)
            for res in ec2.describe_instances()["Reservations"]:
                for inst in res["Instances"]:
                    name = next((t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"), inst["InstanceId"])
                    est = estimate_ec2_cost(inst["InstanceType"], inst["State"]["Name"])
                    row = {
                        "service": "EC2",
                        "id": inst["InstanceId"],
                        "name": name,
                        "region": region,
                        "type": inst["InstanceType"],
                        "state": inst["State"]["Name"],
                        **est,
                    }
                    result["ec2"].append(row)
                    if est.get("monthly_usd"):
                        total += est["monthly_usd"]
                        breakdown["EC2"] = breakdown.get("EC2", 0) + est["monthly_usd"]
        except Exception:
            pass

        # RDS
        try:
            rds = session.client("rds", region_name=region)
            for db in rds.describe_db_instances().get("DBInstances", []):
                est = estimate_rds_cost(db["DBInstanceClass"])
                row = {
                    "service": "RDS",
                    "id": db["DBInstanceIdentifier"],
                    "name": db["DBInstanceIdentifier"],
                    "region": region,
                    "type": db["DBInstanceClass"],
                    "state": db["DBInstanceStatus"],
                    **est,
                }
                result["rds"].append(row)
                if est.get("monthly_usd"):
                    total += est["monthly_usd"]
                    breakdown["RDS"] = breakdown.get("RDS", 0) + est["monthly_usd"]
        except Exception:
            pass

    result["total_monthly_usd"] = round(total, 2)
    result["breakdown"] = {k: round(v, 2) for k, v in breakdown.items()}
    return result
