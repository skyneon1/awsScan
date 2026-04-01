"""
Security audit scanner — checks for common AWS misconfigurations.
Returns findings with severity: CRITICAL | HIGH | MEDIUM | LOW | INFO
"""
from datetime import datetime, timezone


def _age_days(dt_obj):
    if dt_obj is None:
        return None
    if dt_obj.tzinfo is None:
        dt_obj = dt_obj.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - dt_obj).days


# ─── IAM ─────────────────────────────────────────────────────────────────────

def audit_iam(session) -> list[dict]:
    findings = []
    try:
        iam = session.client("iam")

        # 1. Root account access keys
        try:
            summary = iam.get_account_summary()["SummaryMap"]
            if summary.get("AccountAccessKeysPresent", 0) > 0:
                findings.append({
                    "severity": "CRITICAL",
                    "category": "IAM",
                    "title": "Root account has access keys",
                    "detail": "The root account has active access keys. These should be removed immediately.",
                    "resource": "AWS Root Account",
                    "region": "global",
                })
            if summary.get("AccountMFAEnabled", 0) == 0:
                findings.append({
                    "severity": "CRITICAL",
                    "category": "IAM",
                    "title": "Root account MFA not enabled",
                    "detail": "Multi-Factor Authentication is not enabled on the root account.",
                    "resource": "AWS Root Account",
                    "region": "global",
                })
        except Exception:
            pass

        # 2. IAM users without MFA
        try:
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page["Users"]:
                    uname = user["UserName"]
                    mfa_devices = iam.list_mfa_devices(UserName=uname)["MFADevices"]
                    if not mfa_devices:
                        findings.append({
                            "severity": "HIGH",
                            "category": "IAM",
                            "title": f"IAM user '{uname}' has no MFA device",
                            "detail": "This user can log in with only a password. Enable MFA to protect the account.",
                            "resource": uname,
                            "region": "global",
                        })

                    # 3. Old access keys (> 90 days)
                    keys = iam.list_access_keys(UserName=uname)["AccessKeyMetadata"]
                    for key in keys:
                        if key["Status"] == "Active":
                            age = _age_days(key["CreateDate"])
                            if age is not None and age > 90:
                                findings.append({
                                    "severity": "MEDIUM",
                                    "category": "IAM",
                                    "title": f"Access key for '{uname}' is {age} days old",
                                    "detail": f"Key ID {key['AccessKeyId']} was created {age} days ago. Rotate access keys every 90 days.",
                                    "resource": uname,
                                    "region": "global",
                                })
        except Exception:
            pass

        # 4. Password policy
        try:
            pp = iam.get_account_password_policy()["PasswordPolicy"]
            if pp.get("MinimumPasswordLength", 0) < 14:
                findings.append({
                    "severity": "MEDIUM",
                    "category": "IAM",
                    "title": "Weak IAM password policy (min length < 14)",
                    "detail": f"Current minimum password length is {pp.get('MinimumPasswordLength')}. AWS recommends at least 14.",
                    "resource": "Password Policy",
                    "region": "global",
                })
            if not pp.get("RequireMFAAuthentication", False) and not pp.get("RequireNumbers", False):
                findings.append({
                    "severity": "LOW",
                    "category": "IAM",
                    "title": "Password policy does not require numbers",
                    "detail": "Strengthen password policy to require numbers, symbols, and mixed case.",
                    "resource": "Password Policy",
                    "region": "global",
                })
        except iam.exceptions.NoSuchEntityException:
            findings.append({
                "severity": "HIGH",
                "category": "IAM",
                "title": "No IAM password policy configured",
                "detail": "Set a strong account-level password policy.",
                "resource": "Password Policy",
                "region": "global",
            })
        except Exception:
            pass

    except Exception as e:
        findings.append({"severity": "INFO", "category": "IAM", "title": "IAM audit error",
                         "detail": str(e), "resource": "IAM", "region": "global"})
    return findings


# ─── S3 ──────────────────────────────────────────────────────────────────────

def audit_s3(session) -> list[dict]:
    findings = []
    try:
        s3 = session.client("s3")
        buckets = s3.list_buckets().get("Buckets", [])
        for bucket in buckets:
            name = bucket["Name"]

            # Public access block
            try:
                pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
                if not all([
                    pab.get("BlockPublicAcls"),
                    pab.get("IgnorePublicAcls"),
                    pab.get("BlockPublicPolicy"),
                    pab.get("RestrictPublicBuckets"),
                ]):
                    findings.append({
                        "severity": "HIGH",
                        "category": "S3",
                        "title": f"Bucket '{name}' does not block all public access",
                        "detail": "One or more public access block settings are disabled. Review bucket policy and ACLs.",
                        "resource": name,
                        "region": "global",
                    })
            except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
                findings.append({
                    "severity": "HIGH",
                    "category": "S3",
                    "title": f"Bucket '{name}' has no public access block configured",
                    "detail": "Enable S3 Block Public Access settings on this bucket.",
                    "resource": name,
                    "region": "global",
                })
            except Exception:
                pass

            # Versioning
            try:
                ver = s3.get_bucket_versioning(Bucket=name)
                if ver.get("Status") != "Enabled":
                    findings.append({
                        "severity": "LOW",
                        "category": "S3",
                        "title": f"Bucket '{name}' versioning is not enabled",
                        "detail": "Enable versioning to protect against accidental deletion or overwrites.",
                        "resource": name,
                        "region": "global",
                    })
            except Exception:
                pass

            # Encryption
            try:
                s3.get_bucket_encryption(Bucket=name)
            except Exception as e:
                if "ServerSideEncryptionConfigurationNotFoundError" in str(type(e)):
                    findings.append({
                        "severity": "MEDIUM",
                        "category": "S3",
                        "title": f"Bucket '{name}' is not encrypted at rest",
                        "detail": "Enable default server-side encryption (SSE-S3 or SSE-KMS).",
                        "resource": name,
                        "region": "global",
                    })

    except Exception as e:
        findings.append({"severity": "INFO", "category": "S3", "title": "S3 audit error",
                         "detail": str(e), "resource": "S3", "region": "global"})
    return findings


# ─── EC2 / Security Groups ────────────────────────────────────────────────────

def audit_ec2(session, region: str) -> list[dict]:
    findings = []
    try:
        ec2 = session.client("ec2", region_name=region)

        # Security groups with unrestricted inbound
        try:
            sgs = ec2.describe_security_groups()["SecurityGroups"]
            dangerous_ports = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL",
                               27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch"}
            for sg in sgs:
                for perm in sg.get("IpPermissions", []):
                    from_port = perm.get("FromPort", 0)
                    to_port = perm.get("ToPort", 65535)
                    for cidr in perm.get("IpRanges", []):
                        if cidr.get("CidrIp") == "0.0.0.0/0":
                            # Check for critical ports
                            for port, svc_name in dangerous_ports.items():
                                if from_port <= port <= to_port:
                                    findings.append({
                                        "severity": "CRITICAL" if port in (22, 3389) else "HIGH",
                                        "category": "EC2",
                                        "title": f"Security group '{sg['GroupName']}' allows {svc_name} from anywhere",
                                        "detail": f"Port {port} ({svc_name}) is open to 0.0.0.0/0 in SG {sg['GroupId']}. Restrict access to known IPs.",
                                        "resource": sg["GroupId"],
                                        "region": region,
                                    })
                            # Wildcard check (all traffic)
                            if perm.get("IpProtocol") == "-1":
                                findings.append({
                                    "severity": "CRITICAL",
                                    "category": "EC2",
                                    "title": f"Security group '{sg['GroupName']}' allows ALL traffic from 0.0.0.0/0",
                                    "detail": f"SG {sg['GroupId']} permits all inbound traffic. This is a critical misconfiguration.",
                                    "resource": sg["GroupId"],
                                    "region": region,
                                })
                    for cidr6 in perm.get("Ipv6Ranges", []):
                        if cidr6.get("CidrIpv6") == "::/0":
                            for port, svc_name in dangerous_ports.items():
                                if from_port <= port <= to_port:
                                    findings.append({
                                        "severity": "HIGH",
                                        "category": "EC2",
                                        "title": f"Security group '{sg['GroupName']}' allows {svc_name} from ::/0 (IPv6)",
                                        "detail": f"Port {port} is open to all IPv6 in SG {sg['GroupId']}.",
                                        "resource": sg["GroupId"],
                                        "region": region,
                                    })
        except Exception:
            pass

        # Unencrypted EBS volumes
        try:
            vols = ec2.describe_volumes()["Volumes"]
            for vol in vols:
                if not vol.get("Encrypted", False):
                    findings.append({
                        "severity": "MEDIUM",
                        "category": "EC2",
                        "title": f"EBS volume '{vol['VolumeId']}' is not encrypted",
                        "detail": "Enable EBS volume encryption to protect data at rest.",
                        "resource": vol["VolumeId"],
                        "region": region,
                    })
        except Exception:
            pass

        # Public AMIs / instances with public IP
        try:
            reservations = ec2.describe_instances()["Reservations"]
            for res in reservations:
                for inst in res["Instances"]:
                    if inst.get("PublicIpAddress") and inst["State"]["Name"] == "running":
                        # Check if it's in a public subnet — just flag it
                        name = ""
                        for tag in inst.get("Tags", []):
                            if tag["Key"] == "Name":
                                name = tag["Value"]
                        findings.append({
                            "severity": "INFO",
                            "category": "EC2",
                            "title": f"Instance '{name or inst['InstanceId']}' has a public IP",
                            "detail": f"Instance {inst['InstanceId']} has public IP {inst['PublicIpAddress']}. Ensure this is intentional.",
                            "resource": inst["InstanceId"],
                            "region": region,
                        })
        except Exception:
            pass

    except Exception as e:
        findings.append({"severity": "INFO", "category": "EC2", "title": "EC2 audit error",
                         "detail": str(e), "resource": "EC2", "region": region})
    return findings


# ─── RDS ─────────────────────────────────────────────────────────────────────

def audit_rds(session, region: str) -> list[dict]:
    findings = []
    try:
        rds = session.client("rds", region_name=region)
        dbs = rds.describe_db_instances().get("DBInstances", [])
        for db in dbs:
            iid = db["DBInstanceIdentifier"]
            if db.get("PubliclyAccessible"):
                findings.append({
                    "severity": "HIGH",
                    "category": "RDS",
                    "title": f"RDS instance '{iid}' is publicly accessible",
                    "detail": "This database is reachable from the internet. Disable public accessibility unless required.",
                    "resource": iid,
                    "region": region,
                })
            if not db.get("StorageEncrypted"):
                findings.append({
                    "severity": "HIGH",
                    "category": "RDS",
                    "title": f"RDS instance '{iid}' storage is not encrypted",
                    "detail": "Enable storage encryption to protect data at rest.",
                    "resource": iid,
                    "region": region,
                })
            if db.get("BackupRetentionPeriod", 0) < 7:
                findings.append({
                    "severity": "MEDIUM",
                    "category": "RDS",
                    "title": f"RDS instance '{iid}' backup retention is less than 7 days",
                    "detail": f"Current retention: {db.get('BackupRetentionPeriod', 0)} days. Set to 7+ for resilience.",
                    "resource": iid,
                    "region": region,
                })
            if not db.get("MultiAZ"):
                findings.append({
                    "severity": "LOW",
                    "category": "RDS",
                    "title": f"RDS instance '{iid}' is not Multi-AZ",
                    "detail": "Enable Multi-AZ for high availability and automatic failover.",
                    "resource": iid,
                    "region": region,
                })
    except Exception as e:
        findings.append({"severity": "INFO", "category": "RDS", "title": "RDS audit error",
                         "detail": str(e), "resource": "RDS", "region": region})
    return findings


# ─── CloudTrail ──────────────────────────────────────────────────────────────

def audit_cloudtrail(session, region: str) -> list[dict]:
    findings = []
    try:
        ct = session.client("cloudtrail", region_name=region)
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
        if not trails:
            findings.append({
                "severity": "HIGH",
                "category": "CloudTrail",
                "title": f"No CloudTrail trails found in {region}",
                "detail": "Enable CloudTrail to log API activity for auditing and incident response.",
                "resource": region,
                "region": region,
            })
        else:
            for trail in trails:
                status = ct.get_trail_status(Name=trail["TrailARN"])
                if not status.get("IsLogging"):
                    findings.append({
                        "severity": "HIGH",
                        "category": "CloudTrail",
                        "title": f"CloudTrail '{trail['Name']}' logging is disabled",
                        "detail": "Enable logging on this trail to capture API activity.",
                        "resource": trail["Name"],
                        "region": region,
                    })
                if not trail.get("LogFileValidationEnabled"):
                    findings.append({
                        "severity": "MEDIUM",
                        "category": "CloudTrail",
                        "title": f"CloudTrail '{trail['Name']}' log file validation is off",
                        "detail": "Enable log file validation to detect tampering.",
                        "resource": trail["Name"],
                        "region": region,
                    })
    except Exception:
        pass
    return findings
