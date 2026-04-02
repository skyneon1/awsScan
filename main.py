from fastapi import FastAPI, Request, Form, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from concurrent.futures import ThreadPoolExecutor, as_completed
import configparser

from scanner.base import get_session, get_all_regions
from scanner.ec2 import scan_ec2
from scanner.lambda_fn import scan_lambda
from scanner.iam import scan_iam, scan_iam_detailed
from scanner.s3 import scan_s3
from scanner.rds import scan_rds
from scanner.vpc import scan_vpc
from scanner.dynamodb import scan_dynamodb
from scanner.cloudfront import scan_cloudfront
from scanner.security import audit_iam, audit_s3, audit_ec2, audit_rds, audit_cloudtrail
from scanner.cost import scan_costs
from scanner.tagging import scan_tag_compliance

app = FastAPI(title="awsScan")
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")


@app.post("/scan")
def scan(
    access_key: str = Form(default=""),
    secret_key: str = Form(default=""),
    creds_file: UploadFile = File(default=None),
):
    ak, sk = access_key.strip(), secret_key.strip()

    if creds_file and creds_file.filename:
        content = creds_file.file.read()
        config = configparser.ConfigParser()
        config.read_string(content.decode("utf-8"))
        profile = config["default"] if "default" in config else config[list(config.sections())[0]]
        ak = profile.get("aws_access_key_id", "").strip()
        sk = profile.get("aws_secret_access_key", "").strip()

    try:
        session = get_session(ak or None, sk or None)
        regions = get_all_regions(session)
    except Exception as e:
        return JSONResponse({"error": f"Failed to connect to AWS: {str(e)}"}, status_code=400)

    results = []

    results.extend(scan_iam(session))
    results.extend(scan_s3(session))
    results.extend(scan_cloudfront(session))

    def scan_region(region):
        regional = []
        regional.extend(scan_ec2(session, region))
        regional.extend(scan_lambda(session, region))
        regional.extend(scan_rds(session, region))
        regional.extend(scan_vpc(session, region))
        regional.extend(scan_dynamodb(session, region))
        return regional

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(scan_region, r): r for r in regions}
        for future in as_completed(futures):
            try:
                results.extend(future.result())
            except Exception as e:
                results.append({"error": str(e), "region": futures[future], "service": "unknown"})

    resources = [r for r in results if "error" not in r]
    errors    = [r for r in results if "error" in r]

    summary = {
        "total":    len(resources),
        "active":   len([r for r in resources if r.get("active")]),
        "inactive": len([r for r in resources if not r.get("active")]),
        "by_service": {},
        "by_region": {},
    }
    for r in resources:
        svc = r["service"]
        reg = r.get("region", "global")
        if svc not in summary["by_service"]:
            summary["by_service"][svc] = {"active": 0, "inactive": 0}
        if r.get("active"):
            summary["by_service"][svc]["active"] += 1
        else:
            summary["by_service"][svc]["inactive"] += 1
        # Regional breakdown
        if reg not in ("global",):
            summary["by_region"][reg] = summary["by_region"].get(reg, 0) + 1

    return JSONResponse({
        "resources": resources,
        "summary":   summary,
        "errors":    errors,
    })


@app.post("/scan/security")
def scan_security(
    access_key: str = Form(default=""),
    secret_key: str = Form(default=""),
    session_token: str = Form(default=""),
    creds_file: UploadFile = File(default=None),
):
    """Run security audit across all services and regions."""
    ak, sk = access_key.strip(), secret_key.strip()

    if creds_file and creds_file.filename:
        content = creds_file.file.read()
        config = configparser.ConfigParser()
        config.read_string(content.decode("utf-8"))
        profile = config["default"] if "default" in config else config[list(config.sections())[0]]
        ak = profile.get("aws_access_key_id", "").strip()
        sk = profile.get("aws_secret_access_key", "").strip()

    try:
        session = get_session(ak or None, sk or None)
        regions = get_all_regions(session)
    except Exception as e:
        return JSONResponse({"error": f"Failed to connect to AWS: {str(e)}"}, status_code=400)

    findings = []
    findings.extend(audit_iam(session))
    findings.extend(audit_s3(session))

    def audit_region(region):
        regional = []
        regional.extend(audit_ec2(session, region))
        regional.extend(audit_rds(session, region))
        regional.extend(audit_cloudtrail(session, region))
        return regional

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(audit_region, r): r for r in regions}
        for future in as_completed(futures):
            try:
                findings.extend(future.result())
            except Exception:
                pass

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: severity_order.get(f.get("severity", "INFO"), 99))

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1

    return JSONResponse({
        "findings": findings,
        "total": len(findings),
        "counts": counts,
    })


@app.post("/scan/costs")
def scan_costs_endpoint(
    access_key: str = Form(default=""),
    secret_key: str = Form(default=""),
    creds_file: UploadFile = File(default=None),
):
    """Estimate monthly costs for running resources."""
    ak, sk = access_key.strip(), secret_key.strip()

    if creds_file and creds_file.filename:
        content = creds_file.file.read()
        config = configparser.ConfigParser()
        config.read_string(content.decode("utf-8"))
        profile = config["default"] if "default" in config else config[list(config.sections())[0]]
        ak = profile.get("aws_access_key_id", "").strip()
        sk = profile.get("aws_secret_access_key", "").strip()

    try:
        session = get_session(ak or None, sk or None)
    except Exception as e:
        return JSONResponse({"error": f"Failed to connect to AWS: {str(e)}"}, status_code=400)

    try:
        data = scan_costs(session)
        return JSONResponse(data)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/scan/tags")
def scan_tags_endpoint(
    access_key: str = Form(default=""),
    secret_key: str = Form(default=""),
    creds_file: UploadFile = File(default=None),
):
    """Scan resources for tag compliance."""
    ak, sk = access_key.strip(), secret_key.strip()

    if creds_file and creds_file.filename:
        content = creds_file.file.read()
        config = configparser.ConfigParser()
        config.read_string(content.decode("utf-8"))
        profile = config["default"] if "default" in config else config[list(config.sections())[0]]
        ak = profile.get("aws_access_key_id", "").strip()
        sk = profile.get("aws_secret_access_key", "").strip()

    try:
        session = get_session(ak or None, sk or None)
    except Exception as e:
        return JSONResponse({"error": f"Failed to connect to AWS: {str(e)}"}, status_code=400)

    try:
        records = scan_tag_compliance(session)
        compliant = [r for r in records if r["compliant"]]
        non_compliant = [r for r in records if not r["compliant"]]
        return JSONResponse({
            "records": records,
            "total": len(records),
            "compliant": len(compliant),
            "non_compliant": len(non_compliant),
            "compliance_rate": round(len(compliant) / len(records) * 100, 1) if records else 100.0,
        })
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/scan/users")
def scan_users_endpoint(
    access_key: str = Form(default=""),
    secret_key: str = Form(default=""),
    creds_file: UploadFile = File(default=None),
):
    """Return detailed IAM user data."""
    ak, sk = access_key.strip(), secret_key.strip()
    if creds_file and creds_file.filename:
        content = creds_file.file.read()
        config = configparser.ConfigParser()
        config.read_string(content.decode("utf-8"))
        profile = config["default"] if "default" in config else config[list(config.sections())[0]]
        ak = profile.get("aws_access_key_id", "").strip()
        sk = profile.get("aws_secret_access_key", "").strip()
    try:
        session = get_session(ak or None, sk or None)
    except Exception as e:
        return JSONResponse({"error": f"Failed to connect: {str(e)}"}, status_code=400)
    try:
        users = scan_iam_detailed(session)
        return JSONResponse({"users": users, "total": len(users)})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/action")
def perform_action(
    access_key: str = Form(default=""),
    secret_key: str = Form(default=""),
    service: str = Form(...),
    action: str = Form(...),
    resource_id: str = Form(...),
    region: str = Form(default="us-east-1"),
    extra: str = Form(default=""),
):
    """
    Perform a control action on an AWS resource.
    service: ec2 | rds | iam_key
    action:  start | stop | reboot | enable | disable
    resource_id: instance-id / db-id / access-key-id
    extra: for iam_key actions — the username
    """
    ak, sk = access_key.strip(), secret_key.strip()
    try:
        session = get_session(ak or None, sk or None)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=400)

    try:
        if service == "ec2":
            client = session.client("ec2", region_name=region)
            if action == "start":
                client.start_instances(InstanceIds=[resource_id])
            elif action == "stop":
                client.stop_instances(InstanceIds=[resource_id])
            elif action == "reboot":
                client.reboot_instances(InstanceIds=[resource_id])
            elif action == "terminate":
                client.terminate_instances(InstanceIds=[resource_id])
            else:
                return JSONResponse({"error": f"Unknown EC2 action: {action}"}, status_code=400)

        elif service == "rds":
            client = session.client("rds", region_name=region)
            if action == "start":
                client.start_db_instance(DBInstanceIdentifier=resource_id)
            elif action == "stop":
                client.stop_db_instance(DBInstanceIdentifier=resource_id)
            elif action == "delete":
                client.delete_db_instance(DBInstanceIdentifier=resource_id, SkipFinalSnapshot=True)
            else:
                return JSONResponse({"error": f"Unknown RDS action: {action}"}, status_code=400)

        elif service == "cloudfront":
            client = session.client("cloudfront")
            dist = client.get_distribution_config(Id=resource_id)
            config = dist['DistributionConfig']
            etag = dist['ETag']
            if action == "start":
                config['Enabled'] = True
            elif action == "stop":
                config['Enabled'] = False
            else:
                return JSONResponse({"error": f"Unknown CloudFront action: {action}"}, status_code=400)
            client.update_distribution(Id=resource_id, IfMatch=etag, DistributionConfig=config)

        elif service == "dynamodb":
            client = session.client("dynamodb", region_name=region)
            if action == "delete":
                client.delete_table(TableName=resource_id)
            else:
                return JSONResponse({"error": f"Unknown DynamoDB action: {action}"}, status_code=400)

        elif service == "iam_key":
            client = session.client("iam")
            username = extra  # extra holds the IAM username
            if not username:
                return JSONResponse({"error": "username required for IAM key action"}, status_code=400)
            status_map = {"enable": "Active", "disable": "Inactive"}
            if action not in status_map:
                return JSONResponse({"error": f"Unknown IAM key action: {action}"}, status_code=400)
            client.update_access_key(
                UserName=username,
                AccessKeyId=resource_id,
                Status=status_map[action],
            )

        else:
            return JSONResponse({"error": f"Unknown service: {service}"}, status_code=400)

        return JSONResponse({"ok": True, "service": service, "action": action, "resource_id": resource_id})

    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

@app.post("/status")
def get_resource_status(
    access_key: str = Form(default=""),
    secret_key: str = Form(default=""),
    service: str = Form(...),
    resource_id: str = Form(...),
    region: str = Form(default="us-east-1"),
    creds_file: UploadFile = File(default=None),
):
    ak, sk = access_key.strip(), secret_key.strip()
    if creds_file and creds_file.filename:
        content = creds_file.file.read()
        config = configparser.ConfigParser()
        config.read_string(content.decode("utf-8"))
        profile = config["default"] if "default" in config else config[list(config.sections())[0]]
        ak = profile.get("aws_access_key_id", "").strip()
        sk = profile.get("aws_secret_access_key", "").strip()
        
    try:
        session = get_session(ak or None, sk or None)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=400)

    try:
        if service == "ec2":
            client = session.client("ec2", region_name=region)
            res = client.describe_instances(InstanceIds=[resource_id])
            state = res["Reservations"][0]["Instances"][0]["State"]["Name"]
            return JSONResponse({"state": state, "active": state == "running"})
        elif service == "rds":
            client = session.client("rds", region_name=region)
            res = client.describe_db_instances(DBInstanceIdentifier=resource_id)
            state = res["DBInstances"][0]["DBInstanceStatus"]
            return JSONResponse({"state": state, "active": state == "available"})
        elif service == "cloudfront":
            client = session.client("cloudfront")
            res = client.get_distribution(Id=resource_id)
            state = res["Distribution"]["Status"]
            enabled = res["Distribution"]["DistributionConfig"]["Enabled"]
            active = (state == "Deployed") and enabled
            return JSONResponse({"state": state, "active": active})
        elif service == "dynamodb":
            client = session.client("dynamodb", region_name=region)
            res = client.describe_table(TableName=resource_id)
            state = res["Table"]["TableStatus"].lower()
            return JSONResponse({"state": state, "active": state == "active"})
        else:
            return JSONResponse({"error": f"Polling unsupported for {service}"}, status_code=400)
    except Exception as e:
        error_msg = str(e)
        if "NotFound" in error_msg:
            return JSONResponse({"state": "terminated" if service=="ec2" else "deleted", "active": False})
        return JSONResponse({"error": error_msg}, status_code=500)
