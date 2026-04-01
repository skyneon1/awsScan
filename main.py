from fastapi import FastAPI, Request, Form, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from concurrent.futures import ThreadPoolExecutor, as_completed
import configparser

from scanner.base import get_session, get_all_regions
from scanner.ec2 import scan_ec2
from scanner.lambda_fn import scan_lambda
from scanner.iam import scan_iam
from scanner.s3 import scan_s3
from scanner.rds import scan_rds

app = FastAPI(title="awsScan")
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    # Use keyword argument form — compatible with Starlette 0.28+
    return templates.TemplateResponse(request=request, name="index.html")


@app.post("/scan")
async def scan(
    access_key: str = Form(default=""),
    secret_key: str = Form(default=""),
    creds_file: UploadFile = File(default=None),
):
    ak, sk = access_key.strip(), secret_key.strip()

    if creds_file and creds_file.filename:
        content = await creds_file.read()
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

    def scan_region(region):
        regional = []
        regional.extend(scan_ec2(session, region))
        regional.extend(scan_lambda(session, region))
        regional.extend(scan_rds(session, region))
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
        "by_service": {}
    }
    for r in resources:
        svc = r["service"]
        if svc not in summary["by_service"]:
            summary["by_service"][svc] = {"active": 0, "inactive": 0}
        if r.get("active"):
            summary["by_service"][svc]["active"] += 1
        else:
            summary["by_service"][svc]["inactive"] += 1

    return JSONResponse({
        "resources": resources,
        "summary":   summary,
        "errors":    errors
    })
