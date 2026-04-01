import boto3

def get_session(access_key: str = None, secret_key: str = None, region: str = "us-east-1"):
    """
    Build a boto3 session.
    If access_key and secret_key are provided, use them directly.
    Otherwise fall back to ~/.aws/credentials or environment variables.
    """
    if access_key and secret_key:
        return boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region
        )
    return boto3.Session(region_name=region)


def get_all_regions(session: boto3.Session) -> list[str]:
    """Return all available AWS regions."""
    ec2 = session.client("ec2", region_name="us-east-1")
    response = ec2.describe_regions(AllRegions=False)
    return [r["RegionName"] for r in response["Regions"]]
