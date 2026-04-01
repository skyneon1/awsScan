def scan_iam(session) -> list[dict]:
    """Return all IAM users (IAM is global, not per-region)."""
    try:
        client = session.client("iam")
        response = client.list_users()
        users = []
        for user in response.get("Users", []):
            # Check if user has logged in recently
            last_used = user.get("PasswordLastUsed", None)
            active = last_used is not None
            users.append({
                "id": user["UserId"],
                "name": user["UserName"],
                "type": "IAM User",
                "state": "active" if active else "never logged in",
                "active": active,
                "region": "global",
                "launched": str(user.get("CreateDate", "N/A")),
                "service": "IAM"
            })
        return users
    except Exception as e:
        return [{"error": str(e), "region": "global", "service": "IAM"}]
