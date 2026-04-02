def scan_iam(session) -> list[dict]:
    """Return all IAM users (IAM is global, not per-region)."""
    try:
        client = session.client("iam")
        response = client.list_users()
        users = []
        for user in response.get("Users", []):
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


def scan_iam_detailed(session) -> list[dict]:
    """Return detailed IAM user data: groups, policies, MFA devices, access keys."""
    iam = session.client("iam")
    users = []
    try:
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                uname = user["UserName"]
                uid   = user["UserId"]
                arn   = user["Arn"]
                created = str(user.get("CreateDate", "N/A"))
                last_login = str(user.get("PasswordLastUsed", "Never"))

                # Groups
                try:
                    grp_resp = iam.list_groups_for_user(UserName=uname)
                    groups = [g["GroupName"] for g in grp_resp.get("Groups", [])]
                except Exception:
                    groups = []

                # Attached policies (user-level)
                try:
                    pol_resp = iam.list_attached_user_policies(UserName=uname)
                    policies = [p["PolicyName"] for p in pol_resp.get("AttachedPolicies", [])]
                except Exception:
                    policies = []

                # Inline policies
                try:
                    inline_resp = iam.list_user_policies(UserName=uname)
                    inline_policies = inline_resp.get("PolicyNames", [])
                except Exception:
                    inline_policies = []

                # MFA devices
                try:
                    mfa_resp = iam.list_mfa_devices(UserName=uname)
                    mfa_devices = [m["SerialNumber"] for m in mfa_resp.get("MFADevices", [])]
                    mfa_enabled = len(mfa_devices) > 0
                except Exception:
                    mfa_devices = []
                    mfa_enabled = False

                # Access keys
                try:
                    key_resp = iam.list_access_keys(UserName=uname)
                    access_keys = []
                    for k in key_resp.get("AccessKeyMetadata", []):
                        # Last used
                        try:
                            lu = iam.get_access_key_last_used(AccessKeyId=k["AccessKeyId"])
                            last_used_info = lu.get("AccessKeyLastUsed", {})
                            key_last_used = str(last_used_info.get("LastUsedDate", "Never"))
                            key_last_service = last_used_info.get("ServiceName", "—")
                            key_last_region = last_used_info.get("Region", "—")
                        except Exception:
                            key_last_used = "Unknown"
                            key_last_service = "—"
                            key_last_region = "—"

                        from datetime import datetime, timezone
                        created_at = k.get("CreateDate")
                        if created_at:
                            if created_at.tzinfo is None:
                                created_at = created_at.replace(tzinfo=timezone.utc)
                            age_days = (datetime.now(timezone.utc) - created_at).days
                        else:
                            age_days = None

                        access_keys.append({
                            "key_id": k["AccessKeyId"],
                            "status": k["Status"],
                            "created": str(k.get("CreateDate", "N/A")),
                            "age_days": age_days,
                            "last_used": key_last_used,
                            "last_service": key_last_service,
                            "last_region": key_last_region,
                        })
                except Exception:
                    access_keys = []

                # Console access (login profile)
                try:
                    iam.get_login_profile(UserName=uname)
                    console_access = True
                except iam.exceptions.NoSuchEntityException:
                    console_access = False
                except Exception:
                    console_access = None

                # Admin check: has AdministratorAccess?
                is_admin = "AdministratorAccess" in policies

                users.append({
                    "user_id": uid,
                    "username": uname,
                    "arn": arn,
                    "created": created,
                    "last_login": last_login,
                    "console_access": console_access,
                    "mfa_enabled": mfa_enabled,
                    "mfa_devices": mfa_devices,
                    "groups": groups,
                    "policies": policies,
                    "inline_policies": inline_policies,
                    "access_keys": access_keys,
                    "is_admin": is_admin,
                    "active": user.get("PasswordLastUsed") is not None,
                })
    except Exception as e:
        users.append({"error": str(e), "username": "error"})
    return users
