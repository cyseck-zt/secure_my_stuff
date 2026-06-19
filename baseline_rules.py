def as_bool(value):
    """Convert common CSV values into a boolean."""
    return str(value).strip().lower() in ["true", "yes", "1", "enabled", "on", "protected"]


def as_int(value, default=0):
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


BASELINE_RULES = [
    {
        "field": "TPM",
        "finding": "TPM Missing or Disabled",
        "weight": 20,
        "severity": "High",
        "recommendation": "Enable TPM in firmware/UEFI or plan hardware replacement for devices without TPM support.",
    },
    {
        "field": "SecureBoot",
        "finding": "Secure Boot Disabled",
        "weight": 15,
        "severity": "High",
        "recommendation": "Enable Secure Boot after confirming the device is using UEFI boot mode.",
    },
    {
        "field": "BitLocker",
        "finding": "BitLocker Disabled",
        "weight": 20,
        "severity": "High",
        "recommendation": "Enable BitLocker and confirm recovery keys are escrowed before broad rollout.",
    },
    {
        "field": "Defender",
        "finding": "Microsoft Defender Disabled",
        "weight": 15,
        "severity": "High",
        "recommendation": "Enable Defender or verify an approved endpoint protection platform is active.",
    },
    {
        "field": "Firewall",
        "finding": "Firewall Disabled",
        "weight": 10,
        "severity": "Medium",
        "recommendation": "Enable Windows Firewall for domain, private, and public profiles unless a documented exception exists.",
    },
]


def check_os_risk(os_version):
    value = str(os_version or "").strip().lower()
    if "windows 11" in value:
        return None
    if "windows 10" in value:
        return {
            "finding": "Windows 10 Device",
            "weight": 5,
            "severity": "Low",
            "recommendation": "Track this device for lifecycle planning and Windows 11 readiness.",
        }
    if "windows 7" in value or "windows 8" in value:
        return {
            "finding": "Unsupported Legacy OS",
            "weight": 25,
            "severity": "Critical",
            "recommendation": "Prioritize replacement, isolation, or upgrade. Legacy operating systems are a major security risk.",
        }
    return {
        "finding": "Unknown OS Version",
        "weight": 5,
        "severity": "Low",
        "recommendation": "Verify OS inventory data and confirm device lifecycle status.",
    }


def check_local_admin_risk(local_admin_count):
    count = as_int(local_admin_count)
    if count >= 6:
        return {
            "finding": "Excessive Local Administrators",
            "weight": 15,
            "severity": "High",
            "recommendation": "Review local administrators, remove unnecessary accounts, and consider LAPS or privileged access controls.",
        }
    if count >= 3:
        return {
            "finding": "Elevated Local Administrator Count",
            "weight": 8,
            "severity": "Medium",
            "recommendation": "Review local administrator membership and remove unnecessary privileged users.",
        }
    return None


def calculate_risk_level(score):
    if score >= 90:
        return "Low"
    if score >= 75:
        return "Medium"
    if score >= 50:
        return "High"
    return "Critical"


def analyze_device(device):
    score = 100
    findings = []
    recommendations = []
    severities = []

    for rule in BASELINE_RULES:
        if not as_bool(device.get(rule["field"], False)):
            score -= rule["weight"]
            findings.append(rule["finding"])
            recommendations.append(rule["recommendation"])
            severities.append(rule["severity"])

    os_risk = check_os_risk(device.get("OSVersion", ""))
    if os_risk:
        score -= os_risk["weight"]
        findings.append(os_risk["finding"])
        recommendations.append(os_risk["recommendation"])
        severities.append(os_risk["severity"])

    admin_risk = check_local_admin_risk(device.get("LocalAdminCount", 0))
    if admin_risk:
        score -= admin_risk["weight"]
        findings.append(admin_risk["finding"])
        recommendations.append(admin_risk["recommendation"])
        severities.append(admin_risk["severity"])

    score = max(score, 0)

    return {
        "ComputerName": device.get("ComputerName", "Unknown"),
        "SecurityScore": score,
        "RiskLevel": calculate_risk_level(score),
        "Findings": findings,
        "Recommendations": recommendations,
        "HighestSeverity": max(severities, key=["Low", "Medium", "High", "Critical"].index) if severities else "None",
    }


def analyze_dataframe(df):
    return [analyze_device(row) for _, row in df.iterrows()]
