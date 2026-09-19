import zipfile
from pathlib import Path


def analyze_apk(apk_path):
    """
    Safely performs basic static analysis of an APK.
    The APK is not installed or executed.
    """

    apk_path = Path(apk_path)

    if not apk_path.exists():
        return {
            "status": "error",
            "message": "APK file not found."
        }

    if apk_path.suffix.lower() != ".apk":
        return {
            "status": "error",
            "message": "Please provide a valid APK file."
        }

    score = 0
    reasons = []
    permissions = []

    try:
        with zipfile.ZipFile(apk_path, "r") as apk:

            files = apk.namelist()

            # 1. Basic APK structure
            if "AndroidManifest.xml" not in files:
                score += 30
                reasons.append(
                    "AndroidManifest.xml is missing."
                )

            # 2. Check common sensitive permission strings
            manifest_data = b""

            if "AndroidManifest.xml" in files:
                manifest_data = apk.read("AndroidManifest.xml")

            sensitive_permissions = {
                b"CAMERA": "Camera permission detected.",
                b"RECORD_AUDIO": "Microphone permission detected.",
                b"READ_SMS": "SMS reading permission detected.",
                b"SEND_SMS": "SMS sending permission detected.",
                b"READ_CONTACTS": "Contacts reading permission detected.",
                b"ACCESS_FINE_LOCATION": "Precise location permission detected.",
                b"READ_PHONE_STATE": "Phone state permission detected.",
                b"REQUEST_INSTALL_PACKAGES": "Package installation permission detected."
            }

            for permission, reason in sensitive_permissions.items():
                if permission in manifest_data:
                    permissions.append(permission.decode())
                    reasons.append(reason)
                    score += 5

            # 3. Check for native libraries
            native_files = [
                name for name in files
                if name.startswith("lib/") and name.endswith(".so")
            ]

            if native_files:
                reasons.append(
                    "APK contains native library files."
                )

            # 4. Check for executable/script-like files
            suspicious_extensions = (
                ".sh",
                ".dex",
                ".so"
            )

            suspicious_files = [
                name for name in files
                if name.lower().endswith(suspicious_extensions)
            ]

            if len(suspicious_files) > 20:
                score += 10
                reasons.append(
                    "APK contains a large number of executable/native files."
                )

            # 5. Check APK size
            file_size_mb = apk_path.stat().st_size / (1024 * 1024)

            if file_size_mb > 100:
                reasons.append(
                    "APK file size is unusually large."
                )

            score = min(score, 100)

            if score >= 60:
                risk_level = "High"
            elif score >= 30:
                risk_level = "Medium"
            else:
                risk_level = "Low"

            return {
                "status": "success",
                "file_name": apk_path.name,
                "file_size_mb": round(file_size_mb, 2),
                "risk_score": score,
                "risk_level": risk_level,
                "permissions": permissions,
                "reasons": reasons
            }

    except zipfile.BadZipFile:
        return {
            "status": "error",
            "message": "The APK file is invalid or corrupted."
        }

    except Exception as error:
        return {
            "status": "error",
            "message": str(error)
        }


if __name__ == "__main__":

    print("APK Analyzer")
    print("------------")

    apk_file = input("Enter APK file path: ").strip()

    result = analyze_apk(apk_file)

    print("\nAnalysis Result")
    print("----------------")

    for key, value in result.items():
        print(f"{key}: {value}")