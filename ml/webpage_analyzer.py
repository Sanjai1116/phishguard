from urllib.parse import urlparse
import re


def analyze_webpage(url, html):
    """
    PhishGuard webpage security analyzer.

    Checks:
    - HTTPS
    - suspicious domain patterns
    - look-alike/spoof indicators
    - password and sensitive forms
    - urgent language
    - external form destinations
    - suspicious page branding/content
    """

    score = 0
    reasons = []

    parsed = urlparse(url)
    domain = parsed.hostname or ""
    domain = domain.lower()

    html_lower = html.lower()

    # =========================
    # 1. HTTPS CHECK
    # =========================

    if parsed.scheme != "https":
        score += 15
        reasons.append("Website does not use HTTPS.")

    # =========================
    # 2. SUSPICIOUS DOMAIN KEYWORDS
    # =========================

    suspicious_words = [
        "login",
        "verify",
        "secure",
        "account",
        "update",
        "payment",
        "confirm",
        "verification"
    ]

    found_words = [
        word for word in suspicious_words
        if word in domain
    ]

    if found_words:
        score += 15
        reasons.append(
            "Domain contains security-sensitive keywords."
        )

    # =========================
    # 3. IP-BASED DOMAIN
    # =========================

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        score += 25
        reasons.append(
            "Website uses an IP address instead of a normal domain."
        )

    # =========================
    # 4. LOOK-ALIKE DOMAIN INDICATORS
    # =========================

    lookalike_patterns = [
        "govt",
        "government",
        "official",
        "support",
        "service",
        "portal",
        "secure-login"
    ]

    found_lookalike = [
        word for word in lookalike_patterns
        if word in domain
    ]

    if found_lookalike:
        score += 15
        reasons.append(
            "Domain contains terms commonly used to imitate official services."
        )

    # =========================
    # 5. MANY SUBDOMAINS
    # =========================

    domain_parts = domain.split(".")

    if len(domain_parts) > 3:
        score += 15
        reasons.append(
            "Website uses multiple domain levels."
        )

    # =========================
    # 6. PASSWORD INPUT
    # =========================

    password_fields = len(
        re.findall(
            r'type\s*=\s*["\']password["\']',
            html_lower
        )
    )

    if password_fields > 0:
        score += 15
        reasons.append(
            "Page contains a password input field."
        )

    # =========================
    # 7. SENSITIVE INFORMATION
    # =========================

    sensitive_words = [
        "password",
        "otp",
        "one time password",
        "credit card",
        "debit card",
        "cvv",
        "bank account"
    ]

    found_sensitive = [
        word for word in sensitive_words
        if word in html_lower
    ]

    if found_sensitive:
        score += 15
        reasons.append(
            "Page requests sensitive or financial information."
        )

    # =========================
    # 8. URGENT LANGUAGE
    # =========================

    urgent_words = [
        "urgent",
        "immediately",
        "account suspended",
        "verify now",
        "act now",
        "limited time",
        "your account will be blocked"
    ]

    found_urgent = [
        word for word in urgent_words
        if word in html_lower
    ]

    if found_urgent:
        score += 20
        reasons.append(
            "Page contains urgent or pressure-based language."
        )

    # =========================
    # 9. FORM SUBMISSION
    # =========================

    form_actions = re.findall(
        r'<form[^>]+action\s*=\s*["\']([^"\']+)',
        html_lower
    )

    if form_actions:
        score += 10
        reasons.append(
            "Page contains a form submission destination."
        )

    # =========================
    # 10. LOOK-ALIKE / SPOOF DETECTION
    # =========================

    trusted_brands = {
        "google": ["google.com"],
        "microsoft": ["microsoft.com"],
        "wikipedia": ["wikipedia.org"],
        "github": ["github.com"],
        "amazon": ["amazon.com"]
    }

    page_title_match = re.search(
        r"<title[^>]*>(.*?)</title>",
        html_lower,
        re.IGNORECASE | re.DOTALL
    )

    page_title = (
        page_title_match.group(1).strip()
        if page_title_match
        else ""
    )

    page_brand = None

    for brand, trusted_domains in trusted_brands.items():

        if brand in page_title:

            page_brand = brand

            if not any(
                domain == trusted_domain
                or domain.endswith("." + trusted_domain)
                for trusted_domain in trusted_domains
            ):
                score += 30
                reasons.append(
                    f"Page title references {brand.title()}, "
                    "but the website uses a different domain."
                )

            break


    # =========================
    # 11. BRAND / OFFICIAL CLAIMS
    # =========================

    official_claims = [
        "official website",
        "government portal",
        "official portal",
        "ministry",
        "government of india"
    ]

    found_claims = [
        word for word in official_claims
        if word in html_lower
    ]

    if found_claims:
        score += 15
        reasons.append(
            "Page makes official or government-related claims."
        )

    # =========================
    # FINAL SCORE
    # =========================

    score = min(score, 100)

    if score >= 60:
        risk = "High"
    elif score >= 30:
        risk = "Medium"
    else:
        risk = "Low"

    return {
        "url": url,
        "domain": domain,
        "risk_score": score,
        "risk_level": risk,
        "reasons": reasons
    }


# =========================
# SIMPLE TEST
# =========================

if __name__ == "__main__":

    test_url = "https://example.com/login"

    test_html = """
    <html>
        <body>

            <h1>Official Government Portal</h1>

            <p>Urgent! Verify Now.</p>

            <form action="https://example.com/submit">
                <input type="password">
                <input type="text" placeholder="OTP">
            </form>

        </body>
    </html>
    """

    result = analyze_webpage(
        test_url,
        test_html
    )

    print("Webpage Analysis Result")
    print("-----------------------")

    print(
        f"Risk Score : {result['risk_score']}/100"
    )

    print(
        f"Risk Level : {result['risk_level']}"
    )

    print("Reasons:")

    for reason in result["reasons"]:
        print("-", reason)