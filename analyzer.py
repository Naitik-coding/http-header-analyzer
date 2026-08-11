import argparse
import json
import requests

def check_hsts(headers):
    header = "Strict-Transport-Security"
    if header not in headers:
        return {
            "header": header,
            "status": "Missing",
            "severity": "MEDIUM",
            "value": None,
            "message": "HSTS is not enabled.",
            "recommendation": "Enable HSTS with an appropriate max-age value."
        }
    value = headers[header]
    if "max-age=" not in value.lower():
        return {
            "header": header,
            "status": "Invalid",
            "severity": "MEDIUM",
            "value": value,
            "message": "max-age directive is missing.",
            "recommendation": "Add a valid max-age directive to the HSTS header."
        }
    max_age_part = value.lower().split("max-age=")[1].split(";")[0].strip()
    try:
        max_age = int(max_age_part)
    except ValueError:
        return {
            "header": header,
            "status": "Invalid",
            "severity": "MEDIUM",
            "value": value,
            "message": "max-age is not a valid number.",
            "recommendation": "Set max-age to a valid positive integer."
        }
    if max_age <= 0:
        return {
            "header": header,
            "status": "Weak",
            "severity": "MEDIUM",
            "value": value,
            "message": "HSTS max-age is zero or negative.",
            "recommendation": "Set max-age to a positive value."
        }
    return {
        "header": header,
        "status": "Secure",
        "severity": "INFO",
        "value": value,
        "message": "HSTS is enabled.",
        "recommendation": "No action required."
    }

def check_csp(headers):
    header = "Content-Security-Policy"
    if header in headers:
        value = headers[header]
        status = "Enforced"
        severity = "INFO"
    elif "Content-Security-Policy-Report-Only" in headers:
        value = headers["Content-Security-Policy-Report-Only"]
        status = "Report-Only"
        severity = "LOW"
    else:
        return {
            "header": header,
            "status": "Missing",
            "severity": "MEDIUM",
            "value": None,
            "message": "No Content-Security-Policy was detected.",
            "recommendation": "Define and enforce a Content-Security-Policy appropriate for the application.",
            "directives": []
        }
    directives = {}
    for directive in value.split(";"):
        directive = directive.strip()
        if not directive:
            continue
        parts = directive.split()
        name = parts[0].lower()
        sources = parts[1:]
        directives[name] = sources
    
    findings = []
    if "object-src" in directives:
        if "'none'" in directives["object-src"]:
            findings.append({
                "type": "GOOD",
                "message": "object-src is restricted to 'none'."
            })
        else:
            findings.append({
                "type": "WARNING",
                "message": "object-src is not restricted to 'none'."
            })
    else:
        findings.append({
            "type": "WARNING",
            "message": "object-src directive is missing."
        })
    if "base-uri" in directives:
        if "'none'" in directives["base-uri"] or "'self'" in directives["base-uri"]:
            findings.append({
                "type": "GOOD",
                "message": "base-uri is restricted."
            })
        else:
            findings.append({
                "type": "WARNING",
                "message": "base-uri allows broader sources."
            })
    else:
        findings.append({
            "type": "WARNING",
            "message": "base-uri directive is missing."
        })
    if "script-src" in directives:
        script_sources = directives["script-src"]
        if "'unsafe-inline'" in script_sources:
            findings.append({
                "type": "WARNING",
                "message": "script-src contains 'unsafe-inline'."
            })
        if "'unsafe-eval'" in script_sources:
            findings.append({
                "type": "WARNING",
                "message": "script-src contains 'unsafe-eval'."
            })
        if "*" in script_sources:
            findings.append({
                "type": "WARNING",
                "message": "script-src allows all sources."
            })
    else:
        findings.append({
            "type": "WARNING",
            "message": "script-src directive is missing."
        })
    return {
            "header": header,
            "status": status,
            "severity": severity,
            "value": value,
            "message": "CSP policy was detected.",
            "recommendation": (
                "Review the CSP directives and ensure they follow the application's "
                "security requirements."
            ),
            "directives": directives,
            "findings": findings
        }    

def check_x_frame_options(headers):
    header = "X-Frame-Options"
    if header not in headers:
        return {
            "header": header,
            "status": "Missing",
            "severity": "MEDIUM",
            "value": None,
            "message": "Clickjacking protection is not enabled.",
            "recommendation": "Add X-Frame-Options or use CSP frame-ancestors to control framing."
        }
    value = headers[header].strip().upper()
    if value == "DENY":
        return {
            "header": header,
            "status": "Secure",
            "severity": "INFO",
            "value": value,
            "message": "Framing is completely disabled.",
            "recommendation": "No action required."
        }
    elif value == "SAMEORIGIN":
        return {
            "header": header,
            "status": "Secure",
            "severity": "INFO",
            "value": value,
            "message": "Framing is allowed only from the same origin.",
            "recommendation": "No action required."
        }
    else:
        return {
            "header": header,
            "status": "Invalid",
            "severity": "MEDIUM",
            "value": value,
            "message": "Unrecognized X-Frame-Options value.",
            "recommendation": "Use DENY or SAMEORIGIN, or configure CSP frame-ancestors."
        }

def check_content_type_options(headers):
    header = "X-Content-Type-Options"
    if header not in headers:
        return {
            "header": header,
            "status": "Missing",
            "severity": "LOW",
            "value": None,
            "message": "MIME sniffing protection is not enabled.",
            "recommendation": "Set X-Content-Type-Options to nosniff."
        }
    value = headers[header].strip().lower()
    if value == "nosniff":
        return {
            "header": header,
            "status": "Secure",
            "severity": "INFO",
            "value": value,
            "message": "MIME sniffing protection is enabled.",
            "recommendation": "No action required."
        }
    return {
        "header": header,
        "status": "Invalid",
        "severity": "LOW",
        "value": value,
        "message": "Unexpected X-Content-Type-Options value.",
        "recommendation": "Set X-Content-Type-Options to nosniff."
    }

def check_referrer_policy(headers):
    header = "Referrer-Policy"
    if header not in headers:
        return {
            "header": header,
            "status": "Missing",
            "severity": "LOW",
            "value": None,
            "message": "No Referrer-Policy was detected.",
            "recommendation": "Configure an appropriate Referrer-Policy, such as strict-origin-when-cross-origin."
        }
    value = headers[header].strip().lower()
    valid_policies = [
        "no-referrer",
        "no-referrer-when-downgrade",
        "origin",
        "origin-when-cross-origin",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
        "unsafe-url"
    ]
    if value in valid_policies:
        return {
            "header": header,
            "status": "Valid",
            "severity": "INFO",
            "value": value,
            "message": "A valid Referrer-Policy is configured.",
            "recommendation": "No action required."
        }
    return {
        "header": header,
        "status": "Invalid",
        "severity": "LOW",
        "value": value,
        "message": "Unrecognized Referrer-Policy value.",
        "recommendation": "Use a recognized Referrer-Policy value."
    }

def check_permissions_policy(headers):
    header = "Permissions-Policy"
    if header not in headers:
        return {
            "header": header,
            "status": "Missing",
            "severity": "LOW",
            "value": None,
            "message": "No Permissions-Policy was detected.",
            "recommendation": "Define a Permissions-Policy that restricts unnecessary browser features."
        }
    value = headers[header].strip()
    if not value:
        return {
            "header": header,
            "status": "Invalid",
            "severity": "LOW",
            "value": value,
            "message": "Permissions-Policy is empty.",
            "recommendation": "Review the policy and ensure unnecessary browser features are restricted."
        }
    return {
        "header": header,
        "status": "Present",
        "severity": "INFO",
        "value": value,
        "message": "Permissions-Policy is configured.",
        "recommendation": "Review the policy and ensure unnecessary browser features are restricted."
    }

def check_cookies(response):
    cookies = response.cookies
    if not cookies:
        return {
            "status": "No Cookies",
            "severity": "INFO",
            "message": "No cookies were found.",
            "cookies": []
        }

    cookie_results = []
    for cookie in cookies:
        rest = {
            key.lower(): value
            for key, value in cookie._rest.items()
        }
        samesite = cookie.get_nonstandard_attr("SameSite")
        cookie_results.append({
            "name": cookie.name,
            "secure": cookie.secure,
            "httponly": "httponly" in rest,
            "samesite": samesite
        })
    return {
        "status": "Analyzed",
        "severity": "INFO",
        "message": f"Analyzed {len(cookie_results)} cookie(s).",
        "cookies": cookie_results
    }

def calculate_score(results):
    weights = {
        "Strict-Transport-Security": 2,
        "Content-Security-Policy": 3,
        "X-Frame-Options": 2,
        "X-Content-Type-Options": 1,
        "Referrer-Policy": 1,
        "Permissions-Policy": 1
    }
    earned_points = 0
    maximum_points = sum(weights.values())
    for result in results:
        header = result["header"]
        weight = weights.get(header, 0)
        status = result["status"]
        if status in ["Secure", "Enforced", "Valid"]:
            points = weight
        elif status == "Report-Only":
            points = weight * 0.5
        else:
            points = 0
        # CSP-specific adjustments
        if header == "Content-Security-Policy":
            findings = result.get("findings", [])
            warning_count = sum(
                1 for finding in findings
                if finding["type"] == "WARNING"
            )
            # Reduce CSP points slightly for each warning.
            points -= warning_count * 0.25
            # Never allow the CSP component to become negative.
            points = max(points, 0)
        earned_points += points
    score = (earned_points / maximum_points) * 100
    return round(score, 2)

def get_score_rating(score):
    if score >= 90:
        return "Excellent"
    elif score >= 75:
        return "Good"
    elif score >= 50:
        return "Needs Improvement"
    else:
        return "Poor"

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="HTTP Header Security Analyzer"
    )
    parser.add_argument(
        "--url",
        required=True,
        help="Target URL to analyze"
    )
    parser.add_argument(
        "--json",
        help="Save analysis results to a JSON file"
    )
    return parser.parse_args()    

def print_report(url, response, results, cookie_result, score, rating):
    print("\n" + "=" * 55)
    print("              HTTP HEADER ANALYZER")
    print("=" * 55)
    print(f"\nTarget      : {url}")
    print(f"Final URL   : {response.url}")
    print(f"Status Code : {response.status_code}")
    print(f"HTTPS       : {'YES' if response.url.startswith('https://') else 'NO'}")
    print(f"Redirects   : {len(response.history)}")
    print("\n" + "-" * 55)
    print("                 SECURITY SCORE")
    print("-" * 55)
    print(f"Score       : {score}/100")
    print(f"Rating      : {rating}")
    print("\n" + "-" * 55)
    print("               SECURITY HEADERS")
    print("-" * 55)
    for result in results:
        print(f"\n[{result['severity']}] {result['header']}")
        print(f"Status         : {result['status']}")
        print(f"Message        : {result['message']}")
        if result["value"] is not None:
            print(f"Value          : {result['value']}")
        print(f"Recommendation : {result['recommendation']}")
        if result["header"] == "Content-Security-Policy":
            if result.get("directives"):
                print("CSP Directives:")
                for directive, sources in result["directives"].items():
                    if sources:
                        print(
                            f"    {directive}: "
                            f"{' '.join(sources)}"
                        )
                    else:
                        print(f"    {directive}")
            if result.get("findings"):
                print("CSP Findings:")
                for finding in result["findings"]:
                    print(
                        f"    [{finding['type']}] "
                        f"{finding['message']}"
                    )
    print("\n" + "-" * 55)
    print("                 COOKIE SECURITY")
    print("-" * 55)
    print(f"Status  : {cookie_result['status']}")
    print(f"Message : {cookie_result['message']}")
    for cookie in cookie_result["cookies"]:
        print(f"\nCookie: {cookie['name']}")
        print(
            f"    Secure   : "
            f"{'YES' if cookie['secure'] else 'NO'}"
        )
        print(
            f"    HttpOnly : "
            f"{'YES' if cookie['httponly'] else 'NO'}"
        )
        samesite = cookie["samesite"]
        if samesite:
            print(f"    SameSite : {samesite}")
        else:
            print("    SameSite : MISSING")
    print("\n" + "=" * 55)

def main():
    args = parse_arguments()
    url = args.url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True
        )
    except requests.exceptions.Timeout:
        print("Error: Request timed out.")
        return
    except requests.exceptions.ConnectionError:
        print("Error: Could not connect to the target.")
        return
    except requests.exceptions.RequestException as error:
        print(f"Error: Request failed - {error}")
        return
    results = [
        check_hsts(response.headers),
        check_csp(response.headers),
        check_x_frame_options(response.headers),
        check_content_type_options(response.headers),
        check_referrer_policy(response.headers),
        check_permissions_policy(response.headers)
    ]
    cookie_result = check_cookies(response)
    score = calculate_score(results)
    rating = get_score_rating(score)
    if args.json:
        report = {
            "target": url,
            "final_url": response.url,
            "status_code": response.status_code,
            "https": response.url.startswith("https://"),
            "redirects": len(response.history),
            "security_score": score,
            "rating": rating,
            "security_headers": results,
            "cookies": cookie_result
    }
        with open(args.json, "w", encoding="utf-8") as file:
            json.dump(report, file, indent=4)
        print(f"\nJSON report saved to: {args.json}")

    print_report(
        url,
        response,
        results,
        cookie_result,
        score,
        rating
    )

if __name__ == "__main__":
    main()