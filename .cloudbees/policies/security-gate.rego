package cloudbees.policy

default allow = false

# Allow deployment ONLY if there are zero critical scanner alerts
allow {
    count(critical_vulnerabilities) == 0
}

critical_vulnerabilities[vuln] {
    vuln := input.security.vulnerabilities[_]
    vuln.severity == "CRITICAL"
}