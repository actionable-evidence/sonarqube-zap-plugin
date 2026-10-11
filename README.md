[![Quality gate status](https://sonarcloud.io/api/project_badges/measure?project=actionable-evidence_sonarqube-zap-plugin&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=actionable-evidence_sonarqube-zap-plugin)

# SonarQube OWASP ZAP Plugin

<img width="1674" height="958" alt="zap html" src="https://github.com/user-attachments/assets/a66010e8-3942-490d-b6b3-7fa5a0e86047" />

Imports [OWASP ZAP](https://www.zaproxy.org/) scan results into SonarQube as **external issues** and shows the ZAP
HTML report on an **OWASP ZAP** project page.

- Targets SonarQube Server 2026.1 LTA / Community Build 26.1 (`sonar-plugin-api` 13.4.3.4290, Java 17+).
- Reads ZAP **JSON** (`traditional-json`) and **XML** reports; no rule catalog to maintain, rules are created from the
  alerts in the report.
- One issue per alert instance (method + URI + parameter), de-duplicated across reports.
- Adds project metrics: high / medium / low / informational / total alerts and a risk score (high x 5 + medium x 3 + low x 1).

## Build and install

```bash
mvn clean verify
cp target/sonar-zap-plugin-26.1.0.jar $SONARQUBE_HOME/extensions/plugins/
# restart SonarQube and look for "Deploy plugin OWASP ZAP" in web.log
```

## Usage

1. Produce reports with ZAP, for example:

   ```bash
   zap-baseline.py -t https://my-app.example -J zap.json -r zap.html
   ```

2. Run the scanner with the report paths (relative to the project base directory):

   ```bash
   sonar-scanner \
     -Dsonar.zap.reportPaths=zap.json \
     -Dsonar.zap.htmlReportPath=zap.html
   ```

| Property | Description |
|---|---|
| `sonar.zap.reportPaths` | Comma-separated `.json` / `.xml` ZAP reports. A `*` wildcard is allowed in the file name. |
| `sonar.zap.htmlReportPath` | ZAP HTML report stored and shown on the **OWASP ZAP** project page (max 5 MB). |
| `sonar.zap.skip` | `true` to skip the import. |

## Severity mapping

| ZAP risk | Issue severity | Software quality impact |
|---|---|---|
| High (3) | Critical | Security: High |
| Medium (2) | Major | Security: Medium |
| Low (1) | Minor | Security: Low |
| Informational (0) | Info | Security: Info |

All issues are vulnerabilities (clean code attribute: Trustworthy), engine id `zap`, rule key = ZAP plugin id.

## Limitations

- ZAP findings are URL based, so issues are attached to the project, not to a file or line.
- Security hotspots are not produced.
- The HTML report is rendered in a fully sandboxed iframe (no scripts), so interactive report features are disabled.
- The HTML report is stored as a measure; very large reports are skipped with a warning.

## License

Apache-2.0
