# Pentesta Project – Information Gathering Stage 📊

This repository showcases my contribution to the **Pentesta Project**, a Web Vulnerability Scanner designed to identify potential security risks in web applications. My focus was on the **Information Gathering** stage, which is crucial for collecting technical and security-related information before active vulnerability scanning.

The Information Gathering stage includes **two main tasks**:

1. **JavaScript Analyzer**
2. **Technologies & Infrastructure Fingerprinting**

---

## 1️⃣ JS Analyzer 🔍

![Go](https://img.shields.io/badge/Language-Go-00ADD8?style=flat\&logo=go)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)
![GitHub Repo Size](https://img.shields.io/github/repo-size/Petersudo01/JS-analyzer?style=flat)
![GitHub last commit](https://img.shields.io/github/last-commit/Petersudo01/JS-analyzer?style=flat)

**JS Analyzer** is a **static analysis tool for JavaScript files** built in Go. It helps detect:

* Dangerous functions like `eval`, `Function`, `exec`, `setTimeout`, `setInterval`
* Sensitive data such as `api_key`, `token`, `password`, `secret`, `PRIVATE_KEY`
* Frontend frameworks used and their versions (React, Angular, Vue, Next.js, Express)

### Features

* Concurrent pipeline using Go channels
* Color-coded CLI output
* Detects dangerous functions and secrets
* Detects frameworks and versions via regex
* Saves structured JSON reports
* Modular architecture (Stage1 → Stage5)

### Project Structure

```text
JS-analyzer/
├─ Stages/       # Source code for each stage
├─ Tests/        # JavaScript test files
├─ Report/       # JSON reports
├─ go.mod
├─ main.go       # Entry point
├─ LICENSE
├─ README.md
```

### Usage

```bash
go run . <filename.js>
```

Example:

```bash
go run . full_test.js
```

Expected output:

```
🚀 Starting analysis for file: full_test.js
🔍 Stage3 Analyzer working...

📊 Analysis results for file: full_test.js
[⚠️] secret - Line 2
[⚠️] api_key - Line 12
[⚙️ FRAMEWORK] React v17.0.2
✅ Report saved as report.json
🚀 Analysis finished successfully!
```

### JSON Report Example

```json
{
  "file": "example.js",
  "dangerous_functions": [{"type": "Dangerous Function", "detail": "eval", "line": 10, "severity": "high"}],
  "secrets": [{"type": "Sensitive Data", "detail": "api_key", "line": 4, "severity": "medium"}],
  "frameworks": [{"name": "React", "version": "17.0.2"}]
}
```

---

## 2️⃣ Technologies & Infrastructure Fingerprinting 🖥️

![Go](https://img.shields.io/badge/Language-Go-00ADD8?style=flat\&logo=go)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)
![GitHub Repo Size](https://img.shields.io/github/repo-size/Petersudo01/Pentesta?style=flat)
![GitHub last commit](https://img.shields.io/github/last-commit/Petersudo01/Pentesta?style=flat)

This module detects **server technologies, backend frameworks, frontend libraries, databases, open ports, TLS info, CDNs, secrets, and endpoints**. It merges information from the JS Analyzer for a full picture.

### Features

* Detects frontend, backend, server, and database technologies
* Computes Favicon MD5 fingerprints
* Scans TLS certificates and protocols
* Detects secrets in HTML/JS
* Extracts JS files and API endpoints
* Scans common ports
* Detects CDN/hosting providers
* Merges JS Analyzer results
* Saves structured JSON reports

### Project Structure

```text
Pentesta/
├─ Fingerprinter/       # Source code
├─ Reports/            # JSON reports
├─ JSAnalyzerReports/  # JS Analyzer reports
├─ go.mod
├─ main.go            # Entry point
├─ LICENSE
├─ README.md
```

### Usage

```bash
go run .
```

Enter the target URL when prompted:

```
Enter target URL: https://example.com
```

Results are saved as **JSON reports** in `Reports/` and merged with JS Analyzer results from `JSAnalyzerReports/`.

### JSON Report Example

```json
{
  "target_url": "https://example.com",
  "ips": ["93.184.216.34"],
  "server": "nginx/1.20",
  "content_type": "text/html",
  "technologies": {"frontend": ["React"], "backend": ["Node.js", "Express.js"], "server": ["nginx"], "database": ["MySQL"]},
  "favicon_md5": "d41d8cd98f00b204e9800998ecf8427e",
  "tls_info": {"issuer": "Let's Encrypt", "expiry": "2025-12-15T00:00:00Z", "protocol": "TLS 1.3", "cipher_suite": "TLS_AES_256_GCM_SHA384"},
  "secrets": ["api_key_example"],
  "endpoints": ["/api/users.js"],
  "open_ports": {"80":"open", "443":"open"},
  "cdn_hosting": ["Cloudflare"],
  "merged_from_js": {...},
  "scan_timestamp": "2025-12-16T00:00:00Z"
}
```

---

## License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.

---

## Author

**Peter Osama** – [GitHub](https://github.com/Petersudo01) | [peterosama.20003@gmail.com](mailto:peterosama.20003@gmail.com)
