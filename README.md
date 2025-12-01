# PoC for cryptidy pickle deserialization RCE

CVE PoC — Unsafe pickle deserialization vulnerability in cryptidy

## Summary

This repository contains a proof of concept (PoC) for a remote code execution (RCE) vulnerability in the `cryptidy` Python library. The library uses `pickle.loads` without input validation in `cryptidy/symmetric_encryption.py`, which allows an attacker to craft a malicious payload that, when deserialized, executes arbitrary code.

>  CVE ID: CVE-2025-63675 

---

## Vulnerability Details

- **Library:** cryptidy (PyPI)
- **Affected Versions:** 1.2.4 (or "All versions up to current" if not confirmed)
- **Component:** `cryptidy/symmetric_encryption.py` — vulnerable `decrypt_message()` (uses `pickle.loads`)
- **Vulnerability Type:** CWE-502: Deserialization of Untrusted Data
- **Attack Type:** Remote
- **Impact:** Remote Code Execution (RCE), Information Disclosure, Denial of Service, Privilege Escalation

### Attack Vector

An attacker can provide malicious encrypted data that, when decrypted and passed to `pickle.loads`, executes arbitrary code. A PoC payload (`payload_malicioso.bin`) and a runner (`ejecutar_exploit.py`) are included for testing in a controlled environment.

---

##  Proof of Concept (PoC)

> Warning: The files included demonstrate an exploit. Do NOT run them on production systems or any system you don't own. Use a disposable VM or container.

### Included files

- `cve_report.md` — Technical report (Spanish)
- `payload_malicioso.bin` — Example malicious payload (binary)
- `ejecutar_exploit.py` — Script to run the PoC locally (sanitized)
- `exploit.txt` — Output log from PoC run
- `cve_hunter_advanced.log` — Test logs

###  Warning: Safe Payload
The file `payload_malicioso.bin` is included as part of the PoC. It is safe and only opens the calculator when executed. Do NOT use this file outside of a controlled environment. Verify its integrity using the following hash:

SHA256: [ICB03BD0BBED4F796146F0F508D1E8BFF37A3B64D43AE7CFEA21C232473F3FFC0]

The file `payload_malicioso_cifrado.b64` is included as part of the PoC. It is safe and only opens the calculator when executed. Do NOT use this file outside of a controlled environment. Verify its integrity using the following hash:

SHA256: [F7600DAE96C6C4139ABDAABD045B1D554D53F2D7E08C70A391B96116FF80CD47]

### Safe test instructions

1. Create a new disposable virtual environment or VM.
2. Do NOT expose this environment to the network.
3. Inspect `ejecutar_exploit.py` before running.
4. Run the PoC locally:

```bash
# create and activate venv
python -m venv venv
venv\Scripts\activate   # Windows PowerShell: venv\Scripts\Activate.ps1
pip install -r requirements.txt  # if any deps; otherwise run with system python

# run (only on isolated VM)
python ejecutar_exploit.py
```

---

## Mitigation / Patch Recommendation

1. Avoid using `pickle` for untrusted input. Use safe formats such as JSON, or a vetted serialization library with explicit schemas.
2. If binary serialization is required, implement strict validation and restrict the set of permitted classes during deserialization (e.g., use `pickle.loads` with a safe unpickler or `dill` alternatives with restrictions).
3. Apply the principle of least privilege: ensure code that performs deserialization runs with minimal privileges.

Suggested quick fix (example):

```python
import pickle

def safe_load(data: bytes):
    # Prefer removing pickle entirely. If unavoidable, validate length/type and use restricted unpickling.
    assert isinstance(data, (bytes, bytearray))
    return pickle.loads(data)
```

Note: The best fix is to replace pickle with a safe format (JSON) and redesign APIs to avoid executing deserialized code.

---

## Credits

Discovered by Javier Morales
- GitHub: https://github.com/javiermorales36

---

## References

- Technical report: `cve_report.md`
- PoC files in this repository

For questions or coordination about responsible disclosure, open an issue or contact the maintainer.
