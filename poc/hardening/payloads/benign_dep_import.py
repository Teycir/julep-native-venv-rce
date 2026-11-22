# /// script
# dependencies = ["packaging==24.2"]
# requires-python = ">=3.14"
# ///
import packaging

@pure("poc.benign_dep.v1")
def compute(value, **kwargs):
    # Legitimate native-tier use case: consume a declared third-party dep.
    return {"loaded": True, "module": str(type(packaging))}
