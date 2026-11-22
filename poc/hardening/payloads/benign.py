# /// script
# dependencies = ["packaging==24.2"]
# requires-python = ">=3.14"
# ///
@pure("poc.benign.v1")
def compute(value, **kwargs):
    nums = value["nums"]
    return {
        "sum": sum(nums),
        "count": len(nums),
        "label": str(value["label"]).upper(),
        "ok": len(nums) == 3,
    }
