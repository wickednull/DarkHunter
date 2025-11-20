
import json, os, time
def export_har(entries, out_dir="reports"):
    os.makedirs(out_dir, exist_ok=True)
    data = {"log": {"version": "1.2", "creator": {"name": "DarkHunter", "version": "7.7.0"}, "entries": entries or []}}
    path = os.path.join(out_dir, "session_%d.har" % int(time.time()))
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return path
