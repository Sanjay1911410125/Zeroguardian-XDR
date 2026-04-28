# scripts/collect_samples.py
import json, time, argparse
from core.orchestrator import collect_all
from core.features import build_features

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data/normal_samples.jsonl")
    ap.add_argument("--count", type=int, default=300)      # 300 samples
    ap.add_argument("--sleep", type=float, default=2.0)    # 2 sec gap
    args = ap.parse_args()

    print(f"[+] Collecting {args.count} samples → {args.out}")
    print("[!] Keep network mostly NORMAL while collecting (no scans, no flood).")

    with open(args.out, "a") as f:
        for i in range(args.count):
            data = collect_all(cache_seconds=0)  # always fresh
            feats = build_features(data.get("devices"), data.get("traffic"))
            row = {"ts": int(time.time()), "features": feats}
            f.write(json.dumps(row) + "\n")
            f.flush()
            print(f"{i+1}/{args.count} features={feats}")
            time.sleep(args.sleep)

    print("[+] Done.")

if __name__ == "__main__":
    main()
