import argparse, json, sys
from pathlib import Path
from .runner import load_events, load_rules, run, contract_gaps

def main(argv=None):
    parser = argparse.ArgumentParser(prog="replay")
    sub = parser.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--rules", required=True)
    r.add_argument("--events", required=True)
    args = parser.parse_args(argv)
    rules = load_rules(Path(args.rules))
    events = load_events(Path(args.events))
    report = run(rules, events)
    report["contract_gaps"] = contract_gaps(rules, events)
    print(json.dumps(report, indent=2))
    return 1 if report["contract_gaps"] else 0

if __name__ == "__main__":
    sys.exit(main())
