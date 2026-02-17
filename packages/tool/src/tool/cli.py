import argparse
import json


def start_cli()->None:
    parser = argparse.ArgumentParser(
        description="cli for the tool"
    )
    parser.add_argument("uuid", help="uuid for the file")
    parser.add_argument(
        "--output",
        "-o",
        metavar="FILE",
        help="Write JSON output to FILE instead of stdout",
    )
    args = parser.parse_args()
    nodes = {"result": "This is a test result"}
    output = json.dumps(nodes, indent=2)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"Tree written to {args.output} ({len(nodes)} nodes)")
    else:
        print(output)

