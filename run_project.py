"""One-command, package-free demonstration for project teammates."""
import argparse
from pathlib import Path
import subprocess
import sys
import webbrowser

ROOT = Path(__file__).resolve().parent

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Also run unit tests and audit all retained captures")
    parser.add_argument("--no-open", action="store_true", help="Do not open a browser")
    parser.add_argument("--output", default="results/local_demo", help="Output folder within this project")
    args = parser.parse_args()
    if sys.version_info < (3, 10):
        parser.exit(2, "Python 3.10 or newer is required. Install it from https://www.python.org/downloads/\n")
    output = (ROOT / args.output).resolve()
    if not output.is_relative_to(ROOT / "results"):
        parser.exit(2, "Choose an output directory inside the project's results folder.\n")
    def run(*arguments):
        print("\nRunning:", " ".join(arguments), flush=True)
        subprocess.run([sys.executable, "-B", *arguments], cwd=ROOT, check=True)
    try:
        run("demo/generate_demo_pcap.py")
        run("demo/run_demo.py", "--output", str(output))
        if args.check:
            run("-m", "unittest", "discover", "-s", "tests", "-v")
            run("tools/audit_results.py", str(output))
    except subprocess.CalledProcessError as error:
        print("A step failed. Read the error above; the demo is not complete.", file=sys.stderr)
        return error.returncode or 1
    report = output / "report.html"
    print("\nDemo complete. Open:", report)
    print("This is synthetic file-only traffic; no network packets were sent.")
    if not args.no_open:
        if not webbrowser.open(report.as_uri()):
            print("Open report.html manually if your browser did not launch.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
