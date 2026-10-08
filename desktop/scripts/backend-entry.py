"""Frozen desktop backend: retain the existing module command/stdin contracts."""
import runpy
import sys


def main():
    args = sys.argv[1:]
    if args[:1] == ["-u"]:
        args = args[1:]
    allowed = {"reconbot", "reconbot.ai.assistant", "reconbot.orchestration.ip_enrichment", "reconbot.validation.sqlmap", "reconbot.validation.authentication"}
    if len(args) < 2 or args[0] != "-m" or args[1] not in allowed:
        raise SystemExit("ReconBot backend requires a supported -m module command")
    module = args[1]
    sys.argv = [module, *args[2:]]
    runpy.run_module(module, run_name="__main__", alter_sys=True)


if __name__ == "__main__":
    main()
