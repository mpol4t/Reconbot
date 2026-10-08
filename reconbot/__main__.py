from .cli import main

try:
    main()
except KeyboardInterrupt:
    print("[!] Program interrupted by user (Ctrl+C). Exiting...", flush=True)
    raise SystemExit(130)