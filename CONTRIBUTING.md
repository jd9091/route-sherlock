# Contributing to Route Sherlock

Thanks for taking the time. Route Sherlock is built for network operators, by a network operator — your operator-level critique is exactly what makes the scoring better. Bug reports, methodology corrections, and new feature proposals are all welcome.

## How to file an issue

Use one of the issue templates:

- **Bug report** — the tool doesn't do what the docs / help text say it should.
- **Feature request** — a new command, flag, output format, or data source.
- **Methodology critique** — the score is wrong, the math doesn't capture reality, or a signal is missing. The talk explicitly invites this; bring an ASN, the current output, and your reasoning.

For open-ended questions ("does the score handle X?", "how would I integrate this with my pipeline?") open a [Discussion](https://github.com/jd9091/route-sherlock/discussions) instead.

## How to send a pull request

1. Fork, branch off `main`.
2. Set up the dev environment:
   ```bash
   python3.11 -m venv venv
   source venv/bin/activate
   pip install -e ".[dev]"
   ```
3. Run the unit tests: `pytest tests/ -q`. They must pass before you push.
4. If you change anything the deck demos (`peer-risk`, `compare`, `lookup`, `ix-presence`, `stability`, `backtest`), run `python scripts/validate_deck.py --skip-slow` and confirm it still produces the green-tile report.
5. Open a PR using the template. CI will re-run tests.

## Code style

- Prefer keeping a single `risk_data` dict shape across the pipeline — adding a new score component means adding a sub-dict, not a parallel data structure.
- Every new external API call should be wrapped in the same retry/backoff helper PeeringDB and RIPEstat already use.
- New CLI flags should be reflected in the docstring example block of the command.
- Default to no comments. Only add one when the *why* is non-obvious.

## Known open work

Tracked in the repo's [issue list](https://github.com/jd9091/route-sherlock/issues). Some currently-open critiques the maintainer has called out publicly:

- IX overlap counts membership, not peerability (no operational/route-server/policy check)
- Stability uses absolute updates/day (no prefix-count normalization)
- No `--as-of <date>` for point-in-time scoring
- No `last_incident_at` surfaced in the score

If you want to take one of these, comment on the issue first so we don't duplicate effort.

## Contact

For anything that doesn't fit a public issue or discussion:

- Email: davejd2990@gmail.com
- NANOG 97 talk: "Peering Risk Intelligence" (Bellevue, June 1–3 2026) — I'll be presenting remotely, so the fastest channel during the event is email or a GitHub issue.
