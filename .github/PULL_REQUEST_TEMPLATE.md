## What this changes

<!-- One or two sentences. Why are we doing this? -->

## How it changes behaviour

<!-- New flag, new score component, new endpoint? Anything a user-facing CLI consumer would notice. -->

## Tests

- [ ] `pytest tests/ -q` passes locally
- [ ] If a CLI surface changed, `python scripts/validate_deck.py --skip-slow` still passes
- [ ] If a new scoring signal was added: the score breakdown table in `commands.py` surfaces its factors

## Notes for reviewers

<!-- Anything load-bearing or non-obvious in the diff. -->
