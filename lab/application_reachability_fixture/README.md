# AEGIS Deep Source Analysis fixture

This directory is inert source material for Application Research. AEGIS must
copy and inspect it without running it.

Expected deep-source evidence:

- `reachable_flask.py`: one static web-input-to-command path.
- `unreachable_worker.py`: an unsafe command sink with no attacker-input path;
  quick triage may report the sink, but reachability analysis must not promote
  it to `reachable_from_input`.
- `Controller.java` and `pom.xml`: Log4j Core 2.14.1 is both declared and
  referenced, and servlet input reaches a Log4j call. OSV should correlate the
  affected dependency while Semgrep supplies the static taint path.

These are static fixtures only. They contain no runnable server, real secret,
working exploit, or claim of successful exploitation.
