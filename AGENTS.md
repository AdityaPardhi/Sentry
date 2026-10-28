Project: Sentry. C sandbox in sandbox/, Python CLI in cli/, monitors in
monitor/, tests in tests/. Build with `make` (-Wall -Wextra; must stay
warning-free).

Rules:
- Before starting a task: list the files and line ranges you will touch,
  in one short line, then proceed. Do not wait for approval unless the
  task needs a file I did not name.
- Do only the task I give. No refactors, no extra files, no README
  rewrites, no documentation unless I ask. Finish with a summary of at
  most 5 lines.
- Open only the files and line ranges I name. Do not scan the repo.
- NEVER run sudo, `make test*`, `make escape-test`, or anything that
  starts the sandbox. I run those. You may run `make`,
  `python3 -m py_compile <file>` and `bash -n <file>`.
- Never edit anything in tests/escape_src/ or change a test's expected
  result to make it pass, except where I name the file. If a test fails,
  report it and stop.
- Prefer small targeted edits over rewriting whole files.
- If a build error appears, try one fix. If it still fails, stop and show
  me the error. Do not loop.
- Python: standard library only. No new dependencies.
