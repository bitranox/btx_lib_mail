# Open work

Standing backlog. Edit line by line, never rewrite wholesale. When an item is finished, delete
its line; the reason it closed belongs in the commit message, CHANGELOG or git history.

- [ ] (2026-10-30) [10] FOUND: tests/test_deadline.py::test_the_handle_number_a_cut_frees_is_kept_from_other_sockets_until_the_session_closes failed once on CI Tests (Python 3.13, windows-latest), run 41039003169 attempt 1, sha e29b4a60 (assert 1008 == 760: the guard did not get the freed handle number), and the same worker's test_a_failed_session_closes_its_socket then caught a ResourceWarning, most likely the socket the first test left open when its assert fired; attempt 2 on the same sha passed, and the code was unchanged since 4.6.3 | size: unknown - one intermittent test plus the mechanism it pins (does Windows reuse a freed socket handle number deterministically?) | open: first seen here; whether it is the test's assumption or the handle guard itself is not yet known | next: read how the cut takes its placeholder handle and whether anything else can take the number first; close the connection in a finally so a failed assert cannot leak into the next test
