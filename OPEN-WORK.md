# Open work

Standing backlog. Edit line by line, never rewrite wholesale. When an item is finished, delete
its line; the reason it closed belongs in the commit message, CHANGELOG or git history.

- [ ] (2026-10-08) [10] FOUND: the delivery deadline does not cover the EHLO-name lookup - SmtplibTransport.deliver calls _default_local_hostname() (socket.getfqdn(), maybe gethostbyname; functools.cache, once per process) BEFORE _session_deadline opens (src/btx_lib_mail/_transport.py ~208), so on a host with slow reverse DNS the first delivery of a process outlives smtp_delivery_deadline by that lookup (measured by a soundtouch-watchdog review: getfqdn delayed 3 s, deadline 0.5 s, worker held 4.0 s); the 4.0.0 CHANGELOG names only the relay's own name lookup as uninterrupted | size: unknown - a doc line at least; maybe resolve the name outside a deliver() call (e.g. when ConfMail/send is set up) or bound it | open: first seen 2026-10-08 from soundtouch-watchdog rank 36 (it warms the lookup in its test and documents the exception) | next: decide document-only vs move the lookup, then CHANGELOG + docstring of smtp_delivery_deadline
