![build status](https://travis-ci.org/droyo/styx.svg?branch=master)
[![GoDoc](https://godoc.org/aqwari.net/net/styx?status.svg)](https://godoc.org/aqwari.net/net/styx)

This repo provides Go packages for writing 9P2000 file servers. One
such example is [jsonfs](https://github.com/droyo/jsonfs),
which serves a JSON-encoded file as a file tree. Currently, only
server functionality is provided, though a client is planned -- see
[plan9port](https://swtch.com/plan9port), [v9fs](https://v9fs.sf.net)
for client implementations.

9P2000 provides a lightweight, stateful protocol for using hierarchical
APIs. The `styx` package attempts to expose, rather than hide, this
statefulness; user sessions are handled by, and tied to the lifetime of,
a single function.

# WARNING: WORK IN PROGRESS

This is a work-in-progress on a high-level library for writing 9P servers and
clients. While it has reached a point where it can be used to write working
file systems, the high-level API and its implementation are still subject to
change. For now, please vendor this dependency if you would choose to
use it.

This repository provides the following packages:

- `styxproto`: Low-level decoder and encoder for 9P2000 messages.
- `styx`: high-level server package akin to `net/http`
- `styxauth` - various `styx.AuthFunc` implementations

Of these, `styxproto` is the most stable. The `styx` package is still in
an experimental stage.
