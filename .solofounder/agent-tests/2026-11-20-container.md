# No-human agent test: container run, 2026-11-20

A fresh AI agent, given only the docs, ran AuthWAPI at commit `3dfd5df` on Fedora with podman, with its
own MCP client in a second container on a shared podman network, and administered the server over MCP.

**Result: PASS.** Every MCP step passed. Sign-in passed only with two workarounds, both now documented.

| Step | Result |
| --- | --- |
| 1. Build and start the server container | PASS |
| 2. Put the server and the client container on one network | PASS |
| 3. Get the bootstrap key into the client container | PASS |
| 4. Connect to `/mcp` from the client container with the official MCP TypeScript SDK | PASS |
| 5. Mint a write key | PASS |
| 6. Create a user over MCP | PASS |
| 7. Find the `create_user` line in the audit log | PASS |
| 8. Sign in as the new user | PASS, with two workarounds (findings 1 and 2) |

## Doc findings, all fixed in the `docs-agent-in-container` branch

1. The verify step couldn't work from a container: it read the outbox with `docker exec` (the client container
   has no Docker), and the link starts with the server's `BASE_URL` (`http://localhost:4000`), which in the client
   container is the client itself. The docs now say to create test users with `"emailVerified": true`, and that a
   person on the server's host can read the link from the outbox and open it there.
2. Nothing said how to get the bootstrap key into the agent's container safely. The docs now pipe it from the
   server container into a 0600 file in the client container (and the same for a reissued key), and warn that
   `-e KEY=…` shows the key in `inspect`.
3. The in-container setup was one bullet on the configuration page. AGENTS.md and For AI agents now have an "Agent
   in another container" section: user-defined network, `--network-alias authwapi`, `ALLOWED_HOSTS=authwapi`,
   `BASE_URL` left on localhost, MCP at `http://authwapi:4000/mcp`, and the optional `127.0.0.1` port for the host.
4. "Set `BASE_URL` or `ALLOWED_HOSTS`" didn't say that from a container only `ALLOWED_HOSTS` works: a `BASE_URL`
   that isn't localhost refuses to start without Resend.
5. The README's `claude mcp add` example had no in-container URL.
6. Fixed names (`--name authwapi`, `authwapi-net`) collide on a shared machine. The container section now uses
   unique names and the network alias.
7. `node:*-slim` images have no `curl`, which the runbook uses. The docs now say to install it or use Node's
   `fetch`.

The documented commands were then run on macOS with Docker Desktop: a server and a `node:26-slim` client on a
fresh network with the alias, the key piped in (0600, nothing in `inspect`), the runbook's `admin.mjs` minting a
write key, `create_user` with `"emailVerified": true`, `read_audit`, a sign-in from the client container (200,
`"emailVerified":true`), a reissued key piped in and used, and a non-localhost `BASE_URL` refusing to start.
