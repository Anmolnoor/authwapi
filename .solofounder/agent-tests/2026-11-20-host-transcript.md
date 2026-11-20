# AuthWAPI agent acceptance test — host transcript

Date: 2026-11-20. Docs only (README.md, site/src/content/docs/). Secrets redacted: no key, token or link is ever printed.

Placeholders: `<repo>` is the checkout, `<tmp>` the folder `mktemp -d` returned (under `/var/folders/`),
`<tmp-real>` the same folder by its real path (under `/private/var/folders/`), `<user>` the local account.

```console
$ cd <repo> && git fetch origin && git checkout --detach origin/main && git log -1 --format="%h %s"
HEAD is now at de0b1e8 Merge pull request #49 from Anmolnoor/m1-admin-mcp
de0b1e8 Merge pull request #49 from Anmolnoor/m1-admin-mcp
[exit 0]
```

```console
$ docker version --format "{{.Server.Version}}"
29.5.3
[exit 0]
```

## Step 1: start (quick start, with the documented "different port" variant: 4000 could be taken by other agents on this machine, so port 4817)

```console
$ lsof -nP -iTCP:4817 -sTCP:LISTEN | wc -l
       0
[exit 0]
```

```console
$ cd <repo> && docker build -t authwapi-agenttest . 2>&1 | tail -5
#16 naming to docker.io/library/authwapi-agenttest:latest done
#16 unpacking to docker.io/library/authwapi-agenttest:latest done
#16 DONE 0.0s
[exit 0]
```

```console
$ docker run -d --name authwapi-agenttest -p 127.0.0.1:4817:4000 -e BASE_URL=http://localhost:4817 -v "<tmp>/authwapi-data:/data" authwapi-agenttest
ab095139ed0e8aa02af80fcb902222ae3fae27c9159a83a526512b99dea9d8d6
[exit 0]
```

```console
$ for i in $(seq 1 30); do s=$(curl -s http://localhost:4817/health) && [ -n "$s" ] && break; sleep 1; done; echo "$s"
{"status":"ok"}
[exit 0]
```

```console
$ docker ps --filter name=authwapi-agenttest --format "{{.Names}} {{.Status}} {{.Ports}}"
authwapi-agenttest Up 1 second (health: starting) 127.0.0.1:4817->4000/tcp
[exit 0]
```

## Step 2: find the bootstrap key

```console
$ ls -la "<tmp>/authwapi-data"
ls: <tmp>/authwapi-data: No such file or directory
[exit 1]
```

```console
$ BOOT=$(docker exec -u 1000 authwapi-agenttest cat /data/bootstrap-admin-key); echo "key of length ${#BOOT}"; printf %s "$BOOT" | head -c 0; printf "%s" "$BOOT" | od -c | tail -2 | head -1 | cut -c1-0
key of length 47
head: illegal byte count -- 0
cut: [-bcf] list: values may not include zero
[exit 1]
```

```console
$ docker exec -u 1000 authwapi-agenttest cat /data/bootstrap-admin-key | wc -lc
       1      48
[exit 0]
```

```console
$ ls -la "<tmp>"
total 0
drwx------@    2 <user>  staff     64 Nov 20 07:26 .
drwx------@ 2295 <user>  staff  73440 Nov 20 07:26 ..
[exit 0]
```

```console
$ docker inspect authwapi-agenttest --format "{{json .Mounts}}"
[{"Type":"bind","Source":"<tmp>/authwapi-data","Destination":"/data","Mode":"","RW":true,"Propagation":"rprivate"}]
[exit 0]
```

```console
$ docker exec -u 1000 authwapi-agenttest ls -la /data
total 248
drwx------ 6 node node    200 Nov 20 14:26 .
drwxr-xr-x 1 root root   4096 Nov 20 14:26 ..
-rw------- 1 node node 233472 Nov 20 14:26 authwapi.db
drwx------ 2 node node     40 Nov 20 14:26 backups
-rw------- 1 node node     48 Nov 20 14:26 bootstrap-admin-key
drwx------ 2 node node     60 Nov 20 14:26 logs
drwx------ 2 node node    120 Nov 20 14:26 migrations
drwx------ 2 node node     40 Nov 20 14:26 outbox
-rw------- 1 node node   6237 Nov 20 14:26 schema.sql
-rw------- 1 node node     43 Nov 20 14:26 secret
[exit 0]
```

Finding: the data folder did not appear on the host. Docker Desktop on this Mac did not share the `<tmp>` path that `mktemp -d` returns (the container got an empty VM-side folder instead). Retrying with the resolved `<tmp-real>` path.

```console
$ docker rm -f authwapi-agenttest
authwapi-agenttest
[exit 0]
```

```console
$ docker run -d --name authwapi-agenttest -p 127.0.0.1:4817:4000 -e BASE_URL=http://localhost:4817 -v "<tmp-real>/authwapi-data:/data" authwapi-agenttest
c1eaefdfcf21033cd2152c1b1a9eae6bea0246775c5e2ad0108571051cf4ce38
[exit 0]
```

```console
$ for i in $(seq 1 30); do s=$(curl -s http://localhost:4817/health) && [ -n "$s" ] && break; sleep 1; done; echo "$s"
{"status":"ok"}
[exit 0]
```

```console
$ ls -la "<tmp-real>/authwapi-data" "<tmp-real>/authwapi-data/logs"
<tmp-real>/authwapi-data:
total 488
drwx------@ 10 <user>  staff     320 Nov 20 07:26 .
drwx------@  3 <user>  staff      96 Nov 20 07:26 ..
-rw-------@  1 <user>  staff  233472 Nov 20 07:26 authwapi.db
drwx------@  2 <user>  staff      64 Nov 20 07:26 backups
-rw-------   1 <user>  staff      48 Nov 20 07:26 bootstrap-admin-key
drwx------@  3 <user>  staff      96 Nov 20 07:26 logs
drwx------@  6 <user>  staff     192 Nov 20 07:26 migrations
drwx------@  2 <user>  staff      64 Nov 20 07:26 outbox
-rw-------   1 <user>  staff    6237 Nov 20 07:26 schema.sql
-rw-------@  1 <user>  staff      43 Nov 20 07:26 secret

<tmp-real>/authwapi-data/logs:
total 8
drwx------@  3 <user>  staff   96 Nov 20 07:26 .
drwx------@ 10 <user>  staff  320 Nov 20 07:26 ..
-rw-------   1 <user>  staff  726 Nov 20 07:26 app.jsonl
[exit 0]
```

```console
$ BOOT=$(docker exec -u 1000 authwapi-agenttest cat /data/bootstrap-admin-key); echo "bootstrap key read via docker exec: key of length ${#BOOT}"
bootstrap key read via docker exec: key of length 47
[exit 0]
```

```console
$ HB=$(cat "<tmp-real>/authwapi-data/bootstrap-admin-key"); BOOT=$(docker exec -u 1000 authwapi-agenttest cat /data/bootstrap-admin-key); [ "$HB" = "$BOOT" ] && echo 'host file matches: key of length '${#HB}
host file matches: key of length 47
[exit 0]
```

## Step 3: MCP client (official TypeScript SDK, installed in a temp folder)

```console
$ mkdir -p "<tmp-real>/client" && cd "<tmp-real>/client" && npm init -y >/dev/null && npm install @modelcontextprotocol/sdk 2>&1 | tail -2 && node -e 'console.log(require("@modelcontextprotocol/sdk/package.json").version)'; node --version

found 0 vulnerabilities
undefined
v22.23.1
[exit 0]
```

Client script: `<tmp-real>/client/mcp.mjs` (Client + StreamableHTTPClientTransport, header `Authorization: Bearer $KEY`, prints results; a minted key is written to a 0600 file and replaced by its length in output).

```js
// usage: KEY=... node mcp.mjs <tool|--list> [jsonArgs] [--save-key file]
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { writeFileSync } from "node:fs";
const [tool, args = "{}", flag, saveTo] = process.argv.slice(2);
const transport = new StreamableHTTPClientTransport(new URL(process.env.MCP_URL), {
  requestInit: { headers: { Authorization: `Bearer ${process.env.KEY}` } },
});
const client = new Client({ name: "agent-acceptance-test", version: "0.0.1" });
await client.connect(transport);
console.log("connected; server:", JSON.stringify(client.getServerVersion()), "protocol:", transport.protocolVersion ?? "(n/a)");
if (tool === "--list") {
  const { tools } = await client.listTools();
  console.log("tools:", tools.map((t) => t.name).join(", "));
} else {
  const res = await client.callTool({ name: tool, arguments: JSON.parse(args) });
  for (const c of res.content ?? []) {
    let text = c.text ?? JSON.stringify(c);
    if (flag === "--save-key") {
      const obj = JSON.parse(text);
      if (obj.key) { writeFileSync(saveTo, obj.key, { mode: 0o600 }); obj.key = `<redacted: key of length ${obj.key.length}, saved to file>`; }
      text = JSON.stringify(obj);
    }
    console.log(`${tool} -> isError=${!!res.isError}:`, text);
  }
}
await client.close();

```

```console
$ cd <tmp-real>/client && BOOT=$(docker exec -u 1000 authwapi-agenttest cat /data/bootstrap-admin-key) && MCP_URL=http://localhost:4817/mcp KEY="$BOOT" node mcp.mjs --list
connected; server: {"name":"authwapi-admin","version":"0.2.0"} protocol: 2025-11-25
tools: mint_agent_key
[exit 0]
```

## Step 4: mint a scoped write key with the bootstrap key

```console
$ cd <tmp-real>/client && BOOT=$(docker exec -u 1000 authwapi-agenttest cat /data/bootstrap-admin-key) && MCP_URL=http://localhost:4817/mcp KEY="$BOOT" node mcp.mjs mint_agent_key '{"scope":"write"}' --save-key <tmp-real>/client/write.key
connected; server: {"name":"authwapi-admin","version":"0.2.0"} protocol: 2025-11-25
mint_agent_key -> isError=false: {"keyId":"key_491d088e86e2d86e","scope":"write","key":"<redacted: key of length 47, saved to file>"}
[exit 0]
```

```console
$ ls -l <tmp-real>/client/write.key | awk '{print $1, $5}'
-rw-------@ 47
[exit 0]
```

Check the doc claim that the bootstrap key is now spent:

```console
$ cd <tmp-real>/client && BOOT=$(docker exec -u 1000 authwapi-agenttest cat /data/bootstrap-admin-key) && MCP_URL=http://localhost:4817/mcp KEY="$BOOT" node mcp.mjs --list 2>&1 | grep -o 'HTTP[^"]*\|401[^,]*\|Error[^:]*: [^{]\{0,80\}' | head -3
HTTPError(response.status, `Error POSTing to endpoint: ${this._unfollowedRedirect(response, this._url) ?? text}`);
HTTPError: Streamable HTTP error: Error POSTing to endpoint: {
HTTPClientTransport.send (file://<tmp-real>/client/node_modules/@modelcontextprotocol/sdk/dist/esm/client/streamableHttp.js:378:23)
[exit 0]
```

```console
$ BOOT=$(docker exec -u 1000 authwapi-agenttest cat /data/bootstrap-admin-key); curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:4817/mcp -H "Authorization: Bearer $BOOT" -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
401
[exit 0]
```

## Step 5: reconnect with the write key and create a user

```console
$ cd <tmp-real>/client && MCP_URL=http://localhost:4817/mcp KEY="$(cat <tmp-real>/client/write.key)" node mcp.mjs --list
connected; server: {"name":"authwapi-admin","version":"0.2.0"} protocol: 2025-11-25
tools: mint_agent_key, revoke_agent_key, get_status, list_users, create_user, read_audit
[exit 0]
```

```console
$ cd <tmp-real>/client && MCP_URL=http://localhost:4817/mcp KEY="$(cat <tmp-real>/client/write.key)" node mcp.mjs create_user '{"email":"agent-test@example.com","name":"Agent Test","password":"a-long-agent-test-password"}'
connected; server: {"name":"authwapi-admin","version":"0.2.0"} protocol: 2025-11-25
create_user -> isError=false: {"user":{"id":"kRWkEgaswAxCd2B8amuJZDWv6KPrAFfB","email":"agent-test@example.com","name":"Agent Test","emailVerified":false},"verificationEmail":"queued"}
[exit 0]
```

```console
$ cd <tmp-real>/client && MCP_URL=http://localhost:4817/mcp KEY="$(cat <tmp-real>/client/write.key)" node mcp.mjs list_users '{}'
connected; server: {"name":"authwapi-admin","version":"0.2.0"} protocol: 2025-11-25
list_users -> isError=false: {"users":[{"id":"kRWkEgaswAxCd2B8amuJZDWv6KPrAFfB","email":"agent-test@example.com","name":"Agent Test","emailVerified":false,"createdAt":"2026-11-20T14:27:43.156Z"}],"total":1}
[exit 0]
```

## Step 6: read the audit log and find the create_user entry

```console
$ cd <tmp-real>/client && MCP_URL=http://localhost:4817/mcp KEY="$(cat <tmp-real>/client/write.key)" node mcp.mjs read_audit '{"limit":20}'
connected; server: {"name":"authwapi-admin","version":"0.2.0"} protocol: 2025-11-25
read_audit -> isError=false: {"entries":[{"time":"2026-11-20T14:27:36.213Z","who":"key_b9162cabb01868ab","scope":"bootstrap","tool":"mint_agent_key","outcome":"ok","minted":"key_491d088e86e2d86e"},{"time":"2026-11-20T14:27:43.159Z","who":"key_491d088e86e2d86e","scope":"write","tool":"create_user","outcome":"ok","target":"kRWkEgaswAxCd2B8amuJZDWv6KPrAFfB"},{"time":"2026-11-20T14:27:43.814Z","who":"key_491d088e86e2d86e","scope":"write","tool":"list_users","outcome":"ok"}]}
[exit 0]
```

Same file on disk (README: `logs/audit.jsonl`):

```console
$ cat "<tmp-real>/authwapi-data/logs/audit.jsonl"
{"time":"2026-11-20T14:27:36.213Z","who":"key_b9162cabb01868ab","scope":"bootstrap","tool":"mint_agent_key","outcome":"ok","minted":"key_491d088e86e2d86e"}
{"time":"2026-11-20T14:27:43.159Z","who":"key_491d088e86e2d86e","scope":"write","tool":"create_user","outcome":"ok","target":"kRWkEgaswAxCd2B8amuJZDWv6KPrAFfB"}
{"time":"2026-11-20T14:27:43.814Z","who":"key_491d088e86e2d86e","scope":"write","tool":"list_users","outcome":"ok"}
{"time":"2026-11-20T14:27:48.281Z","who":"key_491d088e86e2d86e","scope":"write","tool":"read_audit","outcome":"ok"}
[exit 0]
```

## Step 7: sign in. First, before verifying (docs: unverified users cannot sign in):

```console
$ cd <tmp-real>/client && (umask 077; curl -s -o signin1.json -w '%{http_code}\n' -c jar -X POST http://localhost:4817/api/auth/sign-in/email -H 'content-type: application/json' -d '{"email":"agent-test@example.com","password":"a-long-agent-test-password"}'); cat signin1.json; echo
403
{"message":"Email not verified","code":"EMAIL_NOT_VERIFIED"}
[exit 0]
```

Verify through the outbox, following for-ai-agents.md runbook step 4 (adapted: container name, and port 4817 in the link pattern):

```console
$ for i in $(seq 1 20); do MAIL=$(docker exec -u 1000 authwapi-agenttest sh -c 'grep -l "\"to\": \"agent-test@example.com\"" /data/outbox/*.json 2>/dev/null | sort | tail -1'); [ -n "$MAIL" ] && break; sleep 0.5; done; echo "mail file: $MAIL"; docker exec -u 1000 authwapi-agenttest grep -o '"subject": "[^"]*"' "$MAIL"; LINK=$(docker exec -u 1000 authwapi-agenttest grep -o 'http://localhost:4817/api/auth/verify-email?[^"\\]*' "$MAIL"); echo "link of length ${#LINK}"; curl -s -X POST "$LINK" --data-urlencode password=a-long-agent-test-password | grep -o 'Your email is verified'
mail file: /data/outbox/2026-11-20T14-27-43-164Z-4353cb50.json
"subject": "Verify your email"
link of length 281
Your email is verified
[exit 0]
```

Sign in after verification (runbook step 5, port adapted):

```console
$ cd <tmp-real>/client && rm -f jar && (umask 077; curl -s -o /dev/null -w '%{http_code}\n' -c jar -X POST http://localhost:4817/api/auth/sign-in/email -H 'content-type: application/json' -d '{"email":"agent-test@example.com","password":"a-long-agent-test-password"}'); curl -s -b jar http://localhost:4817/api/auth/get-session | grep -o '"emailVerified":true\|"email":"[^"]*"' | sort -u
200
"email":"agent-test@example.com"
"emailVerified":true
[exit 0]
```

Cross-check over MCP:

```console
$ cd <tmp-real>/client && MCP_URL=http://localhost:4817/mcp KEY="$(cat <tmp-real>/client/write.key)" node mcp.mjs list_users '{}'
connected; server: {"name":"authwapi-admin","version":"0.2.0"} protocol: 2025-11-25
list_users -> isError=false: {"users":[{"id":"kRWkEgaswAxCd2B8amuJZDWv6KPrAFfB","email":"agent-test@example.com","name":"Agent Test","emailVerified":true,"createdAt":"2026-11-20T14:27:43.156Z"}],"total":1}
[exit 0]
```

Check app log for leaked secrets (docs: never contains tokens or links):

```console
$ grep -c 'verify-email?\|token=' "<tmp-real>/authwapi-data/logs/app.jsonl"; grep -cF "$(cat <tmp-real>/client/write.key)" "<tmp-real>/authwapi-data/logs/"*.jsonl
0
<tmp-real>/authwapi-data/logs/audit.jsonl:0
<tmp-real>/authwapi-data/logs/app.jsonl:0
[exit 1]
```

(The last command exits 1 because grep found 0 matches: no links, tokens or the agent key in either log, which is the good result.)

## Cleanup

```console
$ docker rm -f authwapi-agenttest && docker rmi authwapi-agenttest >/dev/null && echo "image removed"
authwapi-agenttest
image removed
[exit 0]
```

```console
$ rm -rf "<tmp-real>" && echo 'temp dir (data folder with secret, write key, client) removed'
temp dir (data folder with secret, write key, client) removed
[exit 0]
```

```console
$ docker ps -a --filter name=authwapi-agenttest --format "{{.Names}}" | wc -l
       0
[exit 0]
```
