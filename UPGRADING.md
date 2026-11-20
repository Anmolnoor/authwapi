# Upgrading AuthWAPI

## How an upgrade works

Stop the container, start the new image on the same data folder. On boot, AuthWAPI applies any new migrations
from `migrations/` before it serves a request:

1. **Backup first.** If the database already has migrations and new ones are pending, it copies the database and
   the secret to `backups/before-<first pending migration>-<timestamp>.db` and `.secret`, and logs
   `backed up database before migrating`. A brand-new data folder has nothing to back up.
2. **All or nothing.** Every pending migration runs in one transaction. If one fails, the whole upgrade is rolled
   back and the container refuses to start:

   ```
   AuthWAPI failed to start: Migration <name> failed, so the whole upgrade was rolled back; the database is unchanged. A backup from before the upgrade is at <data>/backups/before-<...>.db.
     cause: <the SQLite error>
   ```

   The database is left as it was, so the previous image still runs on it. Report the error before retrying.
3. After a successful upgrade, `migrations/` in the data folder holds a copy of every applied migration and
   `schema.sql` is rewritten.

**Never run an older image on a newer data folder.** If the database has a migration the image doesn't know,
the container refuses to start:

```
AuthWAPI failed to start: Database has migration <name>, which this image doesn't know: it was made by a newer AuthWAPI.
```

To go back to an older version after an upgrade, stop the container and restore the backup: copy
`backups/before-<...>.db` over `authwapi.db` and `backups/before-<...>.secret` over `secret`, delete the copies
of the newer migrations from `migrations/`, then start the older image. Anything written since the upgrade is
lost.

## 0.2.0 → next

Filled in at release.
