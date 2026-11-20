// M3 organizations and admin (plan flow.md, M3 in "Rev 8 execution"): Better Auth's organization and admin plugins,
// and the policy around them. Org claims and the OAuth side of the ban live in src/oauth.ts; MCP tools in src/admin.ts.
// - banUser: the one ban operation, for HTTP (/admin/ban-user, /admin/update-user) and MCP (ban_user).
// - /admin/revoke-user-session(s) and /admin/set-user-password also revoke OAuth tokens and unused authorization codes
//   (/admin/remove-user: the user's tokens go with the user).
// - Impersonation: 10 minutes (never refreshed), audited, never an admin or an organization owner/admin; no credential
//   or consent changes, no linked-provider tokens. It also gets no authorization code (consentReferenceId in
//   src/oauth.ts), and signing it out revokes nothing of the target's (src/oauth.ts).
// - Invitations are emailed with a link to the hosted accept page (src/pages.ts).
import path from 'node:path';
import { defineRequestState, getCurrentAdapter, queueAfterTransactionHook, runWithRequestState, runWithTransaction } from '@better-auth/core/context';
import type { AuthContext, BetterAuthOptions, BetterAuthPlugin } from 'better-auth';
import { APIError, createAuthEndpoint, createAuthMiddleware, isAPIError } from 'better-auth/api';
import type Database from 'better-sqlite3';
import { admin, organization } from 'better-auth/plugins';
import { appendAudit } from './admin.ts';
import type { AuthDeps } from './auth.ts';
import { dataPaths } from './data.ts';
import type { SendMail } from './mailer.ts';
import { isBanned, revokeUserTokens } from './oauth.ts';

type Plugin = NonNullable<BetterAuthOptions['plugins']>[number];
type HookContext = Parameters<Parameters<typeof createAuthMiddleware>[0]>[0];
type Deliver = (what: string, mail: Parameters<SendMail>[0]) => void;

export const IMPERSONATION_SECONDS = 10 * 60;
export const ACCEPT_INVITATION_PAGE = '/accept-invitation';

const roleList = (role: unknown) => (typeof role === 'string' ? role.split(',').map((r) => r.trim()) : []);

/**
 * Deletes the user's unused authorization codes: the provider stores each as a verification row whose JSON value
 * names its type and user (redirectWithAuthorizationCode). Matched exactly; other verification values aren't all JSON.
 * Better Auth's Kysely transactions run on this same connection, so inside one this statement is part of it.
 */
export function deletePendingCodes(context: Pick<AuthContext, 'options'>, userId: string): void {
  (context.options.database as Database.Database)
    .prepare(
      `DELETE FROM verification WHERE CASE WHEN json_valid(value)
         THEN json_extract(value, '$.type') = 'authorization_code' AND json_extract(value, '$.userId') = ? ELSE 0 END`
    )
    .run(userId);
}

/**
 * The one ban operation, in one transaction: the ban, the end of the user's sessions, the revocation of their OAuth
 * tokens and the deletion of their unused authorization codes. The ban is written first: a token issued at the same
 * time is either revoked here, or written after it and revoked by /oauth2/token's own re-check (src/oauth.ts).
 * Idempotent: the HTTP routes run it inside Better Auth's own handler's transaction, after the handler wrote their ban
 * (keeping its banExpires; inBanTransaction). MCP's ban_user passes banExpires: null, an indefinite ban.
 */
export async function banUser(
  context: Pick<AuthContext, 'adapter' | 'internalAdapter'>,
  userId: string,
  fields: { banReason?: string; banExpires?: null } = {}
): Promise<void> {
  await runWithTransaction(context.adapter, async () => {
    await context.internalAdapter.updateUser(userId, { banned: true, ...fields });
    await context.internalAdapter.deleteUserSessions(userId);
    await revokeUserTokens(context, userId);
    deletePendingCodes(context as unknown as Pick<AuthContext, 'options'>, userId);
  });
}

type Endpoint = ((ctx: object) => Promise<unknown>) & { path: string; options: { use?: unknown } & Record<string, unknown> };

/**
 * Better Auth's /admin/ban-user or /admin/update-user, made atomic with the ban operation: its handler (permission
 * checks, the ban write, the session deletion) and then banUser's cleanup run in one transaction, so a failed cleanup
 * leaves no ban and no deleted sessions. The handler runs as a plain call with its own middleware (`use`); hooks run
 * once, around this endpoint, and the response is the handler's.
 */
function inBanTransaction(endpoint: Endpoint): Endpoint {
  const { use: _middleware, ...options } = endpoint.options;
  return createAuthEndpoint(endpoint.path, options as never, async (ctx) =>
    runWithTransaction(ctx.context.adapter, async () => {
      const response = await endpoint({ ...ctx, asResponse: false, returnHeaders: false, returnStatus: false });
      const userId = (ctx.body as { userId?: unknown }).userId;
      if (typeof userId === 'string' && isBanned(await ctx.context.internalAdapter.findUserById(userId))) await banUser(ctx.context, userId);
      return ctx.json(response as Record<string, unknown> | null);
    })
  ) as unknown as Endpoint;
}

/** The user a server-side Better Auth call (no HTTP request) acts as: MCP has no session. See asUser. */
const actingAs = defineRequestState<string | undefined>(() => undefined);

/** Runs `call`, a direct auth.api call, as `userId` (the org owner an MCP invitation comes from). */
export const asUser = <T>(userId: string, call: () => Promise<T>): Promise<T> =>
  runWithRequestState(new WeakMap(), async (): Promise<T> => {
    await actingAs.set(userId);
    return call();
  }) as Promise<T>;

// What an impersonated session may not do: change credentials (password, email, linked accounts, 2FA, passkeys),
// delete the account, edit consent outside the authorization step, or get or refresh linked providers' tokens.
const IMPERSONATION_REFUSED = new Set([
  '/change-password',
  '/set-password',
  '/change-email',
  '/delete-user',
  '/link-social',
  '/unlink-account',
  '/oauth2/update-consent',
  '/oauth2/delete-consent',
  '/get-access-token',
  '/refresh-token',
  '/account-info',
]);
const refusedWhenImpersonated = (p: string) => IMPERSONATION_REFUSED.has(p) || p.startsWith('/two-factor/') || p.startsWith('/passkey/');
// Server-side calls that run as the organization owner (asUser): MCP invitations, SSO provider changes (src/sso.ts).
const AS_USER_PATHS = new Set(['/organization/invite-member', '/sso/register', '/sso/delete-provider']);
// Admin routes that end a user's sessions or replace their password: their OAuth tokens go too (by body.userId).
// /admin/remove-user needs nothing: deleting the user deletes their tokens (foreign keys cascade).
const REVOKES_TOKENS = new Set(['/admin/revoke-user-sessions', '/admin/set-user-password']);

function orgAdminGlue(auditFile: string): BetterAuthPlugin {
  const audit = (tool: string, who: string, target: string) => appendAudit(auditFile, { who, scope: 'admin-session', tool, outcome: 'ok', target });
  return {
    id: 'authwapi-orgs',
    init: (authContext) => ({
      options: {
        databaseHooks: {
          session: {
            create: {
              before: async (session) => {
                const by = (session as { impersonatedBy?: string | null }).impersonatedBy;
                if (!by) return;
                // Better Auth already refuses admins (without impersonate-admins); organization owners and admins too.
                const target = await authContext.internalAdapter.findUserById(session.userId);
                const memberships = await authContext.adapter.findMany<{ role: string }>({ model: 'member', where: [{ field: 'userId', value: session.userId }] });
                if (roleList((target as { role?: string } | null)?.role).includes('admin') || memberships.some((m) => roleList(m.role).some((r) => r === 'owner' || r === 'admin'))) {
                  throw new APIError('FORBIDDEN', { code: 'CANNOT_IMPERSONATE', message: "Admins and organization owners or admins can't be impersonated." });
                }
                audit('impersonate_user', by, session.userId); // a line that can't be written stops the impersonation
              },
            },
            update: {
              // Better Auth's session refresh (get-session past updateAge) would push an impersonation to the normal
              // 7 days; it keeps its own expiry. Better Auth sets ctx.context.session to the session it refreshes.
              before: async (data, ctx) => {
                const current = ctx?.context.session?.session as { expiresAt: Date; impersonatedBy?: string | null } | undefined;
                if ('expiresAt' in data && current?.impersonatedBy) return { data: { expiresAt: current.expiresAt } };
              },
            },
            delete: {
              before: async (session, ctx) => {
                const by = (session as { impersonatedBy?: string | null }).impersonatedBy;
                if (ctx?.path === '/admin/stop-impersonating' && by) audit('stop_impersonating', by, session.userId);
                if (ctx?.path === '/admin/revoke-user-session') {
                  await revokeUserTokens(ctx.context, session.userId);
                  deletePendingCodes(ctx.context, session.userId);
                }
              },
            },
          },
        },
      },
    }),
    hooks: {
      before: [
        {
          matcher: (ctx) => ctx.path !== undefined && refusedWhenImpersonated(ctx.path),
          handler: createAuthMiddleware(async (ctx) => {
            const token = await ctx.getSignedCookie(ctx.context.authCookies.sessionToken.name, ctx.context.secret);
            const found = token ? await ctx.context.internalAdapter.findSession(token) : null;
            if ((found?.session as { impersonatedBy?: string | null } | undefined)?.impersonatedBy) {
              throw new APIError('FORBIDDEN', { code: 'IMPERSONATED_SESSION', message: "An impersonated session can't do this." });
            }
          }),
        },
        {
          // Never reachable over HTTP: the router always passes the request.
          matcher: (ctx) => ctx.path !== undefined && AS_USER_PATHS.has(ctx.path) && ctx.request === undefined,
          handler: createAuthMiddleware(async (ctx) => {
            const userId = await actingAs.get();
            const user = userId ? await ctx.context.internalAdapter.findUserById(userId) : null;
            if (!user) return;
            const now = new Date();
            const session = { id: `mcp-${user.id}`, token: '', userId: user.id, createdAt: now, updatedAt: now, expiresAt: new Date(now.getTime() + 60_000) };
            // Inside a caller's transaction (MCP audits its write inside one), the endpoint's own queries join it: Better
            // Auth's SSO routes use the plain adapter, which would otherwise wait on the transaction forever.
            const adapter = await getCurrentAdapter(ctx.context.adapter);
            return { context: { context: { session: { session, user }, adapter } } };
          }),
        },
      ],
      after: [
        {
          matcher: (ctx) => ctx.path !== undefined && REVOKES_TOKENS.has(ctx.path),
          handler: createAuthMiddleware(async (ctx: HookContext) => {
            if (isAPIError(ctx.context.returned) || typeof ctx.body?.userId !== 'string') return;
            await revokeUserTokens(ctx.context, ctx.body.userId);
            deletePendingCodes(ctx.context, ctx.body.userId); // a code issued just before could otherwise still be exchanged
          }),
        },
      ],
    },
  };
}

/** Better Auth's organization and admin plugins, and the glue above. Added to authOptions().plugins. */
export function orgAdminPlugins({ config, db }: AuthDeps, deliver: Deliver): Plugin[] {
  return [
    organization({
      // M4a: an organization's SSO providers would outlive it (no foreign key), with no owner left to delete them.
      organizationHooks: {
        beforeDeleteOrganization: async ({ organization: org }) => {
          if (db.prepare('SELECT 1 FROM ssoProvider WHERE organizationId = ?').get(org.id)) {
            throw new APIError('BAD_REQUEST', { code: 'ORGANIZATION_HAS_SSO_PROVIDERS', message: 'This organization has SSO providers: delete its SSO providers first.' });
          }
        },
      },
      // Organizations are made by an agent (MCP create_org, a server-side call Better Auth treats as a system action).
      allowUserToCreateOrganization: false,
      // Accepting needs a verified email that matches the invitation (also Better Auth's default here; made explicit).
      requireEmailVerificationOnInvitation: true,
      // Queued until the invitation commits (MCP invite_member writes it inside its audited transaction), so a
      // rolled-back invitation is never emailed. Outside a transaction it is queued at once.
      sendInvitationEmail: ({ id, email, role, organization: org, inviter }) =>
        queueAfterTransactionHook(async () => deliver('invitation', {
          to: email,
          subject: 'You are invited to join an organization on AuthWAPI',
          text:
            `${inviter.user.email} invited you to join the organization "${org.name}" as ${role}. To accept, sign in with this ` +
            `email address and open:\n\n${config.baseUrl.origin}${ACCEPT_INVITATION_PAGE}?id=${id}\n\nIf you don't know them, ignore this email.`,
        })),
    }),
    adminPlugin(),
    orgAdminGlue(dataPaths(path.resolve(config.dataDir)).audit),
  ];
}

/** Better Auth's admin plugin, with its two ban routes made atomic with the ban operation (inBanTransaction). */
function adminPlugin(): Plugin {
  const plugin = admin({ impersonationSessionDuration: IMPERSONATION_SECONDS });
  const endpoints = plugin.endpoints as unknown as Record<string, Endpoint>;
  endpoints.banUser = inBanTransaction(endpoints.banUser);
  endpoints.adminUpdateUser = inBanTransaction(endpoints.adminUpdateUser);
  return plugin;
}
