-- Hand-written, not generated (scripts/new-migration.ts only writes what Better Auth's schema lacks): an
-- organization that has SSO providers always keeps an owner, enforced here so that two removals or demotions running
-- at once can't both pass a check. A user's deletion is covered too: their memberships cascade into these triggers.
-- src/orgs.ts turns 'sso_org_needs_owner' into a readable error.
CREATE TRIGGER member_sso_org_needs_owner_delete BEFORE DELETE ON member
WHEN (',' || replace(OLD.role, ' ', '') || ',') LIKE '%,owner,%'
  AND EXISTS (SELECT 1 FROM ssoProvider p WHERE p.organizationId = OLD.organizationId)
  AND NOT EXISTS (SELECT 1 FROM member o WHERE o.organizationId = OLD.organizationId AND o.id != OLD.id
                  AND (',' || replace(o.role, ' ', '') || ',') LIKE '%,owner,%')
BEGIN
  SELECT RAISE(ABORT, 'sso_org_needs_owner');
END;

CREATE TRIGGER member_sso_org_needs_owner_update BEFORE UPDATE OF role ON member
WHEN (',' || replace(OLD.role, ' ', '') || ',') LIKE '%,owner,%'
  AND (',' || replace(NEW.role, ' ', '') || ',') NOT LIKE '%,owner,%'
  AND EXISTS (SELECT 1 FROM ssoProvider p WHERE p.organizationId = OLD.organizationId)
  AND NOT EXISTS (SELECT 1 FROM member o WHERE o.organizationId = OLD.organizationId AND o.id != OLD.id
                  AND (',' || replace(o.role, ' ', '') || ',') LIKE '%,owner,%')
BEGIN
  SELECT RAISE(ABORT, 'sso_org_needs_owner');
END;
