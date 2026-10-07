import { useMemo } from 'react';
import { useSession } from '../../lib/session';
import { HealthView } from '../HealthPage';
import { useOrgData } from './shared';

/** Admins see (and can decrypt) every collection, so they can assess the organization's shared credentials. */
export function OrgHealthTab() {
  const { orgId } = useOrgData();
  const items = useSession((s) => s.items);
  const orgItems = useMemo(() => items.filter((i) => i.orgId === orgId), [items, orgId]);
  return <HealthView items={orgItems} scopeLabel="every shared item in this organization's collections" />;
}
