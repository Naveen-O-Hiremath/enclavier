import { verifyAuditChain } from '../audit';
import { createPool } from '../db';

const url = process.env.DATABASE_URL;
if (!url) {
  console.error('DATABASE_URL is required');
  process.exit(1);
}
const db = createPool(url);
verifyAuditChain(db)
  .then((r) => {
    if (r.ok) {
      console.log(`Audit chain intact: ${r.checked} events verified.`);
    } else {
      console.error(`AUDIT CHAIN BROKEN at event #${r.brokenAt}: ${r.reason} (${r.checked} events verified before it)`);
      process.exitCode = 2;
    }
  })
  .catch((e) => {
    console.error(e);
    process.exitCode = 1;
  })
  .finally(() => db.end());
