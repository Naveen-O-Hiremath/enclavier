import { createPool } from '../db';
import { migrate } from '../migrations';

const url = process.env.DATABASE_URL;
if (!url) {
  console.error('DATABASE_URL is required');
  process.exit(1);
}
const db = createPool(url);
migrate(db, console.log)
  .then(() => console.log('Database is up to date'))
  .catch((e) => {
    console.error(e);
    process.exitCode = 1;
  })
  .finally(() => db.end());
