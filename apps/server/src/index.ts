import { buildApp } from './app';
import { loadConfig } from './config';
import { createPool } from './db';
import { migrate } from './migrations';
import { startLogStreaming } from './siem/worker';

async function main(): Promise<void> {
  const config = loadConfig();
  const db = createPool(config.DATABASE_URL);
  const app = await buildApp(config, db);
  await migrate(db, (m) => app.log.info(m));

  const stopStreaming = startLogStreaming(app);

  const shutdown = async (signal: string) => {
    app.log.info(`${signal} received, shutting down`);
    await stopStreaming();
    await app.close();
    await db.end();
    process.exit(0);
  };
  process.on('SIGINT', () => void shutdown('SIGINT'));
  process.on('SIGTERM', () => void shutdown('SIGTERM'));

  await app.listen({ host: config.HOST, port: config.PORT });
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
