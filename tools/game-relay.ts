import { startRelay } from "../src/main/vpn/multipath/relay";

void startRelay().then((relay) => {
  process.stdout.write("Levik Game relay ready on loopback\n");
  for (const signal of ["SIGINT", "SIGTERM"] as const) process.once(signal, () => { void relay.close().then(() => process.exit(0)); });
}).catch(() => { process.stderr.write("Game relay failed to start\n"); process.exitCode = 1; });
