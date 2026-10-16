import { constants, setPriority } from "node:os";
import { GameMultipath } from "./client";
import { STATE_INTERVAL_MS, type DataPlaneEvent, type DataPlaneRequest } from "./dataPlane";
import type { ProbeMeasurement, ProbeTarget } from "./wire";

/** Electron utility process that owns every game packet: the VLESS loopback
 * listener, the relay paths and their timers. It runs at high priority, apart
 * from the UI and controller event loop, so their work and garbage collection
 * never delay a game datagram. Only main can talk to it (parentPort). */
const parent = process.parentPort;
if (!parent) throw new Error("Game data plane must run as an Electron utility process");
// HIGH_PRIORITY_CLASS on Windows needs no elevation; elsewhere it may be refused.
try { setPriority(0, constants.priority.PRIORITY_HIGH); } catch { /* Normal priority still works. */ }

const plane = new GameMultipath(false);
const emit = (event: DataPlaneEvent): void => parent.postMessage(event);
const measurements = new Map<number, (results: ProbeMeasurement[]) => void>();
let measureId = 0;
/** Direct measurements need the physical adapter helpers that live in main. */
const measureDirect = (targets: ProbeTarget[], signal: AbortSignal): Promise<ProbeMeasurement[]> => new Promise((resolve) => {
  const id = ++measureId; measurements.set(id, resolve);
  signal.addEventListener("abort", () => { if (measurements.delete(id)) { emit({ type: "measure-abort", id }); resolve([]); } }, { once: true });
  emit({ type: "measure", id, targets });
});

const publish = (): void => emit({ type: "state", snapshot: plane.snapshot(), runtime: plane.runtimeSnapshot(), qualities: plane.routeQualities(), idle: plane.idle() });
setInterval(publish, STATE_INTERVAL_MS);

async function call(request: Extract<DataPlaneRequest, { type: "call" }>): Promise<unknown> {
  switch (request.method) {
    case "listen": return plane.listen(request.args[0]);
    case "connect": {
      const [candidates, password, options] = request.args;
      if (!options) return plane.connect(candidates, password);
      const { measureDirect: direct, ...rest } = options;
      return plane.connect(candidates, password, direct ? { ...rest, measureDirect } : rest);
    }
    case "stop": { await plane.stop(); publish(); return null; }
    case "pauseNewFlowsIfIdle": return plane.pauseNewFlowsIfIdle();
  }
}

parent.on("message", (event: { data: DataPlaneRequest }) => {
  const request = event.data;
  if (request.type === "measured") { const resolve = measurements.get(request.id); measurements.delete(request.id); resolve?.(request.results); return; }
  if (request.type === "notify") {
    switch (request.method) {
      case "refreshMeasurements": plane.refreshMeasurements(); break;
      case "resumeNewFlows": plane.resumeNewFlows(); break;
      case "startCounting": plane.startCounting(); break;
      case "setPlaying": plane.setPlaying(request.args[0]); break;
      case "configure": plane.configure(request.args[0]); break;
      case "setPrimaryRoute": plane.setPrimaryRoute(request.args[0]); break;
    }
    publish(); return;
  }
  void call(request).then((value) => { publish(); emit({ type: "result", id: request.id, ok: true, value }); },
    () => emit({ type: "result", id: request.id, ok: false }));
});
emit({ type: "ready" });
publish();
