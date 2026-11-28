import type { TrafficSample } from "../api/tauri";

export const TRAFFIC_HISTORY_CAPACITY = 600;

export const EMPTY_TRAFFIC: TrafficSample = {
  up_bps: 0,
  down_bps: 0,
  up_total_bytes: 0,
  down_total_bytes: 0,
  connections: 0,
  tunnel_connections: 0,
  memory_mb: 0,
  timestamp_ms: 0,
};

/**
 * Fixed-length 600-point Float64Array ring buffer (1s x 600 = full 10 minutes).
 * Zero allocations on push; zero GC churn during steady-state streaming.
 */
export class TrafficRingBuffer {
  readonly capacity: number;
  readonly up: Float64Array;
  readonly down: Float64Array;
  readonly ts: Float64Array;
  private head = 0;
  private count = 0;

  constructor(capacity = TRAFFIC_HISTORY_CAPACITY) {
    this.capacity = capacity;
    this.up = new Float64Array(capacity);
    this.down = new Float64Array(capacity);
    this.ts = new Float64Array(capacity);
  }

  get length(): number {
    return this.count;
  }

  push(upBps: number, downBps: number, timestampMs: number = Date.now()): void {
    const safeUp = Number.isFinite(upBps) && upBps > 0 ? upBps : 0;
    const safeDown = Number.isFinite(downBps) && downBps > 0 ? downBps : 0;
    this.up[this.head] = safeUp;
    this.down[this.head] = safeDown;
    this.ts[this.head] = timestampMs;
    this.head = (this.head + 1) % this.capacity;
    if (this.count < this.capacity) {
      this.count += 1;
    }
  }

  /** Logical index 0 = oldest retained point, length - 1 = newest point. */
  slotAt(logicalIndex: number): number {
    if (this.count < this.capacity) {
      return logicalIndex;
    }
    return (this.head + logicalIndex) % this.capacity;
  }

  upAt(logicalIndex: number): number {
    return this.up[this.slotAt(logicalIndex)];
  }

  downAt(logicalIndex: number): number {
    return this.down[this.slotAt(logicalIndex)];
  }

  tsAt(logicalIndex: number): number {
    return this.ts[this.slotAt(logicalIndex)];
  }

  clear(): void {
    this.head = 0;
    this.count = 0;
    this.up.fill(0);
    this.down.fill(0);
    this.ts.fill(0);
  }
}
