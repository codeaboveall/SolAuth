import type { Store } from "./types.js";

export class InMemoryStore<T> implements Store<T> {
  private m = new Map<string, T>();

  get(key: string): T | undefined {
    return this.m.get(key);
  }

  set(key: string, value: T): void {
    this.m.set(key, value);
  }

  delete(key: string): void {
    this.m.delete(key);
  }
}
