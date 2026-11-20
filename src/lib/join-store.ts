import { constants, type Stats } from "node:fs";
import { open, mkdir, lstat, unlink, link, rename, readdir } from "node:fs/promises";
import { createPrivateKey, createPublicKey, randomUUID, type KeyObject } from "node:crypto";
import { homedir } from "node:os";
import { dirname, join, parse, resolve } from "node:path";

export const JOIN_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const JOIN_DOMAIN = /^[a-z0-9-]{1,20}\.z\.viz$/;
const MAX_METADATA_BYTES = 65536;
const MAX_KEY_BYTES = 4096;

export class JoinStoreError extends Error {
  constructor(readonly code: "E_JOIN_STORE" | "E_JOIN_EXISTS" | "E_JOIN_BUSY") {
    super(code === "E_JOIN_EXISTS" ? "A local key already exists." : code === "E_JOIN_BUSY"
      ? "This pending request is already in use." : "The private local join store is unavailable or unsafe.");
    this.name = "JoinStoreError";
  }
}

function fail(): never { throw new JoinStoreError("E_JOIN_STORE"); }
function validId(id: string): void { if (!JOIN_ID.test(id)) fail(); }
function enoent(error: unknown): boolean { return (error as NodeJS.ErrnoException)?.code === "ENOENT"; }
function exists(error: unknown): boolean { return (error as NodeJS.ErrnoException)?.code === "EEXIST"; }
function sameFile(a: Stats, b: Stats): boolean { return a.dev === b.dev && a.ino === b.ino; }
function owner(stat: Stats): boolean { return typeof process.getuid === "function" && stat.uid === process.getuid(); }
function safeFile(stat: Stats, links = 1): void {
  if (!stat.isFile() || !owner(stat) || (stat.mode & 0o777) !== 0o600 || stat.nlink !== links) fail();
}
function rawPublicKey(key: KeyObject): string {
  return createPublicKey(key).export({ type: "spki", format: "der" }).subarray(-32).toString("hex");
}

/** Private pending state; callers validate closed metadata and serialize mutations.
 * No method opens bots.json or modifies any bot's identity grants.
 */
export class JoinStore {
  readonly root: string;
  private readonly pending: string;

  constructor(root = join(homedir(), ".zipviz", "keys")) {
    this.root = resolve(root);
    this.pending = join(this.root, "pending");
  }

  private path(id: string, extension: "key" | "json" | "lock"): string {
    validId(id);
    return join(this.pending, `${id}.${extension}`);
  }

  private async directories(): Promise<void> {
    // Never follow an ancestor symlink. Newly created private ancestors use 0700;
    // the shared ancestors (e.g. /tmp) need not themselves be private.
    let cursor = parse(this.root).root;
    for (const segment of this.root.slice(cursor.length).split("/").filter(Boolean)) {
      cursor = join(cursor, segment);
      try { await mkdir(cursor, { mode: 0o700 }); } catch (error) { if (!exists(error)) throw error; }
      const stat = await lstat(cursor);
      if (!stat.isDirectory() || stat.isSymbolicLink()) fail();
    }
    const parentStat = await lstat(dirname(this.root));
    if (!owner(parentStat) || (parentStat.mode & 0o022) !== 0) fail();
    const rootStat = await lstat(this.root);
    if (!owner(rootStat) || (rootStat.mode & 0o777) !== 0o700) fail();
    try { await mkdir(this.pending, { mode: 0o700 }); } catch (error) { if (!exists(error)) throw error; }
    const pendingStat = await lstat(this.pending);
    if (!pendingStat.isDirectory() || !owner(pendingStat) || (pendingStat.mode & 0o777) !== 0o700) fail();
  }

  private async syncDirectory(path: string): Promise<void> {
    const handle = await open(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    try { await handle.sync(); } finally { await handle.close(); }
  }

  private async readFile(path: string, limit: number, links = 1): Promise<Buffer> {
    const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    try {
      const stat = await handle.stat();
      safeFile(stat, links);
      if (stat.size > limit) fail();
      const bytes = Buffer.alloc(limit + 1);
      let total = 0;
      while (total <= limit) {
        const { bytesRead } = await handle.read(bytes, total, bytes.length - total, null);
        if (bytesRead === 0) break;
        total += bytesRead;
      }
      if (total > limit || !sameFile(stat, await lstat(path))) fail();
      return bytes.subarray(0, total);
    } finally { await handle.close(); }
  }

  private async guarded<T>(work: () => Promise<T>): Promise<T> {
    try { return await work(); } catch (error) {
      if (error instanceof JoinStoreError) throw error;
      throw new JoinStoreError("E_JOIN_STORE");
    }
  }

  async create(id: string, key: KeyObject): Promise<void> {
    return this.guarded(async () => {
      validId(id);
      if (key.type !== "private" || key.asymmetricKeyType !== "ed25519") fail();
      await this.directories();
      let handle;
      try {
        handle = await open(this.path(id, "key"), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      } catch (error) {
        if (exists(error)) throw new JoinStoreError("E_JOIN_EXISTS");
        throw error;
      }
      try {
        await handle.writeFile(key.export({ type: "pkcs8", format: "pem" }));
        await handle.sync();
      } finally { await handle.close(); }
      await this.syncDirectory(this.pending);
    });
  }

  async reserveMetadata(id: string): Promise<void> {
    return this.guarded(async () => {
      await this.directories();
      let handle;
      try {
        handle = await open(this.path(id, "json"), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      } catch (error) {
        if (exists(error)) throw new JoinStoreError("E_JOIN_EXISTS");
        throw error;
      }
      try { await handle.writeFile("{}"); await handle.sync(); } finally { await handle.close(); }
      await this.syncDirectory(this.pending);
    });
  }

  async readKey(id: string, adoptedDomain?: string): Promise<KeyObject> {
    return this.guarded(async () => {
      if (adoptedDomain !== undefined && !JOIN_DOMAIN.test(adoptedDomain)) fail();
      await this.directories();
      let path = this.path(id, "key");
      let stat: Stats;
      try { stat = await lstat(path); } catch (error) {
        if (!enoent(error) || adoptedDomain === undefined) throw error;
        // The caller supplies this only from validated durable adoption
        // metadata, then checks its public key and current registry identity.
        path = join(this.root, `${adoptedDomain}.key`);
        stat = await lstat(path);
        safeFile(stat);
      }
      let links = 1;
      if (stat.nlink === 2) {
        // Recover the link-before-unlink crash window only if the second link
        // is an actual validated main-store domain entry pointing to this key.
        let matches = 0;
        for (const entry of await readdir(this.root)) {
          if (!entry.endsWith(".key") || !JOIN_DOMAIN.test(entry.slice(0, -4))) continue;
          const candidate = await lstat(join(this.root, entry));
          if (sameFile(stat, candidate) && candidate.isFile()) matches++;
        }
        if (matches !== 1) fail();
        links = 2;
      }
      const key = createPrivateKey({ key: await this.readFile(path, MAX_KEY_BYTES, links), format: "pem" });
      if (key.asymmetricKeyType !== "ed25519") fail();
      return key;
    });
  }

  async read(id: string): Promise<unknown> {
    return this.guarded(async () => {
      await this.directories();
      return JSON.parse((await this.readFile(this.path(id, "json"), MAX_METADATA_BYTES)).toString("utf8")) as unknown;
    });
  }

  async write(id: string, metadata: unknown): Promise<void> {
    return this.guarded(async () => {
      const destination = this.path(id, "json");
      const bytes = Buffer.from(JSON.stringify(metadata), "utf8");
      if (bytes.length > MAX_METADATA_BYTES) fail();
      await this.directories();
      try { safeFile(await lstat(destination)); } catch (error) { if (!enoent(error)) throw error; }
      const temporary = join(this.pending, `.${id}.${randomUUID()}.tmp`);
      const handle = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      try {
        await handle.writeFile(bytes);
        await handle.sync();
        await handle.close();
        // Recheck the destination before replacing it. Symlinks and public files
        // are configuration errors, never silently repaired.
        try { safeFile(await lstat(destination)); } catch (error) { if (!enoent(error)) throw error; }
        await rename(temporary, destination);
        await this.syncDirectory(this.pending);
      } finally {
        await handle.close().catch(() => {});
        await unlink(temporary).catch((error: unknown) => { if (!enoent(error)) throw error; });
      }
    });
  }

  async removeMetadata(id: string): Promise<void> {
    return this.guarded(async () => {
      await this.directories();
      const path = this.path(id, "json");
      try { safeFile(await lstat(path)); } catch (error) { if (enoent(error)) return; throw error; }
      await unlink(path);
      await this.syncDirectory(this.pending);
    });
  }

  async adopt(id: string, domain: string, expectedPublicKey?: string): Promise<void> {
    return this.guarded(async () => {
      if (!JOIN_DOMAIN.test(domain)) fail();
      if (expectedPublicKey !== undefined && !/^[0-9a-f]{64}$/.test(expectedPublicKey)) fail();
      await this.directories();
      const source = this.path(id, "key");
      const destination = join(this.root, `${domain}.key`);
      let sourceStat: Stats;
      try { sourceStat = await lstat(source); } catch (error) {
        if (!enoent(error) || expectedPublicKey === undefined) throw error;
        // Finish only the cleanup after a crash beyond pending-key unlink.
        // The validated main key is never rewritten or replaced.
        const recovered = await this.readKey(id, domain);
        if (rawPublicKey(recovered) !== expectedPublicKey) fail();
        await this.syncDirectory(this.root);
        await this.removeMetadata(id);
        await this.syncDirectory(this.pending);
        return;
      }
      const key = await this.readKey(id);
      if (expectedPublicKey !== undefined && rawPublicKey(key) !== expectedPublicKey) fail();
      // A second link is permitted only when an earlier adoption linked this
      // exact destination before crashing. An unrelated hard link is refused.
      if (sourceStat.nlink === 2) {
        safeFile(sourceStat, 2);
        const destinationStat = await lstat(destination);
        safeFile(destinationStat, 2);
        if (!sameFile(sourceStat, destinationStat)) fail();
      } else {
        safeFile(sourceStat);
        await this.readFile(source, MAX_KEY_BYTES);
        try { await link(source, destination); } catch (error) {
          if (exists(error)) throw new JoinStoreError("E_JOIN_EXISTS");
          throw error;
        }
        const linked = await lstat(destination);
        if (!sameFile(sourceStat, linked) || linked.isSymbolicLink()) fail();
      }
      await this.syncDirectory(this.root);
      if (!sameFile(sourceStat, await lstat(source))) fail();
      await unlink(source);
      await this.syncDirectory(this.pending);
      await this.removeMetadata(id);
    });
  }

  async withLock<T>(id: string, work: () => Promise<T>): Promise<T> {
    let callbackError: { cause: unknown } | undefined;
    const result = await this.guarded(async () => {
      const path = this.path(id, "lock");
      await this.directories();
      let handle;
      try {
        handle = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      } catch (error) {
        if (!exists(error)) throw error;
        const observed = await lstat(path);
        const markerBytes = await this.readFile(path, 1024);
        let marker: unknown;
        try { marker = JSON.parse(markerBytes.toString("utf8")); }
        catch (cause) {
          if (cause instanceof SyntaxError) throw new JoinStoreError("E_JOIN_BUSY");
          throw cause;
        }
        if (typeof marker !== "object" || marker === null || Array.isArray(marker)) throw new JoinStoreError("E_JOIN_BUSY");
        const pid = (marker as { pid?: unknown }).pid;
        if (!Number.isSafeInteger(pid) || (pid as number) <= 0) throw new JoinStoreError("E_JOIN_BUSY");
        try {
          process.kill(pid as number, 0);
          throw new JoinStoreError("E_JOIN_BUSY");
        } catch (cause) {
          if ((cause as NodeJS.ErrnoException)?.code !== "ESRCH") throw new JoinStoreError("E_JOIN_BUSY");
        }
        // Serialize cooperative stale-lock recovery. If a recovery itself was
        // interrupted, this ambiguous guard is deliberately refused instead of
        // guessing. Same-user filesystem tampering is outside the store's lock
        // protocol; owner-only directories and inode checks narrow that race.
        const recoveryPath = join(this.pending, `.${id}.recovery`);
        let recovery;
        try {
          recovery = await open(recoveryPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
        } catch (cause) {
          if (exists(cause)) throw new JoinStoreError("E_JOIN_BUSY");
          throw cause;
        }
        try {
          if (!sameFile(observed, await lstat(path)) || !markerBytes.equals(await this.readFile(path, 1024))) {
            throw new JoinStoreError("E_JOIN_BUSY");
          }
          await unlink(path);
          handle = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
        } finally {
          await recovery.close();
          await unlink(recoveryPath);
        }
      }
      const held = await handle.stat();
      try {
        await handle.writeFile(JSON.stringify({ pid: process.pid, token: randomUUID() }));
        await handle.sync();
        await this.syncDirectory(this.pending);
        try { return await work(); } catch (cause) {
          callbackError = { cause };
          return undefined as T;
        }
      } finally {
        await handle.close();
        if (sameFile(held, await lstat(path))) await unlink(path);
        await this.syncDirectory(this.pending);
      }
    });
    if (callbackError) throw callbackError.cause;
    return result;
  }
}
