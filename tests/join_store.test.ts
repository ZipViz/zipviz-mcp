import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createPrivateKey, createPublicKey } from "node:crypto";
import { chmod, lstat, mkdtemp, readFile, readdir, rm, symlink, writeFile, mkdir, link } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { JoinStore } from "../src/lib/join-store.js";

// Public deterministic TEST-ONLY seed. All keys live in disposable test roots.
const key = createPrivateKey({ key: Buffer.concat([
  Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.alloc(32, 0x11),
]), type: "pkcs8", format: "der" });
const publicKey = (value: ReturnType<typeof createPrivateKey>) => createPublicKey(value).export({ type: "spki", format: "der" }).toString("hex");
const id = "00000000-0000-4000-8000-000000000001";
const domain = "fixture-1234.z.viz";

describe("private pending join store (synthetic fixtures only)", () => {
  let temporary: string;
  let root: string;
  let store: JoinStore;
  const metadata = { attempts: [{ request_b64url: "e30", request_digest: "a".repeat(64), issued_at_ms: 1793000000000 }] };
  beforeEach(async () => {
    temporary = await mkdtemp(join(tmpdir(), "join-store-"));
    root = join(temporary, "keys");
    store = new JoinStore(root);
  });
  afterEach(async () => { vi.restoreAllMocks(); await rm(temporary, { recursive: true, force: true }); });

  it("creates owner-only pending keys and metadata without leaking material", async () => {
    await store.create(id, key);
    await store.write(id, metadata);
    expect((await lstat(root)).mode & 0o777).toBe(0o700);
    expect((await lstat(join(root, "pending"))).mode & 0o777).toBe(0o700);
    for (const ext of ["key", "json"]) {
      const stat = await lstat(join(root, "pending", `${id}.${ext}`));
      expect(stat.mode & 0o777).toBe(0o600);
      expect(stat.uid).toBe(process.getuid!());
    }
    expect(publicKey(await store.readKey(id))).toBe(publicKey(key));
    expect(await store.read(id)).toEqual(metadata);
  });

  it("replaces metadata atomically and leaves no temporary files", async () => {
    await store.write(id, metadata);
    const second = { attempts: [...metadata.attempts, { ...metadata.attempts[0], issued_at_ms: 1793000301000 }] };
    await store.write(id, second);
    expect(await store.read(id)).toEqual(second);
    expect(await readdir(join(root, "pending"))).toEqual([`${id}.json`]);
  });

  it("does not overwrite an existing pending key", async () => {
    await store.create(id, key);
    const original = await readFile(join(root, "pending", `${id}.key`));
    await expect(store.create(id, key)).rejects.toMatchObject({ code: "E_JOIN_EXISTS" });
    expect(await readFile(join(root, "pending", `${id}.key`))).toEqual(original);
  });

  it.each(["../escape", "DEFAULT", "00000000-0000-0000-8000-000000000001", "00000000-0000-4000-C000-000000000001", "fixture.z.viz"])("refuses unsafe pending ID %s before writing", async (invalid) => {
    await expect(store.create(invalid, key)).rejects.toMatchObject({ code: "E_JOIN_STORE" });
    expect(await readdir(temporary)).toEqual([]);
  });

  it("refuses a permissive root without silently chmodding it", async () => {
    await mkdir(root, { mode: 0o755 });
    await chmod(root, 0o755);
    await expect(store.create(id, key)).rejects.toMatchObject({ code: "E_JOIN_STORE" });
    expect((await lstat(root)).mode & 0o777).toBe(0o755);
    expect(await readdir(root)).toEqual([]);
  });

  it("refuses a writable parent even when the key directory is private", async () => {
    await mkdir(root, { mode: 0o700 });
    await chmod(temporary, 0o777);
    await expect(store.create(id, key)).rejects.toMatchObject({ code: "E_JOIN_STORE" });
    expect((await lstat(temporary)).mode & 0o777).toBe(0o777);
    expect((await lstat(root)).mode & 0o777).toBe(0o700);
    expect(await readdir(root)).toEqual([]);
  });

  it("refuses symlink root ancestors and pending directories", async () => {
    const actual = join(temporary, "actual");
    await mkdir(actual, { mode: 0o700 });
    await symlink(actual, root);
    await expect(store.create(id, key)).rejects.toMatchObject({ code: "E_JOIN_STORE" });
    await rm(root);
    await mkdir(root, { mode: 0o700 });
    await symlink(actual, join(root, "pending"));
    await expect(store.write(id, metadata)).rejects.toMatchObject({ code: "E_JOIN_STORE" });
    expect(await readdir(actual)).toEqual([]);
  });

  it.each(["key", "json"])("refuses permissive or linked %s files", async (ext) => {
    await store.create(id, key);
    await store.write(id, metadata);
    const path = join(root, "pending", `${id}.${ext}`);
    await chmod(path, 0o644);
    const read = () => ext === "key" ? store.readKey(id) : store.read(id);
    await expect(read()).rejects.toMatchObject({ code: "E_JOIN_STORE" });
    await chmod(path, 0o600);
    await link(path, join(temporary, "outside"));
    await expect(read()).rejects.toMatchObject({ code: "E_JOIN_STORE" });
    if (ext === "json") await expect(store.write(id, {})).rejects.toMatchObject({ code: "E_JOIN_STORE" });
  });

  it.each(["key", "json"])("never follows a %s symlink", async (ext) => {
    await store.create(id, key);
    await store.write(id, metadata);
    const path = join(root, "pending", `${id}.${ext}`);
    const original = await readFile(path);
    await rm(path);
    const outside = join(temporary, "outside");
    await writeFile(outside, original, { mode: 0o600 });
    await symlink(outside, path);
    await expect(ext === "key" ? store.readKey(id) : store.read(id)).rejects.toMatchObject({ code: "E_JOIN_STORE" });
    if (ext === "json") await expect(store.write(id, {})).rejects.toMatchObject({ code: "E_JOIN_STORE" });
    expect(await readFile(outside)).toEqual(original);
  });

  it("bounds metadata input and output and hides local paths in errors", async () => {
    await expect(store.write(id, { value: "x".repeat(65536) })).rejects.toMatchObject({ code: "E_JOIN_STORE" });
    await store.write(id, metadata);
    await writeFile(join(root, "pending", `${id}.json`), "x".repeat(65537));
    await expect(store.read(id)).rejects.toMatchObject({ code: "E_JOIN_STORE" });
    try { await store.readKey(id); } catch (error) {
      expect(String(error)).not.toContain(temporary);
      expect(String(error)).not.toContain("ENOENT");
    }
  });

  it("adopts by no-clobber link then unlink and cleans metadata only after success", async () => {
    await store.create(id, key);
    await store.write(id, metadata);
    const pending = await lstat(join(root, "pending", `${id}.key`));
    const bots = join(temporary, "bots.json");
    await writeFile(bots, '{"identities":[]}', { mode: 0o600 });
    await store.adopt(id, domain);
    const adopted = await lstat(join(root, `${domain}.key`));
    expect(adopted.ino).toBe(pending.ino);
    expect(adopted.mode & 0o777).toBe(0o600);
    expect(await readdir(join(root, "pending"))).toEqual([]);
    expect(await readFile(bots, "utf8")).toBe('{"identities":[]}');
  });

  it("retains pending key and metadata on a destination conflict or hostile domain", async () => {
    await store.create(id, key);
    await store.write(id, metadata);
    const destination = join(root, `${domain}.key`);
    await writeFile(destination, "existing", { mode: 0o600 });
    await expect(store.adopt(id, domain)).rejects.toMatchObject({ code: "E_JOIN_EXISTS" });
    await expect(store.adopt(id, "../../escape")).rejects.toMatchObject({ code: "E_JOIN_STORE" });
    expect(await store.read(id)).toEqual(metadata);
    expect(publicKey(await store.readKey(id))).toBe(publicKey(key));
    expect(await readFile(destination, "utf8")).toBe("existing");
  });

  it("recovers an interrupted link-before-unlink adoption without clobbering", async () => {
    await store.create(id, key);
    await store.write(id, metadata);
    await link(join(root, "pending", `${id}.key`), join(root, `${domain}.key`));
    expect(publicKey(await store.readKey(id))).toBe(publicKey(key));
    await store.adopt(id, domain);
    expect((await lstat(join(root, `${domain}.key`))).nlink).toBe(1);
    expect(await readdir(join(root, "pending"))).toEqual([]);
  });

  it("finishes metadata cleanup after an interrupted pending-key unlink", async () => {
    await store.create(id, key);
    await store.write(id, { ...metadata, adoption_domain: domain });
    const destination = join(root, `${domain}.key`);
    await link(join(root, "pending", `${id}.key`), destination);
    await rm(join(root, "pending", `${id}.key`));
    const before = await readFile(destination);
    const inode = (await lstat(destination)).ino;
    await expect(store.readKey(id)).rejects.toMatchObject({ code: "E_JOIN_STORE" });
    expect(publicKey(await store.readKey(id, domain))).toBe(publicKey(key));
    await store.adopt(id, domain, publicKey(key).slice(-64));
    expect(await readdir(join(root, "pending"))).toEqual([]);
    expect(await readFile(destination)).toEqual(before);
    expect((await lstat(destination)).ino).toBe(inode);
  });

  it("refuses cleanup for a different main key and preserves retained attempts", async () => {
    await store.write(id, { ...metadata, adoption_domain: domain });
    const otherKey = createPrivateKey({ key: Buffer.concat([
      Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.alloc(32, 0x22),
    ]), type: "pkcs8", format: "der" });
    const destination = join(root, `${domain}.key`);
    await writeFile(destination, otherKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
    const before = await readFile(destination);
    await expect(store.adopt(id, domain, publicKey(key).slice(-64))).rejects.toMatchObject({ code: "E_JOIN_STORE" });
    expect(await store.read(id)).toEqual({ ...metadata, adoption_domain: domain });
    expect(await readFile(destination)).toEqual(before);
    await expect(store.adopt(id, domain)).rejects.toMatchObject({ code: "E_JOIN_STORE" });
    await expect(store.readKey(id, "../escape")).rejects.toMatchObject({ code: "E_JOIN_STORE" });
  });

  it("refuses a symlink at the adoption target and preserves its referent", async () => {
    await store.create(id, key);
    await store.write(id, metadata);
    const outside = join(temporary, "outside");
    await writeFile(outside, "sentinel", { mode: 0o600 });
    await symlink(outside, join(root, `${domain}.key`));
    await expect(store.adopt(id, domain)).rejects.toMatchObject({ code: "E_JOIN_EXISTS" });
    expect(await store.read(id)).toEqual(metadata);
    expect(await readFile(outside, "utf8")).toBe("sentinel");
  });

  it("excludes a concurrent lock and releases it on errors", async () => {
    let release!: () => void;
    let entered!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const started = new Promise<void>((resolve) => { entered = resolve; });
    const first = store.withLock(id, async () => { entered(); await gate; return "first"; });
    await started;
    await expect(new JoinStore(root).withLock(id, async () => "second")).rejects.toMatchObject({ code: "E_JOIN_BUSY" });
    release();
    expect(await first).toBe("first");
    const applicationError = new Error("safe application failure");
    await expect(store.withLock(id, async () => { throw applicationError; })).rejects.toBe(applicationError);
    expect(await store.withLock(id, async () => "next")).toBe("next");
  });

  it("recovers a provably dead process lock and refuses ambiguous recovery", async () => {
    await store.write(id, metadata);
    const pid = 424242;
    // Deterministic OS liveness evidence; never signal any actual process.
    vi.spyOn(process, "kill").mockImplementation((observed, signal) => {
      expect(observed).toBe(pid);
      expect(signal).toBe(0);
      throw Object.assign(new Error("synthetic absent process"), { code: "ESRCH" });
    });
    await writeFile(join(root, "pending", `${id}.lock`), JSON.stringify({ pid, token: "test" }), { mode: 0o600 });
    expect(await store.withLock(id, async () => "restarted")).toBe("restarted");
    await writeFile(join(root, "pending", `${id}.lock`), "", { mode: 0o600 });
    await expect(store.withLock(id, async () => "unsafe")).rejects.toMatchObject({ code: "E_JOIN_BUSY" });
    expect(await store.read(id)).toEqual(metadata);
  });

  it("refuses an interrupted recovery guard without removing pending state", async () => {
    await store.write(id, metadata);
    vi.spyOn(process, "kill").mockImplementation(() => { throw Object.assign(new Error("synthetic absent process"), { code: "ESRCH" }); });
    await writeFile(join(root, "pending", `${id}.lock`), JSON.stringify({ pid: 424242 }), { mode: 0o600 });
    await writeFile(join(root, "pending", `.${id}.recovery`), "", { mode: 0o600 });
    await expect(store.withLock(id, async () => "unsafe")).rejects.toMatchObject({ code: "E_JOIN_BUSY" });
    expect(await store.read(id)).toEqual(metadata);
    expect(await readFile(join(root, "pending", `${id}.lock`), "utf8")).toBe(JSON.stringify({ pid: 424242 }));
  });

  it("refuses roots owned by a different operating-system user", async () => {
    await store.write(id, metadata);
    const uid = process.getuid!();
    vi.spyOn(process, "getuid").mockReturnValue(uid + 1);
    await expect(store.read(id)).rejects.toMatchObject({ code: "E_JOIN_STORE" });
    await expect(store.create(id, key)).rejects.toMatchObject({ code: "E_JOIN_STORE" });
  });
});
