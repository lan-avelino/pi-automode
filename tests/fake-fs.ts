import { basename, dirname, join } from "node:path";
import type { CreatedPathsFs, StatLike } from "../extensions/auto-mode/created-paths.ts";

type FakeNode = {
	kind: "file" | "folder" | "symlink" | "fifo";
	dev: number;
	ino: number;
	birthtimeMs: number;
	ctimeMs: number;
	size: number;
	nlink: number;
	target?: string;
};

function enoent(path: string): Error {
	return Object.assign(new Error(`ENOENT: ${path}`), { code: "ENOENT" });
}

/**
 * An in-memory filesystem with symlinks, hard links, inode numbers, and
 * birth and change times, for created-paths tests. Nodes are stored by real
 * path; a hard link stores the same node under two paths.
 */
export class FakeFs implements CreatedPathsFs {
	nodes = new Map<string, FakeNode>();
	clock = 1_000_000;
	private nextIno = 1;

	constructor() {
		this.nodes.set("/", this.node("folder"));
	}

	private node(kind: FakeNode["kind"], extra: Partial<FakeNode> = {}): FakeNode {
		return {
			kind,
			dev: 1,
			ino: this.nextIno++,
			birthtimeMs: this.clock,
			ctimeMs: this.clock,
			size: 0,
			nlink: 1,
			...extra,
		};
	}

	/** Advance the clock, so later creations have later birth times. */
	tick(ms = 10_000): void {
		this.clock += ms;
	}

	private add(path: string, node: FakeNode): void {
		const parent = this.nodes.get(this.realSync(dirname(path)));
		if (!parent || parent.kind !== "folder") throw enoent(dirname(path));
		this.nodes.set(join(this.realSync(dirname(path)), basename(path)), node);
	}

	mkdir(path: string, extra: Partial<FakeNode> = {}): this {
		this.add(path, this.node("folder", extra));
		return this;
	}

	write(path: string, size = 1, extra: Partial<FakeNode> = {}): this {
		const real = this.tryReal(path);
		const existing = real === undefined ? undefined : this.nodes.get(real);
		if (existing?.kind === "file") {
			existing.size = size;
			existing.ctimeMs = this.clock;
			return this;
		}
		this.add(path, this.node("file", { size, ...extra }));
		return this;
	}

	symlink(path: string, target: string): this {
		this.add(path, this.node("symlink", { target }));
		return this;
	}

	fifo(path: string): this {
		this.add(path, this.node("fifo"));
		return this;
	}

	/** Hard link: one node under two names. */
	link(existing: string, path: string): this {
		const node = this.nodes.get(this.realSync(existing))!;
		node.nlink += 1;
		node.ctimeMs = this.clock;
		this.add(path, node);
		return this;
	}

	/** Remove a path and everything below it. */
	rm(path: string): this {
		const real = join(this.realSync(dirname(path)), basename(path));
		for (const key of [...this.nodes.keys()]) {
			if (key === real || key.startsWith(`${real}/`)) {
				const node = this.nodes.get(key)!;
				node.nlink -= 1;
				this.nodes.delete(key);
			}
		}
		return this;
	}

	/** Rename, keeping birth times; change times move as on a real rename. */
	mv(from: string, to: string): this {
		const realFrom = join(this.realSync(dirname(from)), basename(from));
		const realTo = join(this.realSync(dirname(to)), basename(to));
		for (const key of [...this.nodes.keys()]) {
			if (key === realFrom || key.startsWith(`${realFrom}/`)) {
				const node = this.nodes.get(key)!;
				this.nodes.delete(key);
				node.ctimeMs = this.clock;
				this.nodes.set(realTo + key.slice(realFrom.length), node);
			}
		}
		return this;
	}

	/** Change metadata only, as chmod or an extended attribute would. */
	touchCtime(path: string): this {
		this.nodes.get(this.realSync(path))!.ctimeMs = this.clock;
		return this;
	}

	private tryReal(path: string): string | undefined {
		try {
			return this.realSync(path);
		} catch {
			return undefined;
		}
	}

	private realSync(path: string, depth = 0): string {
		if (depth > 40) throw new Error("ELOOP");
		let current = "/";
		for (const segment of path.split("/").filter(Boolean)) {
			const next = join(current, segment);
			const node = this.nodes.get(next);
			if (!node) throw enoent(next);
			current = node.kind === "symlink"
				? this.realSync(node.target!.startsWith("/") ? node.target! : join(current, node.target!), depth + 1)
				: next;
		}
		return current;
	}

	async realpath(path: string): Promise<string> {
		return this.realSync(path);
	}

	async lstat(path: string): Promise<StatLike> {
		const key = join(this.realSync(dirname(path)), basename(path));
		const node = this.nodes.get(path === "/" ? "/" : key);
		if (!node) throw enoent(path);
		return {
			dev: node.dev,
			ino: node.ino,
			nlink: node.nlink,
			size: node.size,
			birthtimeMs: node.birthtimeMs,
			ctimeMs: node.ctimeMs,
			isFile: () => node.kind === "file",
			isDirectory: () => node.kind === "folder",
			isSymbolicLink: () => node.kind === "symlink",
		};
	}

	async readdir(path: string): Promise<string[]> {
		const real = this.realSync(path);
		const prefix = real === "/" ? "/" : `${real}/`;
		return [...this.nodes.keys()]
			.filter((key) => key.startsWith(prefix) && key !== real && !key.slice(prefix.length).includes("/"))
			.map((key) => key.slice(prefix.length));
	}
}
