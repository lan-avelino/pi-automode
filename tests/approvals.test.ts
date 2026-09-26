import assert from "node:assert/strict";
import test from "node:test";
import { approvalSignature } from "../extensions/auto-mode.ts";

function bash(command: string): string {
	return JSON.stringify({ toolName: "bash", input: { command } });
}

function key(command: string): string | undefined {
	return approvalSignature(bash(command))?.key;
}

function assertSame(a: string, b: string) {
	assert.ok(key(a), `no signature for ${a}`);
	assert.equal(key(a), key(b), `${a}  vs  ${b}`);
}

function assertDifferent(a: string, b: string) {
	assert.ok(key(a), `no signature for ${a}`);
	assert.notEqual(key(a), key(b), `${a}  vs  ${b}`);
}

test("a session approval covers the same command with other numbers and option values", () => {
	assertSame(
		"journalctl -u nginx -n 50 --since=10m",
		"journalctl -u nginx -n 200 --since=1h",
	);
	assertSame(
		"tail -n 50 /var/log/app.log | grep error | head -20",
		"tail -n 100 /var/log/app.log | grep error | head -5",
	);
	assertSame(
		"timeout 25 ssh -o BatchMode=yes -o ConnectTimeout=15 web-1 'tail -n 50 /var/log/nginx/error.log'",
		"timeout 30 ssh -o BatchMode=yes -o ConnectTimeout=10 web-1 'tail -n 80 /var/log/nginx/error.log'",
	);
	assertSame(
		"ssh web-1 'sudo systemctl restart nginx'",
		"ssh web-1 'sudo systemctl restart nginx'",
	);
});

test("a session approval never widens to other targets, flags, commands, or hosts", () => {
	// Different non-numeric argument.
	assertDifferent("ssh web-1 'sudo systemctl restart nginx'", "ssh web-1 'sudo systemctl restart php-fpm'");
	assertDifferent("journalctl -u nginx -n 50", "journalctl -u sshd -n 50");
	assertDifferent("tail -n 50 /var/log/app.log | grep error", "tail -n 50 /var/log/app.log | grep warn");
	// Different or extra flags.
	assertDifferent("git push origin feature/x", "git push --force origin feature/x");
	assertDifferent("ssh web-1 'ls /srv'", "ssh -A web-1 'ls /srv'");
	// A different chain shape, including an appended command.
	assertDifferent("systemctl status nginx", "systemctl status nginx && rm -rf /srv");
	assertDifferent("systemctl status nginx", "rm -rf /srv; systemctl status nginx");
	// Different redirect target.
	assertDifferent("curl -s http://localhost:8080/metrics > /tmp/m.txt", "curl -s http://localhost:8080/metrics > /etc/passwd");
	// Different host, or a different remote command on the same host.
	assertDifferent("ssh web-1 'uptime'", "ssh web-2 'uptime'");
	assertDifferent("ssh web-1 'uptime'", "ssh web-1 'reboot'");
});

test("numbers that name a target never vary", () => {
	// PIDs, modes, owners, and ports are exact even after a flag.
	assertDifferent("kill -9 1234", "kill -9 1");
	assertDifferent("chmod 755 ./deploy.sh", "chmod 4755 ./deploy.sh");
	assertDifferent("chown -R 1000 /srv/app", "chown -R 0 /srv/app");
	// A wrapper such as sudo does not hide the command.
	assertDifferent("sudo chmod -R 755 /srv/app", "sudo chmod -R 4755 /srv/app");
	assertDifferent("ssh web-1 'sudo kill -9 1234'", "ssh web-1 'sudo kill -9 1'");
	assertDifferent("sudo ufw allow 443", "sudo ufw allow 22");
	// A bare positional number is a target too.
	assertDifferent("docker stop 3f2a 1", "docker stop 3f2a 2");
	assertDifferent("git checkout 1234", "git checkout 5678");
});

test("heredocs and nested shells get no pattern", () => {
	assert.equal(key("sudo tee /etc/nginx/conf.d/app.conf <<'EOF'\nserver {}\nEOF"), undefined);
	assert.equal(key("bash -c 'systemctl restart nginx'"), undefined);
	assert.equal(key("ssh web-1 \"sh -c 'systemctl restart nginx'\""), undefined);
	assert.equal(key("eval 'systemctl restart nginx'"), undefined);
});

test("approvalSignature describes the pattern with numbers and option values elided", () => {
	assert.equal(
		approvalSignature(bash("tail -n 50 /var/log/app.log | grep error | head -20"))?.description,
		"tail -n <n> /var/log/app.log | grep error | head <n>",
	);
	assert.equal(
		approvalSignature(bash("timeout 25 ssh -o ConnectTimeout=15 web-1 'journalctl -u nginx --since=10m' > /tmp/j.txt"))
			?.description,
		"timeout <n> ssh -o ConnectTimeout=<n> web-1 'journalctl -u nginx --since=…' > /tmp/j.txt",
	);
});

test("approvalSignature offers no pattern for actions it cannot pin down", () => {
	for (const command of [
		"ls $(pwd)",
		"echo \"$HOME\"",
		"ls 'unterminated",
		"ssh web-1 'ssh web-2 uptime'",
		"ssh web-1",
		"",
	]) {
		assert.equal(approvalSignature(bash(command)), undefined, command);
	}
	assert.equal(approvalSignature(JSON.stringify({ toolName: "write", input: { path: "a" } })), undefined);
	assert.equal(approvalSignature("not json"), undefined);
});
