// Talk to the person at the terminal without touching stdout (which carries the
// token) or relying on stderr (the AWS CLI captures a credential_process's stderr).
// Uses /dev/tty when there is one, else stderr for messages and no prompts.

import { openSync, writeSync } from "node:fs";
import tty from "node:tty";

let fd;
try { fd = openSync("/dev/tty", "r+"); } catch { fd = undefined; }

export const interactive = fd !== undefined;

export function say(msg) {
  if (fd !== undefined) writeSync(fd, msg + "\n");
  else process.stderr.write(msg + "\n");
}

/** Read one line from the terminal without echoing it. */
export function promptHidden(question) {
  if (fd === undefined) return Promise.reject(new Error(`${question.replace(/:\s*$/, "")} is needed, but there is no terminal to ask on.`));
  const input = new tty.ReadStream(fd);
  input.setRawMode(true);
  writeSync(fd, question);
  return new Promise((resolve, reject) => {
    let value = "";
    const done = (err) => {
      input.setRawMode(false);
      input.removeAllListeners("data");
      input.pause();
      writeSync(fd, "\n");
      err ? reject(err) : resolve(value);
    };
    input.on("data", (buf) => {
      for (const ch of buf.toString("utf8")) {
        if (ch === "\r" || ch === "\n") return done();
        if (ch === "\u0003" || ch === "\u0004") return done(new Error("Cancelled."));
        if (ch === "\u007f" || ch === "\b") value = value.slice(0, -1);
        else if (ch >= " ") value += ch;
      }
    });
  });
}
