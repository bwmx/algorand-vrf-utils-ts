function assertBytes(value: Uint8Array, name: string): void {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError(`${name} must be a Uint8Array`);
  }
}

export function bytesToHex(value: Uint8Array): string {
  assertBytes(value, "value");
  return Buffer.from(value).toString("hex");
}

export function hexToBytes(value: string): Uint8Array {
  if (typeof value !== "string" || value.length % 2 !== 0 || !/^[0-9a-f]*$/iu.test(value)) {
    throw new TypeError("value must be an even-length hexadecimal string");
  }
  return new Uint8Array(Buffer.from(value, "hex"));
}

export function bytesToBase64(value: Uint8Array): string {
  assertBytes(value, "value");
  return Buffer.from(value).toString("base64");
}

export function base64ToBytes(value: string): Uint8Array {
  if (
    typeof value !== "string" ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value)
  ) {
    throw new TypeError("value must be canonical base64");
  }
  return new Uint8Array(Buffer.from(value, "base64"));
}
