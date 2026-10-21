import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  Device,
  IncomingResult,
  IncomingTransfer,
  PairingPrompt,
  PairingResult,
  Transfer,
  TransferResult,
} from "./ipc";

/** Subscribe to a backend event, resolving to an unlisten function. */
export function subscribe<T>(
  name: string,
  handler: (payload: T) => void,
): Promise<UnlistenFn> {
  return listen<T>(name, (event) => handler(event.payload));
}

export type {
  Device,
  IncomingResult,
  IncomingTransfer,
  PairingPrompt,
  PairingResult,
  Transfer,
  TransferResult,
};

/** Format the 8-digit code as two groups of four for cross-screen comparison. */
export function formatCode(code: string): string {
  return code.replace(/(\d{4})(?=\d)/, "$1 ");
}
