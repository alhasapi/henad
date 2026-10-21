import { invoke } from "@tauri-apps/api/core";

export type DeviceState = "online" | "offline";

export type Device = {
  id: string;
  name: string;
  state: DeviceState;
  trusted: boolean;
  fingerprint: string;
  address?: string | null;
  port?: number | null;
  last_seen?: string | null;
};

export type TransferState = "queued" | "active" | "complete" | "failed" | "cancelled";

export type Transfer = {
  id: string;
  device_name: string;
  file_name: string;
  bytes_done: number;
  bytes_total: number;
  speed_bps: number;
  state: TransferState;
  error?: string | null;
};

export type IdentityInfo = {
  device_id: string;
  name: string;
  fingerprint: string;
};

export type AppStatus = {
  discovery_error: string | null;
  port: number;
  protocol_version: number;
};

export type PairingPrompt = {
  device_id: string;
  device_name: string;
  code: string;
  expires_in_secs: number;
};

export type PairingResult = {
  device_id: string;
  ok: boolean;
  error: string | null;
};

export type TransferResult = {
  transfer_id: string;
  file_name: string;
  state: TransferState;
  error: string | null;
};

export const api = {
  listDevices: () => invoke<Device[]>("list_devices"),
  listTransfers: () => invoke<Transfer[]>("list_transfers"),
  localIdentity: () => invoke<IdentityInfo>("local_identity"),
  appStatus: () => invoke<AppStatus>("app_status"),
  startPairing: (deviceId: string) =>
    invoke<PairingPrompt>("start_pairing", { deviceId }),
  confirmPairing: (deviceId: string, accepted: boolean) =>
    invoke<void>("confirm_pairing", { deviceId, accepted }),
  cancelPairing: (deviceId: string) =>
    invoke<void>("cancel_pairing", { deviceId }),
  unpair: (deviceId: string) => invoke<void>("unpair_device", { deviceId }),
  sendFile: (deviceId: string, path: string) =>
    invoke<string>("send_file", { deviceId, path }),
  cancelTransfer: (transferId: string) =>
    invoke<void>("cancel_transfer", { transferId }),
};

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const exponent = Math.min(
    Math.floor(Math.log(bytes) / Math.log(1024)),
    units.length - 1,
  );
  const value = bytes / 1024 ** exponent;
  return `${value >= 10 || exponent === 0 ? Math.round(value) : value.toFixed(1)} ${units[exponent]}`;
}

export function formatSpeed(bytesPerSecond: number): string {
  return `${formatBytes(bytesPerSecond)}/s`;
}
