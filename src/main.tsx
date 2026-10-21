import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import "./styles.css";

type Device = { id: string; name: string; state: "online" | "offline"; fingerprint: string; last_seen?: string };
type Transfer = { id: string; device_name: string; file_name: string; bytes_done: number; bytes_total: number; state: string; speed_bps: number };

function App() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [transfers, setTransfers] = useState<Transfer[]>([]);
  const [message, setMessage] = useState("Looking for nearby devices…");
  const [pairing, setPairing] = useState<{ device: Device; code: string } | null>(null);
  const refresh = async () => { setDevices(await invoke<Device[]>("list_devices")); setTransfers(await invoke<Transfer[]>("list_transfers")); };
  useEffect(() => { refresh().catch(e => setMessage(String(e))); const id = setInterval(() => refresh().catch(() => {}), 1000); return () => clearInterval(id); }, []);
  const pair = async (device: Device) => setPairing({ device, code: await invoke<string>("start_pairing", { deviceId: device.id }) });
  const confirm = async () => { if (!pairing) return; await invoke("confirm_pairing", { deviceId: pairing.device.id, accepted: true }); setMessage(`${pairing.device.name} is now trusted.`); setPairing(null); refresh(); };
  const send = async (device: Device) => { const picked = await open({ multiple: false, directory: false, title: "Choose a file to send" }); if (typeof picked === "string") { await invoke("queue_transfer", { deviceId: device.id, path: picked }); setMessage(`Sending to ${device.name}`); refresh(); } };
  return <main><header><div><h1>Henad</h1><p>Private file sharing, on your local network.</p></div><span className="status">● Ready</span></header><p className="notice">{message}</p><section><h2>Nearby devices</h2>{devices.length === 0 ? <div className="empty">No devices found yet. Make sure both devices are on the same network and Henad is open.</div> : <div className="devices">{devices.map(d => <article className="device" key={d.id}><div><strong>{d.name}</strong><small><i className={d.state} /> {d.state} · {d.fingerprint}</small></div><div>{d.state === "online" && <button onClick={() => send(d)}>Send file</button>}<button className="secondary" onClick={() => pair(d)}>Pair</button></div></article>)}</div>}</section><section><h2>Transfers</h2>{transfers.length === 0 ? <div className="empty">Your transfers will appear here.</div> : transfers.map(t => <article className="transfer" key={t.id}><div><strong>{t.file_name}</strong><small>To {t.device_name} · {t.state}</small></div><progress value={t.bytes_done} max={t.bytes_total} /><span>{Math.round(t.bytes_done / Math.max(t.bytes_total, 1) * 100)}%</span></article>)}</section>{pairing && <div className="overlay"><div className="dialog"><h2>Confirm pairing</h2><p>On both devices, verify this code is identical before continuing.</p><output>{pairing.code}</output><p>Pair with <strong>{pairing.device.name}</strong></p><footer><button className="secondary" onClick={() => setPairing(null)}>Cancel</button><button onClick={confirm}>Codes match</button></footer></div></div>}</main>;
}
createRoot(document.getElementById("root")!).render(<App />);
