import { useEffect, useState } from "react";
import { formatCode } from "../lib/events";
import type { PairingPrompt } from "../lib/ipc";

type Props = {
  prompt: PairingPrompt;
  mode: "outgoing" | "incoming";
  onConfirm: () => void;
  onCancel: () => void;
};

export function PairingDialog({ prompt, mode, onConfirm, onCancel }: Props) {
  const [remaining, setRemaining] = useState(prompt.expires_in_secs);

  useEffect(() => {
    setRemaining(prompt.expires_in_secs);
    const timer = setInterval(() => {
      setRemaining((value) => (value > 0 ? value - 1 : 0));
    }, 1000);
    return () => clearInterval(timer);
  }, [prompt.device_id, prompt.expires_in_secs]);

  return (
    <div className="overlay">
      <div className="dialog">
        <h2>{mode === "incoming" ? "Pairing request" : "Confirm pairing"}</h2>
        <p>
          Check that this code is identical on both screens. Only confirm if you
          are pairing with <strong>{prompt.device_name}</strong> right now.
        </p>
        <output>{formatCode(prompt.code)}</output>
        <p className="muted">
          {remaining > 0
            ? `Expires in ${Math.floor(remaining / 60)}:${String(remaining % 60).padStart(2, "0")}`
            : "This request has expired."}
        </p>
        <footer>
          <button className="secondary" onClick={onCancel}>
            {mode === "incoming" ? "Decline" : "Cancel"}
          </button>
          <button disabled={remaining === 0} onClick={onConfirm}>
            Codes match
          </button>
        </footer>
      </div>
    </div>
  );
}
