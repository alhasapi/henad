import { useEffect, useState } from "react";
import { formatBytes, type IncomingTransfer } from "../lib/ipc";

type Props = {
  offer: IncomingTransfer;
  onRespond: (accepted: boolean, remember: boolean) => void;
};

export function IncomingTransferDialog({ offer, onRespond }: Props) {
  const [remaining, setRemaining] = useState(offer.expires_in_secs);
  const [remember, setRemember] = useState(false);

  useEffect(() => {
    setRemaining(offer.expires_in_secs);
    setRemember(false);
    const timer = setInterval(() => {
      setRemaining((value) => (value > 0 ? value - 1 : 0));
    }, 1000);
    return () => clearInterval(timer);
  }, [offer.transfer_id, offer.expires_in_secs]);

  return (
    <div className="overlay">
      <div className="dialog">
        <h2>Incoming file</h2>
        <p>
          <strong>{offer.device_name}</strong> wants to send you a file.
        </p>
        <output className="file">{offer.file_name}</output>
        <p className="muted">
          {formatBytes(offer.bytes)} ·{" "}
          {remaining > 0
            ? `expires in ${Math.floor(remaining / 60)}:${String(remaining % 60).padStart(2, "0")}`
            : "this request has expired"}
        </p>
        <label className="remember">
          <input
            type="checkbox"
            checked={remember}
            onChange={(event) => setRemember(event.target.checked)}
          />
          Always accept files from {offer.device_name}
        </label>
        <footer>
          <button className="secondary" onClick={() => onRespond(false, false)}>
            Decline
          </button>
          <button disabled={remaining === 0} onClick={() => onRespond(true, remember)}>
            Accept
          </button>
        </footer>
      </div>
    </div>
  );
}
