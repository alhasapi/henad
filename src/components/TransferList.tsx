import { formatBytes, formatSpeed, type Transfer } from "../lib/ipc";

type Props = {
  transfers: Transfer[];
  onCancel: (transfer: Transfer) => void;
};

export function TransferList({ transfers, onCancel }: Props) {
  if (transfers.length === 0) {
    return <div className="empty">Your transfers will appear here.</div>;
  }

  return (
    <div className="transfers">
      {transfers.map((transfer) => {
        const percent = Math.min(
          100,
          Math.round((transfer.bytes_done / Math.max(transfer.bytes_total, 1)) * 100),
        );
        const active = transfer.state === "active" || transfer.state === "queued";
        return (
          <article className="transfer" key={transfer.id}>
            <div className="transfer-main">
              <strong>{transfer.file_name}</strong>
              <small>
                {transfer.device_name} · {transfer.state}
                {active && transfer.speed_bps > 0
                  ? ` · ${formatSpeed(transfer.speed_bps)}`
                  : ""}
                {` · ${formatBytes(transfer.bytes_done)} / ${formatBytes(transfer.bytes_total)}`}
              </small>
              {transfer.error ? <small className="error">{transfer.error}</small> : null}
            </div>
            <progress value={transfer.bytes_done} max={Math.max(transfer.bytes_total, 1)} />
            <span>{percent}%</span>
            {active ? (
              <button className="secondary" onClick={() => onCancel(transfer)}>
                Cancel
              </button>
            ) : null}
          </article>
        );
      })}
    </div>
  );
}
