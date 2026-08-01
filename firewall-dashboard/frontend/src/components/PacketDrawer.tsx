import { PacketEvent } from "../types";
import LayerStack from "./LayerStack";

interface Props {
  pkt: PacketEvent | null;
  onClose: () => void;
  onFilter: (value: string) => void;
}

export default function PacketDrawer({ pkt, onClose, onFilter }: Props) {
  return (
    <>
      <div className={`drawer-scrim ${pkt ? "drawer-scrim-visible" : ""}`} onClick={onClose} />
      <aside className={`drawer ${pkt ? "drawer-open" : ""}`}>
        {pkt && (
          <>
            <div className="drawer-head">
              <div>
                <h2>Packet detail</h2>
                <span className="drawer-sub mono">{new Date(pkt.ts).toLocaleTimeString(undefined, { hour12: false })}</span>
              </div>
              <button className="icon-btn" onClick={onClose} aria-label="Close">
                ✕
              </button>
            </div>

            <div className="drawer-quickfilters">
              {pkt.src_ip && (
                <button className="chip" onClick={() => onFilter(pkt.src_ip!)}>
                  filter: {pkt.src_ip}
                </button>
              )}
              {pkt.process && (
                <button className="chip" onClick={() => onFilter(pkt.process!)}>
                  filter: {pkt.process}
                </button>
              )}
              {pkt.dst_ip && (
                <button className="chip" onClick={() => onFilter(pkt.dst_ip!)}>
                  filter: {pkt.dst_ip}
                </button>
              )}
            </div>

            <div className="drawer-body">
              <LayerStack pkt={pkt} />
            </div>
          </>
        )}
      </aside>
    </>
  );
}
