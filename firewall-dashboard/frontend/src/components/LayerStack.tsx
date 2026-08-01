import { PacketEvent } from "../types";

interface Layer {
  tag: string;
  name: string;
  fields: { k: string; v: string }[];
}

export default function LayerStack({ pkt }: { pkt: PacketEvent }) {
  const layers: Layer[] = [
    {
      tag: "L2",
      name: "Data Link",
      fields: [
        { k: "Src MAC", v: pkt.src_mac },
        { k: "Dst MAC", v: pkt.dst_mac },
      ],
    },
  ];

  if (pkt.src_ip) {
    layers.push({
      tag: "L3",
      name: "Network",
      fields: [
        { k: "Src IP", v: pkt.src_ip },
        { k: "Dst IP", v: pkt.dst_ip ?? "—" },
        { k: "Direction", v: pkt.direction },
      ],
    });
  }

  if (pkt.src_port !== null) {
    layers.push({
      tag: "L4",
      name: "Transport",
      fields: [
        { k: "Protocol", v: pkt.protocol },
        { k: "Src Port", v: String(pkt.src_port) },
        { k: "Dst Port", v: String(pkt.dst_port) },
        ...(pkt.flags ? [{ k: "Flags", v: pkt.flags }] : []),
      ],
    });
  }

  const l7fields: { k: string; v: string }[] = [{ k: "Guess", v: pkt.l7_guess }];
  if (pkt.sni) l7fields.push({ k: "TLS SNI", v: pkt.sni });
  if (pkt.dns_query) l7fields.push({ k: "DNS Query", v: pkt.dns_query });
  layers.push({ tag: "L5-7", name: "Session / App", fields: l7fields });

  layers.push({
    tag: "USER",
    name: "Process attribution",
    fields: [
      { k: "Application", v: pkt.process ?? "unknown (needs root/setcap)" },
      { k: "PID", v: pkt.pid !== null ? String(pkt.pid) : "—" },
      { k: "User", v: pkt.user ?? "—" },
    ],
  });

  return (
    <div className="layer-stack">
      {layers.map((layer) => (
        <div className="layer-row" key={layer.tag}>
          <div className="layer-tag">{layer.tag}</div>
          <div className="layer-body">
            <div className="layer-name">{layer.name}</div>
            <div className="layer-fields">
              {layer.fields.map((f) => (
                <div className="layer-field" key={f.k}>
                  <span className="lf-key">{f.k}</span>
                  <span className="lf-val">{f.v}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
