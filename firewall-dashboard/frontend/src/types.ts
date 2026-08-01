export interface PacketEvent {
  ts: string;
  src_mac: string;
  dst_mac: string;
  src_ip: string | null;
  dst_ip: string | null;
  src_port: number | null;
  dst_port: number | null;
  protocol: string;
  l7_guess: string;
  length: number;
  direction: "inbound" | "outbound" | "local";
  process: string | null;
  pid: number | null;
  user: string | null;
  flags: string | null;
  sni: string | null;
  dns_query: string | null;
}

export interface Stats {
  total_packets: number;
  total_bytes: number;
  by_protocol: Record<string, number>;
  by_process: Record<string, number>;
}
