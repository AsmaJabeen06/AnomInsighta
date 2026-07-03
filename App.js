import { useState, useEffect, useCallback, useRef } from "react";
import {
  AreaChart, Area, LineChart, Line, BarChart, Bar,
  PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid,
  Tooltip, Legend, ResponsiveContainer, RadarChart,
  Radar, PolarGrid, PolarAngleAxis
} from "recharts";
import {
  Shield, Activity, AlertTriangle, FileText, BarChart2,
  Globe, Bell, RefreshCw, ChevronRight, CheckCircle,
  XCircle, Eye, Search, Cpu, Database, Wifi, Lock,
  Zap, Server, Radio, TrendingUp, AlertCircle, Menu, X,
  Map, Settings, Download, ToggleLeft, ToggleRight,
  Clock, Flag, ArrowUp, ArrowDown, ChevronsUpDown,
  FileBarChart2, Layers, BookOpen
} from "lucide-react";

// ─── palette & helpers ────────────────────────────────────────────────────────
const C = {
  bg:      "#070d1a",
  panel:   "#0c1424",
  border:  "#162035",
  border2: "#1e2e4a",
  teal:    "#00c8a8",
  blue:    "#3b82f6",
  purple:  "#8b5cf6",
  red:     "#f43f5e",
  orange:  "#f97316",
  yellow:  "#eab308",
  green:   "#22c55e",
  muted:   "#4a5f7a",
  text:    "#c8d8ec",
  bright:  "#e8f0fc",
};

const SEVERITY = {
  critical: { label: "Critical", color: C.red,    bg: "#2a0a12" },
  high:     { label: "High",     color: C.orange,  bg: "#1f1208" },
  medium:   { label: "Medium",   color: C.yellow,  bg: "#1a1608" },
  low:      { label: "Low",      color: C.green,   bg: "#071a0e" },
  info:     { label: "Info",     color: C.blue,    bg: "#070f22" },
};

const rnd = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;
const pick = (arr) => arr[rnd(0, arr.length - 1)];
const fmtNum = (n) => n >= 1000 ? (n / 1000).toFixed(1) + "k" : n;
const now = () => new Date().toLocaleTimeString("en-US", { hour12: false });
const ts = () => new Date().toISOString().replace("T", " ").slice(0, 19);

// ─── data generators ──────────────────────────────────────────────────────────
const IPS = ["192.168.1.101","10.0.0.45","172.16.0.22","192.168.2.88","10.10.5.12","45.33.32.156","185.220.101.8","198.51.100.23"];
const PROTOS = ["TCP","UDP","ICMP","HTTP","HTTPS","DNS","SSH","FTP"];
const THREAT_TYPES = ["Port Scan","DDoS","Brute Force","SQL Injection","XSS","Data Exfil","C2 Beacon","ARP Spoof"];
const ACTIONS = ["BLOCKED","LOGGED","ALERTED","DROPPED","ALLOWED"];
const SERVICES = ["zeek","suricata","elasticsearch","kibana","logstash","filebeat"];

const genTrafficPoint = (t) => ({
  time: t,
  normal: rnd(120, 280),
  suspicious: rnd(5, 35),
  blocked: rnd(2, 18),
});

const genLog = (id) => ({
  id,
  ts: ts(),
  src: pick(IPS),
  dst: pick(IPS),
  proto: pick(PROTOS),
  bytes: rnd(64, 65535),
  action: pick(ACTIONS),
  severity: pick(["critical","high","medium","low","info"]),
  threat: Math.random() > 0.7 ? pick(THREAT_TYPES) : null,
  service: pick(["zeek","suricata"]),
});

const genAlert = (id) => ({
  id,
  ts: ts(),
  type: pick(THREAT_TYPES),
  src: pick(IPS),
  dst: pick(IPS),
  severity: pick(["critical","high","medium","low"]),
  status: pick(["new","investigating","resolved"]),
  ml_score: (Math.random() * 0.4 + 0.6).toFixed(3),
});

const initTraffic = () => {
  const d = [];
  for (let i = 29; i >= 0; i--) {
    const date = new Date(Date.now() - i * 2000);
    d.push(genTrafficPoint(date.toLocaleTimeString("en-US", { hour12: false }).slice(0, 5)));
  }
  return d;
};

const PROTOCOL_DATA = [
  { name: "TCP",   value: 42, color: C.teal },
  { name: "HTTP",  value: 21, color: C.blue },
  { name: "HTTPS", value: 18, color: C.purple },
  { name: "UDP",   value: 11, color: C.yellow },
  { name: "DNS",   value: 5,  color: C.green },
  { name: "Other", value: 3,  color: C.muted },
];

const ML_RADAR = [
  { metric: "Precision", iso: 94, rf: 97, kmeans: 82 },
  { metric: "Recall",    iso: 88, rf: 93, kmeans: 75 },
  { metric: "F1 Score",  iso: 91, rf: 95, kmeans: 78 },
  { metric: "Accuracy",  iso: 92, rf: 96, kmeans: 80 },
  { metric: "AUC-ROC",   iso: 89, rf: 94, kmeans: 71 },
  { metric: "Speed",     iso: 98, rf: 72, kmeans: 88 },
];

// ─── sub-components ───────────────────────────────────────────────────────────
const Badge = ({ sev }) => {
  const s = SEVERITY[sev] || SEVERITY.info;
  return (
    <span style={{
      background: s.bg, color: s.color,
      border: `1px solid ${s.color}44`,
      padding: "2px 8px", borderRadius: 4,
      fontSize: 11, fontWeight: 700, letterSpacing: 0.5,
    }}>{s.label}</span>
  );
};

const StatCard = ({ icon: Icon, label, value, sub, color, pulse }) => (
  <div style={{
    background: C.panel, border: `1px solid ${C.border2}`,
    borderRadius: 10, padding: "18px 20px",
    display: "flex", alignItems: "center", gap: 16,
    position: "relative", overflow: "hidden",
  }}>
    {pulse && (
      <div style={{
        position: "absolute", top: 0, right: 0, bottom: 0, left: 0,
        background: `radial-gradient(circle at 90% 50%, ${color}08 0%, transparent 60%)`,
        pointerEvents: "none",
      }} />
    )}
    <div style={{
      background: `${color}15`, border: `1px solid ${color}30`,
      borderRadius: 8, padding: 10, color,
      display: "flex", alignItems: "center", justifyContent: "center",
    }}>
      <Icon size={20} />
    </div>
    <div>
      <div style={{ fontSize: 11, color: C.muted, textTransform: "uppercase", letterSpacing: 1, marginBottom: 2 }}>{label}</div>
      <div style={{ fontSize: 24, fontWeight: 800, color: C.bright, lineHeight: 1 }}>{value}</div>
      {sub && <div style={{ fontSize: 11, color: C.muted, marginTop: 3 }}>{sub}</div>}
    </div>
  </div>
);

const Panel = ({ title, children, toolbar, style = {} }) => (
  <div style={{
    background: C.panel, border: `1px solid ${C.border2}`,
    borderRadius: 10, overflow: "hidden", ...style,
  }}>
    <div style={{
      padding: "14px 20px",
      borderBottom: `1px solid ${C.border}`,
      display: "flex", alignItems: "center", justifyContent: "space-between",
    }}>
      <span style={{ fontWeight: 700, color: C.bright, fontSize: 13, letterSpacing: 0.3 }}>{title}</span>
      {toolbar}
    </div>
    <div style={{ padding: 20 }}>{children}</div>
  </div>
);

const TT = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={{
      background: "#0d1829", border: `1px solid ${C.border2}`,
      borderRadius: 8, padding: "10px 14px", fontSize: 12,
    }}>
      <div style={{ color: C.muted, marginBottom: 6 }}>{label}</div>
      {payload.map((p) => (
        <div key={p.name} style={{ color: p.color, marginBottom: 3 }}>
          {p.name}: <strong>{p.value}</strong>
        </div>
      ))}
    </div>
  );
};

// ─── PAGE: DASHBOARD ──────────────────────────────────────────────────────────
const PageDashboard = ({ state, logs, alerts }) => {
  const alertsByType = THREAT_TYPES.slice(0, 6).map((t) => ({
    name: t.split(" ")[0],
    count: rnd(3, 28),
  }));

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      {/* stats row */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 14 }}>
        <StatCard icon={Activity}       label="Traffic Events"   value={fmtNum(state.totalEvents)}  sub="+12% last hour"  color={C.teal}   pulse />
        <StatCard icon={AlertTriangle}  label="Active Alerts"    value={state.activeAlerts}         sub="3 critical"      color={C.red}    pulse />
        <StatCard icon={Shield}         label="Threats Blocked"  value={state.blocked}              sub="Today"           color={C.green}  />
        <StatCard icon={Cpu}            label="ML Detections"    value={state.mlDetections}         sub="Isolation Forest" color={C.purple} />
        <StatCard icon={Database}       label="Logs Indexed"     value={fmtNum(state.logsIndexed)}  sub="Elasticsearch"   color={C.blue}   />
        <StatCard icon={TrendingUp}     label="Detection Rate"   value={state.detectionRate + "%"}  sub="AI accuracy"     color={C.yellow} />
      </div>

      {/* live traffic + pie */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 320px", gap: 20 }}>
        <Panel title="🔴 Live Network Traffic (30s window)" toolbar={
          <span style={{ fontSize: 11, color: C.teal, display: "flex", alignItems: "center", gap: 4 }}>
            <span style={{ width: 7, height: 7, borderRadius: "50%", background: C.teal, display: "inline-block", animation: "pulse 1s infinite" }} />
            LIVE
          </span>
        }>
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={state.traffic}>
              <defs>
                <linearGradient id="gn" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor={C.teal}   stopOpacity={0.3} />
                  <stop offset="95%" stopColor={C.teal}  stopOpacity={0} />
                </linearGradient>
                <linearGradient id="gs" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor={C.orange} stopOpacity={0.3} />
                  <stop offset="95%" stopColor={C.orange} stopOpacity={0} />
                </linearGradient>
                <linearGradient id="gb" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor={C.red}   stopOpacity={0.3} />
                  <stop offset="95%" stopColor={C.red}  stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke={C.border} />
              <XAxis dataKey="time" tick={{ fill: C.muted, fontSize: 10 }} interval={4} />
              <YAxis tick={{ fill: C.muted, fontSize: 10 }} />
              <Tooltip content={<TT />} />
              <Legend wrapperStyle={{ fontSize: 11, color: C.text }} />
              <Area type="monotone" dataKey="normal"     stroke={C.teal}   fill="url(#gn)" name="Normal"     strokeWidth={2} />
              <Area type="monotone" dataKey="suspicious" stroke={C.orange} fill="url(#gs)" name="Suspicious" strokeWidth={2} />
              <Area type="monotone" dataKey="blocked"    stroke={C.red}    fill="url(#gb)" name="Blocked"    strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        </Panel>

        <Panel title="Protocol Distribution">
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie data={PROTOCOL_DATA} cx="50%" cy="50%" innerRadius={50} outerRadius={80}
                dataKey="value" nameKey="name" paddingAngle={3}>
                {PROTOCOL_DATA.map((e, i) => <Cell key={i} fill={e.color} />)}
              </Pie>
              <Tooltip content={<TT />} />
            </PieChart>
          </ResponsiveContainer>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 8 }}>
            {PROTOCOL_DATA.map((p) => (
              <div key={p.name} style={{ display: "flex", alignItems: "center", gap: 4, fontSize: 11, color: C.text }}>
                <div style={{ width: 8, height: 8, borderRadius: 2, background: p.color }} />
                {p.name} {p.value}%
              </div>
            ))}
          </div>
        </Panel>
      </div>

      {/* alert types + recent alerts */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
        <Panel title="Threat Type Distribution">
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={alertsByType} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" stroke={C.border} horizontal={false} />
              <XAxis type="number" tick={{ fill: C.muted, fontSize: 10 }} />
              <YAxis dataKey="name" type="category" tick={{ fill: C.text, fontSize: 11 }} width={70} />
              <Tooltip content={<TT />} />
              <Bar dataKey="count" fill={C.purple} radius={[0, 4, 4, 0]} name="Count" />
            </BarChart>
          </ResponsiveContainer>
        </Panel>

        <Panel title="Recent Alerts">
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {alerts.slice(0, 5).map((a) => (
              <div key={a.id} style={{
                display: "flex", alignItems: "center", gap: 12,
                padding: "8px 12px", background: C.bg, borderRadius: 7,
                border: `1px solid ${C.border}`,
              }}>
                <AlertCircle size={14} color={SEVERITY[a.severity]?.color} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 12, color: C.bright, fontWeight: 600, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{a.type}</div>
                  <div style={{ fontSize: 10, color: C.muted }}>{a.src} → {a.dst}</div>
                </div>
                <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 3 }}>
                  <Badge sev={a.severity} />
                  <span style={{ fontSize: 10, color: C.muted }}>{a.ts.slice(-8)}</span>
                </div>
              </div>
            ))}
          </div>
        </Panel>
      </div>
    </div>
  );
};

// ─── PAGE: LOGS ───────────────────────────────────────────────────────────────
const PageLogs = ({ logs }) => {
  const [filter, setFilter] = useState("");
  const [src, setSrc] = useState("all");
  const filtered = logs.filter((l) =>
    (src === "all" || l.service === src) &&
    (!filter || l.src.includes(filter) || l.dst.includes(filter) || (l.threat || "").toLowerCase().includes(filter.toLowerCase()))
  );

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      {/* filters */}
      <div style={{
        display: "flex", gap: 12, alignItems: "center",
        background: C.panel, border: `1px solid ${C.border2}`,
        borderRadius: 10, padding: "12px 18px",
      }}>
        <Search size={15} color={C.muted} />
        <input
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="Search by IP, threat type..."
          style={{
            flex: 1, background: "transparent", border: "none", outline: "none",
            color: C.text, fontSize: 13,
          }}
        />
        <div style={{ display: "flex", gap: 8 }}>
          {["all","zeek","suricata"].map((s) => (
            <button key={s}
              onClick={() => setSrc(s)}
              style={{
                padding: "5px 14px", borderRadius: 6, cursor: "pointer", fontSize: 12,
                background: src === s ? C.teal : C.bg,
                color:      src === s ? "#000"  : C.muted,
                border: `1px solid ${src === s ? C.teal : C.border2}`,
                fontWeight: src === s ? 700 : 400,
              }}>
              {s === "all" ? "All" : s.charAt(0).toUpperCase() + s.slice(1)}
            </button>
          ))}
        </div>
        <span style={{ fontSize: 11, color: C.muted }}>{filtered.length} entries</span>
      </div>

      {/* table */}
      <div style={{
        background: C.panel, border: `1px solid ${C.border2}`,
        borderRadius: 10, overflow: "hidden",
      }}>
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
            <thead>
              <tr style={{ background: C.bg }}>
                {["Timestamp","Source IP","Dest IP","Protocol","Bytes","Threat","Severity","Source","Action"].map((h) => (
                  <th key={h} style={{
                    padding: "10px 14px", textAlign: "left",
                    color: C.muted, fontWeight: 600, fontSize: 11,
                    letterSpacing: 0.5, borderBottom: `1px solid ${C.border}`,
                    whiteSpace: "nowrap",
                  }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.slice(0, 60).map((l, i) => (
                <tr key={l.id} style={{ borderBottom: `1px solid ${C.border}`, background: i % 2 === 0 ? "transparent" : "#0a1220" }}>
                  <td style={{ padding: "8px 14px", color: C.muted, whiteSpace: "nowrap" }}>{l.ts.slice(-8)}</td>
                  <td style={{ padding: "8px 14px", color: C.teal,  fontFamily: "monospace" }}>{l.src}</td>
                  <td style={{ padding: "8px 14px", color: C.blue,  fontFamily: "monospace" }}>{l.dst}</td>
                  <td style={{ padding: "8px 14px", color: C.text }}>{l.proto}</td>
                  <td style={{ padding: "8px 14px", color: C.text }}>{l.bytes.toLocaleString()}</td>
                  <td style={{ padding: "8px 14px" }}>
                    {l.threat
                      ? <span style={{ color: C.orange, fontWeight: 600 }}>{l.threat}</span>
                      : <span style={{ color: C.muted }}>—</span>}
                  </td>
                  <td style={{ padding: "8px 14px" }}><Badge sev={l.severity} /></td>
                  <td style={{ padding: "8px 14px" }}>
                    <span style={{
                      fontSize: 10, fontWeight: 700, color: l.service === "zeek" ? C.teal : C.purple,
                      textTransform: "uppercase", letterSpacing: 0.5,
                    }}>{l.service}</span>
                  </td>
                  <td style={{ padding: "8px 14px" }}>
                    <span style={{
                      fontSize: 10, fontWeight: 700,
                      color: l.action === "BLOCKED" || l.action === "DROPPED" ? C.red : l.action === "ALLOWED" ? C.green : C.yellow,
                    }}>{l.action}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

// ─── PAGE: ANALYTICS ─────────────────────────────────────────────────────────
const PageAnalytics = () => {
  const acc = Array.from({ length: 20 }, (_, i) => ({
    epoch: i + 1,
    isolation: Math.min(95, 70 + i * 1.3 + rnd(-2, 2)),
    randomForest: Math.min(97, 75 + i * 1.1 + rnd(-1, 2)),
    kMeans: Math.min(83, 60 + i * 1.1 + rnd(-3, 3)),
  }));

  const cm = [
    { label: "TP", value: 847, color: C.green,  desc: "True Positive" },
    { label: "TN", value: 3241, color: C.teal,   desc: "True Negative" },
    { label: "FP", value: 38,   color: C.orange,  desc: "False Positive" },
    { label: "FN", value: 74,   color: C.red,     desc: "False Negative" },
  ];

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      {/* model performance cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 14 }}>
        {[
          { name: "Isolation Forest", acc: "92.4%", f1: "0.914", color: C.teal,   icon: "🌲" },
          { name: "Random Forest",    acc: "96.1%", f1: "0.953", color: C.blue,   icon: "🌳" },
          { name: "K-Means",         acc: "80.3%", f1: "0.786", color: C.purple, icon: "⚙️" },
        ].map((m) => (
          <div key={m.name} style={{
            background: C.panel, border: `1px solid ${C.border2}`,
            borderRadius: 10, padding: 20,
            borderTop: `3px solid ${m.color}`,
          }}>
            <div style={{ fontSize: 20, marginBottom: 6 }}>{m.icon}</div>
            <div style={{ fontWeight: 700, color: C.bright, marginBottom: 12 }}>{m.name}</div>
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
              <span style={{ fontSize: 12, color: C.muted }}>Accuracy</span>
              <span style={{ fontSize: 18, fontWeight: 800, color: m.color }}>{m.acc}</span>
            </div>
            <div style={{ background: C.border, borderRadius: 4, height: 6, marginBottom: 10 }}>
              <div style={{ background: m.color, borderRadius: 4, height: 6, width: m.acc }} />
            </div>
            <div style={{ display: "flex", justifyContent: "space-between" }}>
              <span style={{ fontSize: 12, color: C.muted }}>F1 Score</span>
              <span style={{ fontSize: 12, color: C.text, fontWeight: 600 }}>{m.f1}</span>
            </div>
          </div>
        ))}
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 320px", gap: 20 }}>
        {/* training curves */}
        <Panel title="Model Training Accuracy over Epochs">
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={acc}>
              <CartesianGrid strokeDasharray="3 3" stroke={C.border} />
              <XAxis dataKey="epoch" tick={{ fill: C.muted, fontSize: 10 }} label={{ value: "Epoch", position: "insideBottom", offset: -2, fill: C.muted, fontSize: 11 }} />
              <YAxis domain={[55, 100]} tick={{ fill: C.muted, fontSize: 10 }} tickFormatter={(v) => v + "%"} />
              <Tooltip content={<TT />} />
              <Legend wrapperStyle={{ fontSize: 11, color: C.text }} />
              <Line type="monotone" dataKey="isolation"    stroke={C.teal}   strokeWidth={2} dot={false} name="Isolation Forest" />
              <Line type="monotone" dataKey="randomForest" stroke={C.blue}   strokeWidth={2} dot={false} name="Random Forest" />
              <Line type="monotone" dataKey="kMeans"       stroke={C.purple} strokeWidth={2} dot={false} name="K-Means" />
            </LineChart>
          </ResponsiveContainer>
        </Panel>

        {/* radar chart */}
        <Panel title="Multi-metric Comparison">
          <ResponsiveContainer width="100%" height={220}>
            <RadarChart data={ML_RADAR}>
              <PolarGrid stroke={C.border} />
              <PolarAngleAxis dataKey="metric" tick={{ fill: C.text, fontSize: 10 }} />
              <Radar name="Isolation Forest" dataKey="iso" stroke={C.teal}   fill={C.teal}   fillOpacity={0.15} />
              <Radar name="Random Forest"    dataKey="rf"  stroke={C.blue}   fill={C.blue}   fillOpacity={0.15} />
              <Radar name="K-Means"          dataKey="kmeans" stroke={C.purple} fill={C.purple} fillOpacity={0.15} />
              <Legend wrapperStyle={{ fontSize: 10 }} />
              <Tooltip content={<TT />} />
            </RadarChart>
          </ResponsiveContainer>
        </Panel>
      </div>

      {/* confusion matrix */}
      <Panel title="Confusion Matrix (Random Forest — Best Model)">
        <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 14 }}>
          {cm.map((c) => (
            <div key={c.label} style={{
              background: C.bg, border: `1px solid ${c.color}30`,
              borderRadius: 10, padding: 20, textAlign: "center",
              borderTop: `3px solid ${c.color}`,
            }}>
              <div style={{ fontSize: 30, fontWeight: 900, color: c.color }}>{c.value}</div>
              <div style={{ fontSize: 13, fontWeight: 700, color: C.bright, marginTop: 4 }}>{c.label}</div>
              <div style={{ fontSize: 11, color: C.muted, marginTop: 2 }}>{c.desc}</div>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
};

// ─── PAGE: ALERTS ─────────────────────────────────────────────────────────────
const PageAlerts = ({ alerts }) => {
  const [filter, setFilter] = useState("all");
  const filtered = filter === "all" ? alerts : alerts.filter((a) => a.severity === filter);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      {/* severity filter bar */}
      <div style={{
        background: C.panel, border: `1px solid ${C.border2}`,
        borderRadius: 10, padding: "12px 18px",
        display: "flex", gap: 10, alignItems: "center",
      }}>
        <Bell size={15} color={C.muted} />
        <span style={{ fontSize: 12, color: C.muted, marginRight: 6 }}>Filter:</span>
        {["all","critical","high","medium","low"].map((s) => (
          <button key={s}
            onClick={() => setFilter(s)}
            style={{
              padding: "5px 14px", borderRadius: 6, cursor: "pointer", fontSize: 12,
              background: filter === s ? (SEVERITY[s]?.color || C.teal) : C.bg,
              color:      filter === s ? "#000" : SEVERITY[s]?.color || C.text,
              border: `1px solid ${filter === s ? (SEVERITY[s]?.color || C.teal) : C.border2}`,
              fontWeight: filter === s ? 700 : 400,
            }}>
            {s.charAt(0).toUpperCase() + s.slice(1)}
          </button>
        ))}
        <span style={{ marginLeft: "auto", fontSize: 11, color: C.muted }}>{filtered.length} alerts</span>
      </div>

      {/* alerts grid */}
      <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
        {filtered.slice(0, 50).map((a) => {
          const s = SEVERITY[a.severity] || SEVERITY.info;
          return (
            <div key={a.id} style={{
              background: C.panel, border: `1px solid ${s.color}25`,
              borderLeft: `4px solid ${s.color}`,
              borderRadius: "0 10px 10px 0",
              padding: "14px 18px",
              display: "flex", alignItems: "center", gap: 16,
            }}>
              <AlertCircle size={18} color={s.color} />
              <div style={{ flex: 1 }}>
                <div style={{ fontWeight: 700, color: C.bright, fontSize: 13, marginBottom: 3 }}>{a.type}</div>
                <div style={{ fontSize: 11, color: C.muted }}>
                  <span style={{ color: C.teal }}>{a.src}</span> → <span style={{ color: C.blue }}>{a.dst}</span>
                </div>
              </div>
              <div style={{ textAlign: "right" }}>
                <div style={{ marginBottom: 4 }}><Badge sev={a.severity} /></div>
                <div style={{ fontSize: 11, color: C.purple }}>ML Score: {a.ml_score}</div>
              </div>
              <div style={{ textAlign: "right", minWidth: 90 }}>
                <div style={{ fontSize: 10, color: C.muted, marginBottom: 4 }}>{a.ts.slice(-8)}</div>
                <span style={{
                  fontSize: 10, fontWeight: 700, textTransform: "uppercase",
                  color: a.status === "new" ? C.red : a.status === "investigating" ? C.yellow : C.green,
                }}>{a.status}</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

// ─── PAGE: THREATS ────────────────────────────────────────────────────────────
const PageThreats = () => {
  const threats = THREAT_TYPES.map((t, i) => ({
    id: i,
    name: t,
    count: rnd(5, 120),
    trend: pick(["+12%", "-3%", "+27%", "+5%", "-8%", "+41%"]),
    last: ts(),
    severity: pick(["critical","high","medium","low"]),
    mitre: pick(["T1046","T1595","T1110","T1190","T1059","T1071","T1102","T1557"]),
  }));

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 14 }}>
        {threats.map((t) => {
          const s = SEVERITY[t.severity] || SEVERITY.info;
          const isUp = t.trend.startsWith("+");
          return (
            <div key={t.id} style={{
              background: C.panel, border: `1px solid ${C.border2}`,
              borderRadius: 10, padding: "16px 20px",
            }}>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 10 }}>
                <span style={{ fontWeight: 700, color: C.bright, fontSize: 13 }}>{t.name}</span>
                <Badge sev={t.severity} />
              </div>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end" }}>
                <div>
                  <div style={{ fontSize: 28, fontWeight: 900, color: s.color }}>{t.count}</div>
                  <div style={{ fontSize: 10, color: C.muted }}>detections</div>
                </div>
                <div style={{ textAlign: "right" }}>
                  <div style={{ fontSize: 13, fontWeight: 700, color: isUp ? C.red : C.green }}>{t.trend}</div>
                  <div style={{ fontSize: 10, color: C.muted }}>vs last period</div>
                </div>
              </div>
              <div style={{ marginTop: 12, display: "flex", justifyContent: "space-between", fontSize: 11, color: C.muted }}>
                <span>MITRE: <span style={{ color: C.blue, fontFamily: "monospace" }}>{t.mitre}</span></span>
                <span>Last: {t.last.slice(-8)}</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

// ─── PAGE: TRAFFIC ────────────────────────────────────────────────────────────
const PageTraffic = ({ state }) => {
  const hourly = Array.from({ length: 24 }, (_, i) => ({
    hour: `${String(i).padStart(2, "0")}:00`,
    inbound:  rnd(800,  3500),
    outbound: rnd(400,  2000),
    anomalies: rnd(0, 80),
  }));

  const topSrc = IPS.slice(0, 6).map((ip) => ({
    ip, packets: rnd(200, 2000), bytes: rnd(10000, 500000),
    proto: pick(PROTOS), suspicious: Math.random() > 0.7,
  }));

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      <Panel title="24-Hour Traffic Volume">
        <ResponsiveContainer width="100%" height={220}>
          <BarChart data={hourly}>
            <CartesianGrid strokeDasharray="3 3" stroke={C.border} />
            <XAxis dataKey="hour" tick={{ fill: C.muted, fontSize: 9 }} interval={2} />
            <YAxis tick={{ fill: C.muted, fontSize: 10 }} />
            <Tooltip content={<TT />} />
            <Legend wrapperStyle={{ fontSize: 11 }} />
            <Bar dataKey="inbound"  fill={C.teal}   name="Inbound"  radius={[3, 3, 0, 0]} />
            <Bar dataKey="outbound" fill={C.blue}   name="Outbound" radius={[3, 3, 0, 0]} />
            <Bar dataKey="anomalies" fill={C.red}   name="Anomalies" radius={[3, 3, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </Panel>

      <Panel title="Top Source IPs">
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
          <thead>
            <tr style={{ background: C.bg }}>
              {["Source IP","Packets","Bytes","Protocol","Status"].map((h) => (
                <th key={h} style={{
                  padding: "9px 14px", textAlign: "left", color: C.muted,
                  fontWeight: 600, fontSize: 11, letterSpacing: 0.5,
                  borderBottom: `1px solid ${C.border}`,
                }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {topSrc.map((r, i) => (
              <tr key={i} style={{ borderBottom: `1px solid ${C.border}` }}>
                <td style={{ padding: "9px 14px", color: C.teal, fontFamily: "monospace" }}>{r.ip}</td>
                <td style={{ padding: "9px 14px", color: C.text }}>{r.packets.toLocaleString()}</td>
                <td style={{ padding: "9px 14px", color: C.text }}>{(r.bytes / 1024).toFixed(1)} KB</td>
                <td style={{ padding: "9px 14px", color: C.text }}>{r.proto}</td>
                <td style={{ padding: "9px 14px" }}>
                  {r.suspicious
                    ? <span style={{ color: C.red, fontWeight: 700, fontSize: 11 }}>⚠ Suspicious</span>
                    : <span style={{ color: C.green, fontWeight: 700, fontSize: 11 }}>✓ Normal</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>
    </div>
  );
};

// ─── PAGE: ABOUT ──────────────────────────────────────────────────────────────
const PageAbout = () => (
  <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
    <div style={{
      background: `linear-gradient(135deg, ${C.panel} 0%, #0a1628 100%)`,
      border: `1px solid ${C.border2}`,
      borderRadius: 12, padding: 32, textAlign: "center",
    }}>
      <div style={{ fontSize: 48, marginBottom: 12 }}>🛡️</div>
      <h1 style={{ fontSize: 28, fontWeight: 900, color: C.bright, margin: 0, letterSpacing: -0.5 }}>
        Anom<span style={{ color: C.teal }}>Insight</span>
      </h1>
      <p style={{ color: C.muted, marginTop: 8, fontSize: 14 }}>
        AI-Based Anomaly Detection using Security Onion Logs
      </p>
      <div style={{ display: "flex", gap: 10, justifyContent: "center", marginTop: 16, flexWrap: "wrap" }}>
        {["Machine Learning","Security Onion","Zeek Logs","Suricata","Kibana","Python"].map((t) => (
          <span key={t} style={{
            background: `${C.teal}12`, border: `1px solid ${C.teal}30`,
            color: C.teal, padding: "4px 12px", borderRadius: 20, fontSize: 12, fontWeight: 600,
          }}>{t}</span>
        ))}
      </div>
    </div>

    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
      {/* team */}
      <Panel title="👥 Project Team">
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          {[
            { id: "23R11A6253", name: "Asma Jabeen",   role: "ML Model Development" },
            { id: "23R11A6283", name: "P. Sai Teja",   role: "Log Processing & ELK Stack" },
            { id: "23R11A6294", name: "V. Pandu Naik", role: "Dashboard & Visualization" },
          ].map((m) => (
            <div key={m.id} style={{
              background: C.bg, border: `1px solid ${C.border}`,
              borderRadius: 8, padding: "12px 14px",
              display: "flex", gap: 12, alignItems: "center",
            }}>
              <div style={{
                width: 36, height: 36, borderRadius: "50%",
                background: `linear-gradient(135deg, ${C.teal}, ${C.blue})`,
                display: "flex", alignItems: "center", justifyContent: "center",
                fontWeight: 800, fontSize: 14, color: "#000",
              }}>{m.name[0]}</div>
              <div>
                <div style={{ fontWeight: 700, color: C.bright, fontSize: 13 }}>{m.name}</div>
                <div style={{ fontSize: 11, color: C.muted }}>{m.id} · {m.role}</div>
              </div>
            </div>
          ))}
          <div style={{
            background: C.bg, border: `1px solid ${C.border}`,
            borderRadius: 8, padding: "12px 14px",
            display: "flex", gap: 12, alignItems: "center",
          }}>
            <div style={{
              width: 36, height: 36, borderRadius: "50%",
              background: `linear-gradient(135deg, ${C.purple}, ${C.blue})`,
              display: "flex", alignItems: "center", justifyContent: "center",
              fontSize: 16,
            }}>👩‍🏫</div>
            <div>
              <div style={{ fontWeight: 700, color: C.bright, fontSize: 13 }}>Dr. G Lokeshwari</div>
              <div style={{ fontSize: 11, color: C.muted }}>Professor · Project Guide</div>
            </div>
          </div>
        </div>
      </Panel>

      {/* tech stack */}
      <Panel title="⚙️ Technology Stack">
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {[
            { tech: "Python",          purpose: "ML model implementation",        color: C.yellow  },
            { tech: "Security Onion",  purpose: "Network security monitoring",    color: C.teal    },
            { tech: "Zeek",            purpose: "Network traffic log generation", color: C.blue    },
            { tech: "Suricata",        purpose: "Intrusion detection & alerts",   color: C.orange  },
            { tech: "Scikit-learn",    purpose: "ML algorithms",                  color: C.purple  },
            { tech: "Kibana",          purpose: "Data visualization",             color: C.green   },
            { tech: "Elasticsearch",   purpose: "Log storage & indexing",         color: C.red     },
            { tech: "Pandas / NumPy",  purpose: "Data preprocessing",            color: C.muted   },
          ].map((r) => (
            <div key={r.tech} style={{
              display: "flex", justifyContent: "space-between",
              padding: "6px 0", borderBottom: `1px solid ${C.border}`,
            }}>
              <span style={{ fontWeight: 700, color: r.color, fontSize: 12 }}>{r.tech}</span>
              <span style={{ fontSize: 11, color: C.muted }}>{r.purpose}</span>
            </div>
          ))}
        </div>
      </Panel>
    </div>

    {/* modules */}
    <Panel title="🧩 System Modules">
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 12 }}>
        {[
          { name: "Log Collection",      desc: "Collect Zeek & Suricata logs via Security Onion", icon: "📡" },
          { name: "Data Preprocessing",  desc: "Clean & convert raw logs to structured CSV",       icon: "⚙️" },
          { name: "Feature Extraction",  desc: "Extract IP, protocol, timestamp, traffic size",    icon: "🔍" },
          { name: "ML Detection",        desc: "Isolation Forest, Random Forest, K-Means",          icon: "🤖" },
          { name: "Anomaly Detection",   desc: "Identify suspicious traffic & activities",          icon: "🚨" },
          { name: "Alert Management",    desc: "Generate alerts for detected anomalies",            icon: "🔔" },
          { name: "Visualization",       desc: "Kibana dashboards for logs & alerts",               icon: "📊" },
        ].map((m) => (
          <div key={m.name} style={{
            background: C.bg, border: `1px solid ${C.border}`,
            borderRadius: 8, padding: "14px 16px",
          }}>
            <div style={{ fontSize: 22, marginBottom: 6 }}>{m.icon}</div>
            <div style={{ fontWeight: 700, color: C.bright, fontSize: 12, marginBottom: 4 }}>{m.name}</div>
            <div style={{ fontSize: 11, color: C.muted }}>{m.desc}</div>
          </div>
        ))}
      </div>
    </Panel>
  </div>
);

// ─── GEO DATA ────────────────────────────────────────────────────────────────
const GEO_COUNTRIES = [
  { country: "Russia",        code: "RU", flag: "🇷🇺", attacks: 412, blocked: 389, color: C.red    },
  { country: "China",         code: "CN", flag: "🇨🇳", attacks: 374, blocked: 341, color: C.orange },
  { country: "United States", code: "US", flag: "🇺🇸", attacks: 218, blocked: 175, color: C.blue   },
  { country: "Brazil",        code: "BR", flag: "🇧🇷", attacks: 183, blocked: 162, color: C.green  },
  { country: "India",         code: "IN", flag: "🇮🇳", attacks: 141, blocked: 128, color: C.teal   },
  { country: "Germany",       code: "DE", flag: "🇩🇪", attacks: 97,  blocked: 84,  color: C.yellow },
  { country: "Netherlands",   code: "NL", flag: "🇳🇱", attacks: 86,  blocked: 78,  color: C.purple },
  { country: "Ukraine",       code: "UA", flag: "🇺🇦", attacks: 74,  blocked: 64,  color: C.orange },
  { country: "South Korea",   code: "KR", flag: "🇰🇷", attacks: 62,  blocked: 57,  color: C.blue   },
  { country: "Iran",          code: "IR", flag: "🇮🇷", attacks: 58,  blocked: 53,  color: C.red    },
];

const GEO_ATTACK_TYPES = [
  { type: "Port Scan",   ru: 87, cn: 64, us: 42, br: 31 },
  { type: "Brute Force", ru: 120, cn: 98, us: 55, br: 47 },
  { type: "DDoS",        ru: 68, cn: 112, us: 38, br: 29 },
  { type: "C2 Beacon",   ru: 47, cn: 33, us: 22, br: 18 },
  { type: "Data Exfil",  ru: 90, cn: 67, us: 61, br: 58 },
];

// ─── PAGE: GEO ───────────────────────────────────────────────────────────────
const PageGeo = () => {
  const [selected, setSelected] = useState(null);
  const maxAttacks = GEO_COUNTRIES[0].attacks;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      {/* top summary cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: 12 }}>
        {[
          { label: "Countries Detected",  value: "47",    icon: Globe,  color: C.teal   },
          { label: "Total Attack Sources",value: "1,705", icon: Flag,   color: C.red    },
          { label: "ASNs Flagged",        value: "312",   icon: Server, color: C.orange },
          { label: "Geo-blocked IPs",     value: "2,841", icon: Lock,   color: C.green  },
        ].map((s) => (
          <div key={s.label} style={{
            background: C.panel, border: `1px solid ${C.border2}`,
            borderRadius: 10, padding: "16px 18px",
            display: "flex", alignItems: "center", gap: 12,
          }}>
            <div style={{
              background: `${s.color}18`, border: `1px solid ${s.color}30`,
              borderRadius: 8, padding: 9, color: s.color,
            }}><s.icon size={17} /></div>
            <div>
              <div style={{ fontSize: 20, fontWeight: 800, color: C.bright }}>{s.value}</div>
              <div style={{ fontSize: 10, color: C.muted, lineHeight: 1.3 }}>{s.label}</div>
            </div>
          </div>
        ))}
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 360px", gap: 20 }}>
        {/* country attack bars */}
        <Panel title="🌍 Top Attack Origin Countries">
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {GEO_COUNTRIES.map((c, i) => (
              <div key={c.code}
                onClick={() => setSelected(selected?.code === c.code ? null : c)}
                style={{
                  padding: "12px 14px", borderRadius: 8, cursor: "pointer",
                  background: selected?.code === c.code ? `${c.color}10` : C.bg,
                  border: `1px solid ${selected?.code === c.code ? c.color + "40" : C.border}`,
                  transition: "all 0.15s",
                }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
                  <span style={{ fontSize: 20 }}>{c.flag}</span>
                  <span style={{ fontWeight: 600, color: C.bright, fontSize: 13, flex: 1 }}>{c.country}</span>
                  <span style={{ fontSize: 12, color: C.muted }}>
                    <span style={{ color: c.color, fontWeight: 700 }}>{c.attacks}</span> attacks
                  </span>
                  <span style={{ fontSize: 11, color: C.green }}>✓ {c.blocked} blocked</span>
                </div>
                <div style={{ background: C.border, borderRadius: 4, height: 6 }}>
                  <div style={{
                    background: `linear-gradient(90deg, ${c.color}, ${c.color}88)`,
                    width: `${(c.attacks / maxAttacks) * 100}%`,
                    height: 6, borderRadius: 4,
                    transition: "width 0.6s ease",
                  }} />
                </div>
              </div>
            ))}
          </div>
        </Panel>

        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          {/* selected country detail */}
          {selected ? (
            <Panel title={`${selected.flag} ${selected.country} — Details`}>
              <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                {[
                  { label: "Total Attacks",   value: selected.attacks, color: C.red    },
                  { label: "Blocked",         value: selected.blocked, color: C.green  },
                  { label: "Passed Through",  value: selected.attacks - selected.blocked, color: C.orange },
                  { label: "Block Rate",      value: Math.round((selected.blocked / selected.attacks) * 100) + "%", color: C.teal },
                ].map((r) => (
                  <div key={r.label} style={{
                    display: "flex", justifyContent: "space-between",
                    padding: "8px 12px", background: C.bg, borderRadius: 7,
                    border: `1px solid ${C.border}`,
                  }}>
                    <span style={{ fontSize: 12, color: C.muted }}>{r.label}</span>
                    <span style={{ fontSize: 14, fontWeight: 800, color: r.color }}>{r.value}</span>
                  </div>
                ))}
                <div style={{ marginTop: 4, fontSize: 11, color: C.muted }}>
                  Most common attack: <span style={{ color: C.orange, fontWeight: 600 }}>Brute Force</span>
                </div>
              </div>
            </Panel>
          ) : (
            <div style={{
              background: C.panel, border: `1px dashed ${C.border2}`,
              borderRadius: 10, padding: 24, textAlign: "center",
              color: C.muted, fontSize: 12,
            }}>
              <Globe size={28} color={C.border2} style={{ marginBottom: 8 }} />
              <div>Click a country to see<br />detailed attack breakdown</div>
            </div>
          )}

          {/* attack type by country */}
          <Panel title="Attack Types by Source">
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={GEO_ATTACK_TYPES} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke={C.border} horizontal={false} />
                <XAxis type="number" tick={{ fill: C.muted, fontSize: 9 }} />
                <YAxis dataKey="type" type="category" tick={{ fill: C.text, fontSize: 10 }} width={72} />
                <Tooltip content={<TT />} />
                <Legend wrapperStyle={{ fontSize: 9 }} />
                <Bar dataKey="ru" name="Russia" fill={C.red}    radius={[0,3,3,0]} />
                <Bar dataKey="cn" name="China"  fill={C.orange} radius={[0,3,3,0]} />
                <Bar dataKey="us" name="USA"    fill={C.blue}   radius={[0,3,3,0]} />
              </BarChart>
            </ResponsiveContainer>
          </Panel>
        </div>
      </div>
    </div>
  );
};

// ─── PAGE: RULES ─────────────────────────────────────────────────────────────
const INIT_RULES = [
  { id: "R-001", name: "Port Scan Detection",       engine: "Suricata", severity: "high",     enabled: true,  hits: 847,  action: "ALERT",  category: "Reconnaissance" },
  { id: "R-002", name: "SSH Brute Force",            engine: "Suricata", severity: "critical", enabled: true,  hits: 1204, action: "DROP",   category: "Credential Access" },
  { id: "R-003", name: "Isolation Forest Anomaly",   engine: "ML",       severity: "high",     enabled: true,  hits: 392,  action: "ALERT",  category: "ML Detection" },
  { id: "R-004", name: "Random Forest Classifier",   engine: "ML",       severity: "critical", enabled: true,  hits: 521,  action: "BLOCK",  category: "ML Detection" },
  { id: "R-005", name: "K-Means Cluster Outlier",    engine: "ML",       severity: "medium",   enabled: true,  hits: 178,  action: "LOG",    category: "ML Detection" },
  { id: "R-006", name: "DNS Tunneling",              engine: "Zeek",     severity: "high",     enabled: true,  hits: 63,   action: "ALERT",  category: "Exfiltration" },
  { id: "R-007", name: "DDoS Flood Detection",       engine: "Suricata", severity: "critical", enabled: false, hits: 229,  action: "DROP",   category: "DoS" },
  { id: "R-008", name: "SQL Injection Pattern",      engine: "Suricata", severity: "critical", enabled: true,  hits: 317,  action: "BLOCK",  category: "Web Attack" },
  { id: "R-009", name: "ARP Spoofing",               engine: "Zeek",     severity: "medium",   enabled: true,  hits: 44,   action: "ALERT",  category: "Lateral Movement" },
  { id: "R-010", name: "C2 Beacon Pattern",          engine: "ML",       severity: "critical", enabled: true,  hits: 88,   action: "BLOCK",  category: "Command & Control" },
  { id: "R-011", name: "Data Exfiltration Volume",   engine: "Zeek",     severity: "high",     enabled: false, hits: 31,   action: "ALERT",  category: "Exfiltration" },
  { id: "R-012", name: "ICMP Flood",                 engine: "Suricata", severity: "medium",   enabled: true,  hits: 156,  action: "DROP",   category: "DoS" },
  { id: "R-013", name: "FTP Anomaly",                engine: "Zeek",     severity: "low",      enabled: true,  hits: 22,   action: "LOG",    category: "Unusual Protocol" },
  { id: "R-014", name: "XSS Payload Detection",      engine: "Suricata", severity: "high",     enabled: true,  hits: 209,  action: "BLOCK",  category: "Web Attack" },
  { id: "R-015", name: "Geo-block: High Risk ASN",   engine: "Suricata", severity: "medium",   enabled: false, hits: 644,  action: "DROP",   category: "Geo-Policy" },
];

const ENGINE_COLORS = { Suricata: C.orange, Zeek: C.teal, ML: C.purple };
const ACTION_COLORS  = { ALERT: C.yellow, DROP: C.red, BLOCK: C.red, LOG: C.blue };

const PageRules = () => {
  const [rules, setRules] = useState(INIT_RULES);
  const [search, setSearch] = useState("");
  const [engineFilter, setEngineFilter] = useState("all");
  const [sortCol, setSortCol] = useState("hits");
  const [sortDir, setSortDir] = useState("desc");

  const toggle = (id) => setRules((r) => r.map((x) => x.id === id ? { ...x, enabled: !x.enabled } : x));

  const handleSort = (col) => {
    if (sortCol === col) setSortDir((d) => d === "asc" ? "desc" : "asc");
    else { setSortCol(col); setSortDir("desc"); }
  };

  const filtered = rules
    .filter((r) =>
      (engineFilter === "all" || r.engine === engineFilter) &&
      (!search || r.name.toLowerCase().includes(search.toLowerCase()) || r.category.toLowerCase().includes(search.toLowerCase()))
    )
    .sort((a, b) => {
      const v1 = a[sortCol], v2 = b[sortCol];
      const cmp = typeof v1 === "number" ? v1 - v2 : String(v1).localeCompare(String(v2));
      return sortDir === "asc" ? cmp : -cmp;
    });

  const SortIcon = ({ col }) => {
    if (sortCol !== col) return <ChevronsUpDown size={11} color={C.muted} />;
    return sortDir === "asc" ? <ArrowUp size={11} color={C.teal} /> : <ArrowDown size={11} color={C.teal} />;
  };

  const ThS = ({ col, label }) => (
    <th onClick={() => handleSort(col)} style={{
      padding: "10px 14px", textAlign: "left",
      color: sortCol === col ? C.teal : C.muted,
      fontWeight: 600, fontSize: 11, letterSpacing: 0.5,
      borderBottom: `1px solid ${C.border}`,
      cursor: "pointer", whiteSpace: "nowrap",
      userSelect: "none",
    }}>
      <span style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
        {label} <SortIcon col={col} />
      </span>
    </th>
  );

  const enabled = rules.filter((r) => r.enabled).length;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      {/* summary row */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12 }}>
        {[
          { label: "Total Rules", value: rules.length, color: C.blue   },
          { label: "Active",      value: enabled,       color: C.green  },
          { label: "Disabled",    value: rules.length - enabled, color: C.muted  },
          { label: "Total Hits",  value: rules.reduce((s, r) => s + r.hits, 0).toLocaleString(), color: C.orange },
        ].map((s) => (
          <div key={s.label} style={{
            background: C.panel, border: `1px solid ${C.border2}`,
            borderRadius: 10, padding: "14px 18px", textAlign: "center",
          }}>
            <div style={{ fontSize: 22, fontWeight: 900, color: s.color }}>{s.value}</div>
            <div style={{ fontSize: 11, color: C.muted, marginTop: 2 }}>{s.label}</div>
          </div>
        ))}
      </div>

      {/* filter bar */}
      <div style={{
        background: C.panel, border: `1px solid ${C.border2}`,
        borderRadius: 10, padding: "12px 18px",
        display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap",
      }}>
        <Search size={14} color={C.muted} />
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search rules..."
          style={{ flex: 1, background: "transparent", border: "none", outline: "none", color: C.text, fontSize: 13, minWidth: 140 }}
        />
        {["all", "Suricata", "Zeek", "ML"].map((e) => (
          <button key={e} onClick={() => setEngineFilter(e)} style={{
            padding: "5px 14px", borderRadius: 6, cursor: "pointer", fontSize: 12,
            background: engineFilter === e ? (ENGINE_COLORS[e] || C.teal) : C.bg,
            color:      engineFilter === e ? "#000" : ENGINE_COLORS[e] || C.text,
            border: `1px solid ${engineFilter === e ? (ENGINE_COLORS[e] || C.teal) : C.border2}`,
            fontWeight: engineFilter === e ? 700 : 400,
          }}>{e === "all" ? "All Engines" : e}</button>
        ))}
        <span style={{ fontSize: 11, color: C.muted }}>{filtered.length} rules</span>
      </div>

      {/* rules table */}
      <div style={{ background: C.panel, border: `1px solid ${C.border2}`, borderRadius: 10, overflow: "hidden" }}>
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
            <thead>
              <tr style={{ background: C.bg }}>
                <ThS col="id"       label="Rule ID"   />
                <ThS col="name"     label="Rule Name" />
                <ThS col="engine"   label="Engine"    />
                <ThS col="category" label="Category"  />
                <ThS col="severity" label="Severity"  />
                <ThS col="action"   label="Action"    />
                <ThS col="hits"     label="Hits"      />
                <th style={{ padding: "10px 14px", color: C.muted, fontWeight: 600, fontSize: 11, letterSpacing: 0.5, borderBottom: `1px solid ${C.border}` }}>
                  Status
                </th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((r, i) => (
                <tr key={r.id} style={{
                  borderBottom: `1px solid ${C.border}`,
                  background: i % 2 === 0 ? "transparent" : "#0a1220",
                  opacity: r.enabled ? 1 : 0.5,
                }}>
                  <td style={{ padding: "9px 14px", color: C.muted, fontFamily: "monospace", fontSize: 11 }}>{r.id}</td>
                  <td style={{ padding: "9px 14px", color: C.bright, fontWeight: 600 }}>{r.name}</td>
                  <td style={{ padding: "9px 14px" }}>
                    <span style={{
                      fontSize: 11, fontWeight: 700, color: ENGINE_COLORS[r.engine],
                      background: `${ENGINE_COLORS[r.engine]}12`,
                      border: `1px solid ${ENGINE_COLORS[r.engine]}30`,
                      padding: "2px 8px", borderRadius: 4,
                    }}>{r.engine}</span>
                  </td>
                  <td style={{ padding: "9px 14px", color: C.text, fontSize: 11 }}>{r.category}</td>
                  <td style={{ padding: "9px 14px" }}><Badge sev={r.severity} /></td>
                  <td style={{ padding: "9px 14px" }}>
                    <span style={{ fontSize: 11, fontWeight: 700, color: ACTION_COLORS[r.action] || C.text }}>{r.action}</span>
                  </td>
                  <td style={{ padding: "9px 14px", color: C.yellow, fontWeight: 700 }}>{r.hits.toLocaleString()}</td>
                  <td style={{ padding: "9px 14px" }}>
                    <div
                      onClick={() => toggle(r.id)}
                      style={{
                        display: "inline-flex", alignItems: "center", gap: 6,
                        cursor: "pointer", padding: "3px 8px",
                        background: r.enabled ? `${C.green}15` : `${C.muted}15`,
                        border: `1px solid ${r.enabled ? C.green : C.border2}`,
                        borderRadius: 20, fontSize: 11, fontWeight: 700,
                        color: r.enabled ? C.green : C.muted,
                        userSelect: "none",
                      }}
                    >
                      <div style={{
                        width: 8, height: 8, borderRadius: "50%",
                        background: r.enabled ? C.green : C.muted,
                      }} />
                      {r.enabled ? "Active" : "Disabled"}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

// ─── PAGE: REPORTS ───────────────────────────────────────────────────────────
const TIMELINE = Array.from({ length: 14 }, (_, i) => {
  const d = new Date();
  d.setDate(d.getDate() - (13 - i));
  return {
    date: d.toLocaleDateString("en-US", { month: "short", day: "numeric" }),
    anomalies: rnd(30, 140),
    blocked:   rnd(20, 110),
    critical:  rnd(2, 18),
  };
});

const PageReports = ({ state, alerts }) => {
  const [downloading, setDownloading] = useState(false);

  const handleDownload = () => {
    setDownloading(true);
    const lines = [
      "AnomInsight – Security Summary Report",
      `Generated: ${new Date().toLocaleString()}`,
      "---",
      `Total Events Monitored: ${state.totalEvents.toLocaleString()}`,
      `Active Alerts: ${state.activeAlerts}`,
      `Threats Blocked: ${state.blocked}`,
      `ML Detections: ${state.mlDetections}`,
      `Logs Indexed: ${state.logsIndexed.toLocaleString()}`,
      `Detection Rate: ${state.detectionRate}%`,
      "",
      "Top Threat Types:",
      ...THREAT_TYPES.map((t) => `  - ${t}: ${rnd(20, 120)} detections`),
      "",
      "ML Model Accuracy:",
      "  - Isolation Forest: 92.4%",
      "  - Random Forest: 96.1% (Best)",
      "  - K-Means: 80.3%",
      "",
      "Recent Critical Alerts:",
      ...alerts.filter((a) => a.severity === "critical").slice(0, 5)
        .map((a) => `  [${a.ts}] ${a.type} | ${a.src} → ${a.dst} | ML: ${a.ml_score}`),
    ];
    const blob = new Blob([lines.join("\n")], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = "AnomInsight_Report.txt"; a.click();
    URL.revokeObjectURL(url);
    setTimeout(() => setDownloading(false), 1500);
  };

  const weeklySum = [
    { week: "Week 1", anomalies: 312, blocked: 287, critical: 42 },
    { week: "Week 2", anomalies: 428, blocked: 391, critical: 67 },
    { week: "Week 3", anomalies: 381, blocked: 349, critical: 55 },
    { week: "Week 4", anomalies: 496, blocked: 458, critical: 78 },
    { week: "Week 5", anomalies: 441, blocked: 409, critical: 61 },
    { week: "Week 6", anomalies: 374, blocked: 341, critical: 49 },
  ];

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      {/* report header */}
      <div style={{
        background: `linear-gradient(135deg, ${C.panel}, #0a1628)`,
        border: `1px solid ${C.border2}`, borderRadius: 12,
        padding: "24px 28px",
        display: "flex", justifyContent: "space-between", alignItems: "center",
        flexWrap: "wrap", gap: 16,
      }}>
        <div>
          <div style={{ fontSize: 11, color: C.muted, textTransform: "uppercase", letterSpacing: 1, marginBottom: 4 }}>Security Report</div>
          <div style={{ fontSize: 22, fontWeight: 900, color: C.bright }}>AnomInsight Summary</div>
          <div style={{ fontSize: 12, color: C.muted, marginTop: 4 }}>
            Generated: {new Date().toLocaleString()} · Period: Last 6 Weeks
          </div>
        </div>
        <button
          onClick={handleDownload}
          disabled={downloading}
          style={{
            display: "flex", alignItems: "center", gap: 8,
            padding: "10px 20px", borderRadius: 8, cursor: "pointer",
            background: downloading ? `${C.teal}30` : C.teal,
            color: downloading ? C.teal : "#000",
            border: `1px solid ${C.teal}`,
            fontWeight: 700, fontSize: 13,
            transition: "all 0.2s",
          }}>
          <Download size={15} />
          {downloading ? "Downloading…" : "Export Report (.txt)"}
        </button>
      </div>

      {/* KPI summary */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))", gap: 12 }}>
        {[
          { label: "Total Events",     value: state.totalEvents.toLocaleString(), color: C.teal   },
          { label: "Threats Blocked",  value: state.blocked,                       color: C.green  },
          { label: "ML Detections",    value: state.mlDetections,                  color: C.purple },
          { label: "Active Alerts",    value: state.activeAlerts,                  color: C.red    },
          { label: "Detection Rate",   value: state.detectionRate + "%",           color: C.yellow },
          { label: "Logs Indexed",     value: fmtNum(state.logsIndexed),           color: C.blue   },
        ].map((k) => (
          <div key={k.label} style={{
            background: C.panel, border: `1px solid ${C.border2}`,
            borderRadius: 10, padding: "14px 16px", textAlign: "center",
          }}>
            <div style={{ fontSize: 22, fontWeight: 900, color: k.color }}>{k.value}</div>
            <div style={{ fontSize: 10, color: C.muted, marginTop: 2 }}>{k.label}</div>
          </div>
        ))}
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
        {/* 14-day trend */}
        <Panel title="📅 14-Day Anomaly Trend">
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={TIMELINE}>
              <defs>
                <linearGradient id="ga" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor={C.purple} stopOpacity={0.3} />
                  <stop offset="95%" stopColor={C.purple} stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke={C.border} />
              <XAxis dataKey="date" tick={{ fill: C.muted, fontSize: 9 }} />
              <YAxis tick={{ fill: C.muted, fontSize: 9 }} />
              <Tooltip content={<TT />} />
              <Legend wrapperStyle={{ fontSize: 11 }} />
              <Area type="monotone" dataKey="anomalies" stroke={C.purple} fill="url(#ga)" name="Anomalies" strokeWidth={2} />
              <Line type="monotone" dataKey="blocked"   stroke={C.green}  name="Blocked"   strokeWidth={2} dot={false} />
              <Line type="monotone" dataKey="critical"  stroke={C.red}    name="Critical"  strokeWidth={2} dot={false} />
            </AreaChart>
          </ResponsiveContainer>
        </Panel>

        {/* weekly comparison */}
        <Panel title="📊 Weekly Comparison">
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={weeklySum}>
              <CartesianGrid strokeDasharray="3 3" stroke={C.border} />
              <XAxis dataKey="week" tick={{ fill: C.muted, fontSize: 9 }} />
              <YAxis tick={{ fill: C.muted, fontSize: 9 }} />
              <Tooltip content={<TT />} />
              <Legend wrapperStyle={{ fontSize: 11 }} />
              <Bar dataKey="anomalies" name="Anomalies" fill={C.purple} radius={[3,3,0,0]} />
              <Bar dataKey="blocked"   name="Blocked"   fill={C.green}  radius={[3,3,0,0]} />
              <Bar dataKey="critical"  name="Critical"  fill={C.red}    radius={[3,3,0,0]} />
            </BarChart>
          </ResponsiveContainer>
        </Panel>
      </div>

      {/* phase timeline */}
      <Panel title="🗓️ Project Phase Timeline">
        <div style={{ display: "flex", flexDirection: "column", gap: 0 }}>
          {[
            { phase: "Phase 1", desc: "Requirement Analysis",             dur: "Week 1", done: true  },
            { phase: "Phase 2", desc: "Log Collection & Dataset Prep",    dur: "Week 2", done: true  },
            { phase: "Phase 3", desc: "Data Preprocessing",               dur: "Week 3", done: true  },
            { phase: "Phase 4", desc: "ML Model Development",             dur: "Week 4", done: true  },
            { phase: "Phase 5", desc: "Testing & Evaluation",             dur: "Week 5", done: true  },
            { phase: "Phase 6", desc: "Dashboard Integration & Docs",     dur: "Week 6", done: false },
          ].map((p, i, arr) => (
            <div key={p.phase} style={{ display: "flex", gap: 16, alignItems: "flex-start" }}>
              <div style={{ display: "flex", flexDirection: "column", alignItems: "center", width: 32, flexShrink: 0 }}>
                <div style={{
                  width: 28, height: 28, borderRadius: "50%",
                  background: p.done ? `${C.green}20` : `${C.blue}15`,
                  border: `2px solid ${p.done ? C.green : C.blue}`,
                  display: "flex", alignItems: "center", justifyContent: "center",
                  fontSize: 13, flexShrink: 0,
                }}>{p.done ? "✓" : "⏳"}</div>
                {i < arr.length - 1 && (
                  <div style={{ width: 2, height: 28, background: p.done ? `${C.green}40` : C.border, marginTop: 2 }} />
                )}
              </div>
              <div style={{ paddingBottom: i < arr.length - 1 ? 14 : 0, paddingTop: 4 }}>
                <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
                  <span style={{ fontWeight: 700, color: p.done ? C.bright : C.muted, fontSize: 13 }}>{p.phase}</span>
                  <span style={{ fontSize: 10, color: p.done ? C.green : C.blue, background: p.done ? `${C.green}12` : `${C.blue}12`, padding: "2px 8px", borderRadius: 10 }}>{p.dur}</span>
                </div>
                <div style={{ fontSize: 12, color: C.muted, marginTop: 2 }}>{p.desc}</div>
              </div>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
};

// ─── TOAST SYSTEM ────────────────────────────────────────────────────────────
const ToastContainer = ({ toasts, dismiss }) => (
  <div style={{
    position: "fixed", bottom: 20, right: 20, zIndex: 999,
    display: "flex", flexDirection: "column-reverse", gap: 10,
    pointerEvents: "none",
  }}>
    {toasts.map((t) => {
      const s = SEVERITY[t.severity] || SEVERITY.info;
      return (
        <div key={t.id} style={{
          background: C.panel, border: `1px solid ${s.color}50`,
          borderLeft: `4px solid ${s.color}`,
          borderRadius: 8, padding: "12px 16px",
          minWidth: 280, maxWidth: 340,
          pointerEvents: "all",
          animation: "slideIn 0.3s ease",
          boxShadow: `0 4px 20px ${s.color}20`,
        }}>
          <div style={{ display: "flex", alignItems: "flex-start", gap: 10 }}>
            <AlertCircle size={14} color={s.color} style={{ marginTop: 1, flexShrink: 0 }} />
            <div style={{ flex: 1 }}>
              <div style={{ fontWeight: 700, color: C.bright, fontSize: 12, marginBottom: 2 }}>
                {t.type}
              </div>
              <div style={{ fontSize: 11, color: C.muted }}>{t.src} → {t.dst}</div>
              <div style={{ fontSize: 10, color: s.color, marginTop: 3, fontWeight: 600 }}>
                ML Score: {t.ml_score} · {s.label}
              </div>
            </div>
            <button onClick={() => dismiss(t.id)} style={{
              background: "none", border: "none", color: C.muted, cursor: "pointer", padding: 2,
            }}>
              <X size={12} />
            </button>
          </div>
        </div>
      );
    })}
  </div>
);

// ─── SIDEBAR ──────────────────────────────────────────────────────────────────
const NAV = [
  { id: "dashboard", label: "Dashboard",  icon: Activity      },
  { id: "traffic",   label: "Traffic",    icon: Wifi          },
  { id: "logs",      label: "Logs",       icon: FileText      },
  { id: "alerts",    label: "Alerts",     icon: Bell          },
  { id: "analytics", label: "Analytics",  icon: BarChart2     },
  { id: "threats",   label: "Threats",    icon: AlertTriangle },
  { id: "geo",       label: "Geo Intel",  icon: Globe         },
  { id: "rules",     label: "Rules",      icon: Layers        },
  { id: "reports",   label: "Reports",    icon: FileBarChart2 },
  { id: "about",     label: "About",      icon: Shield        },
];

// ─── ROOT APP ─────────────────────────────────────────────────────────────────
export default function AnomInsight() {
  const [page, setPage]   = useState("dashboard");
  const [menuOpen, setMenuOpen] = useState(false);
  const [tick, setTick]   = useState(0);
  const [toasts, setToasts] = useState([]);
  const [logs, setLogs]   = useState(() => Array.from({ length: 120 }, (_, i) => genLog(i)));
  const [alerts, setAlerts] = useState(() => Array.from({ length: 50 }, (_, i) => genAlert(i)));
  const [traffic, setTraffic] = useState(initTraffic);
  const [state, setState] = useState({
    totalEvents:    18742,
    activeAlerts:   23,
    blocked:        387,
    mlDetections:   91,
    logsIndexed:    142680,
    detectionRate:  94,
    traffic:        initTraffic(),
  });
  const logId   = useRef(120);
  const alertId = useRef(50);
  const toastId = useRef(0);

  const dismissToast = (id) => setToasts((t) => t.filter((x) => x.id !== id));
  const pushToast = (alert) => {
    const id = toastId.current++;
    setToasts((t) => [...t.slice(-4), { ...alert, id }]);
    setTimeout(() => dismissToast(id), 5000);
  };

  useEffect(() => {
    const interval = setInterval(() => {
      const newPoint = genTrafficPoint(new Date().toLocaleTimeString("en-US", { hour12: false }).slice(0, 5));
      setState((prev) => ({
        ...prev,
        totalEvents:   prev.totalEvents + rnd(3, 12),
        activeAlerts:  Math.max(0, prev.activeAlerts + pick([-1, 0, 0, 1, 1])),
        blocked:       prev.blocked + pick([0, 0, 1]),
        mlDetections:  prev.mlDetections + pick([0, 0, 0, 1]),
        logsIndexed:   prev.logsIndexed + rnd(8, 40),
        traffic:       [...prev.traffic.slice(-29), newPoint],
      }));
      // add new log
      if (Math.random() > 0.3) {
        setLogs((prev) => [genLog(logId.current++), ...prev.slice(0, 119)]);
      }
      // add new alert + toast for critical/high
      if (Math.random() > 0.6) {
        const a = genAlert(alertId.current++);
        setAlerts((prev) => [a, ...prev.slice(0, 49)]);
        if (a.severity === "critical" || a.severity === "high") {
          pushToast(a);
        }
      }
      setTick((t) => t + 1);
    }, 2000);
    return () => clearInterval(interval);
  }, []);

  const renderPage = () => {
    const p = { state: { ...state, traffic }, logs, alerts };
    switch (page) {
      case "dashboard": return <PageDashboard {...p} />;
      case "traffic":   return <PageTraffic   {...p} />;
      case "logs":      return <PageLogs      {...p} />;
      case "alerts":    return <PageAlerts    {...p} />;
      case "analytics": return <PageAnalytics />;
      case "threats":   return <PageThreats   />;
      case "geo":       return <PageGeo       />;
      case "rules":     return <PageRules     />;
      case "reports":   return <PageReports   {...p} />;
      case "about":     return <PageAbout     />;
      default:          return <PageDashboard {...p} />;
    }
  };

  const sidebarW = 220;

  return (
    <div style={{ display: "flex", minHeight: "100vh", background: C.bg, color: C.text, fontFamily: "'Inter', 'Segoe UI', system-ui, sans-serif" }}>
      <style>{`
        * { box-sizing: border-box; }
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: ${C.bg}; }
        ::-webkit-scrollbar-thumb { background: ${C.border2}; border-radius: 3px; }
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }
        @keyframes blink { 0%,100%{opacity:1} 50%{opacity:.2} }
        @keyframes slideIn { from { transform: translateX(120%); opacity:0; } to { transform: translateX(0); opacity:1; } }
        @media (max-width: 768px) { .sidebar { display: none; } .sidebar.open { display: flex !important; position: fixed; z-index: 100; top: 0; left: 0; bottom: 0; width: 220px; } .menu-btn { display: block !important; } }
      `}</style>

      {/* Sidebar */}
      <div className={`sidebar${menuOpen ? " open" : ""}`} style={{
        width: sidebarW, background: C.panel,
        borderRight: `1px solid ${C.border2}`,
        display: "flex", flexDirection: "column",
        position: "sticky", top: 0, height: "100vh",
        flexShrink: 0,
      }}>
        {/* logo */}
        <div style={{ padding: "22px 20px 18px", borderBottom: `1px solid ${C.border}` }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <div style={{
              width: 34, height: 34, borderRadius: 8,
              background: `linear-gradient(135deg, ${C.teal}, ${C.blue})`,
              display: "flex", alignItems: "center", justifyContent: "center",
              fontSize: 18,
            }}>🛡️</div>
            <div>
              <div style={{ fontWeight: 900, fontSize: 15, color: C.bright, letterSpacing: -0.3 }}>
                Anom<span style={{ color: C.teal }}>Insight</span>
              </div>
              <div style={{ fontSize: 9, color: C.muted, letterSpacing: 1, textTransform: "uppercase" }}>AI Anomaly Detection</div>
            </div>
          </div>
        </div>

        {/* nav */}
        <nav style={{ flex: 1, padding: "12px 10px", display: "flex", flexDirection: "column", gap: 2 }}>
          {NAV.map(({ id, label, icon: Icon }) => {
            const active = page === id;
            return (
              <button
                key={id}
                onClick={() => { setPage(id); setMenuOpen(false); }}
                style={{
                  display: "flex", alignItems: "center", gap: 10,
                  padding: "10px 12px", borderRadius: 8, cursor: "pointer",
                  background:  active ? `${C.teal}18` : "transparent",
                  color:       active ? C.teal : C.muted,
                  border:      active ? `1px solid ${C.teal}30` : "1px solid transparent",
                  fontWeight:  active ? 700 : 400,
                  fontSize: 13, width: "100%", textAlign: "left",
                  transition: "all 0.15s",
                }}
              >
                <Icon size={15} />
                {label}
                {id === "alerts" && (
                  <span style={{
                    marginLeft: "auto", background: C.red,
                    color: "#fff", borderRadius: 10, padding: "1px 7px", fontSize: 10, fontWeight: 700,
                  }}>{state.activeAlerts}</span>
                )}
              </button>
            );
          })}
        </nav>

        {/* status bar */}
        <div style={{ padding: "14px 16px", borderTop: `1px solid ${C.border}` }}>
          {SERVICES.slice(0, 4).map((s) => (
            <div key={s} style={{
              display: "flex", justifyContent: "space-between", alignItems: "center",
              marginBottom: 5, fontSize: 11,
            }}>
              <span style={{ color: C.muted }}>{s}</span>
              <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
                <div style={{ width: 6, height: 6, borderRadius: "50%", background: C.green, animation: "blink 2s infinite" }} />
                <span style={{ color: C.green }}>online</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* main */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0 }}>
        {/* top bar */}
        <div style={{
          height: 56, background: C.panel,
          borderBottom: `1px solid ${C.border2}`,
          display: "flex", alignItems: "center",
          padding: "0 24px", gap: 16,
          position: "sticky", top: 0, zIndex: 10,
        }}>
          <button
            className="menu-btn"
            onClick={() => setMenuOpen(!menuOpen)}
            style={{ display: "none", background: "none", border: "none", color: C.text, cursor: "pointer" }}
          >
            <Menu size={20} />
          </button>
          <div style={{ flex: 1, fontWeight: 700, color: C.bright, fontSize: 16 }}>
            {NAV.find((n) => n.id === page)?.label}
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12 }}>
            <div style={{ width: 8, height: 8, borderRadius: "50%", background: C.green, animation: "blink 1.5s infinite" }} />
            <span style={{ color: C.green, fontWeight: 600 }}>System Active</span>
          </div>
          <div style={{ fontSize: 11, color: C.muted }}>
            Events: <span style={{ color: C.bright, fontWeight: 700 }}>{state.totalEvents.toLocaleString()}</span>
          </div>
          <div style={{
            display: "flex", alignItems: "center", gap: 5,
            padding: "5px 10px", background: C.bg, borderRadius: 6,
            border: `1px solid ${C.border2}`, fontSize: 11, color: C.muted,
          }}>
            <RefreshCw size={11} />
            Auto-refresh 2s
          </div>
        </div>

        {/* page content */}
        <div style={{ flex: 1, padding: 24, overflowY: "auto" }}>
          {renderPage()}
        </div>
      </div>

      {/* global toast notifications */}
      <ToastContainer toasts={toasts} dismiss={dismissToast} />

      {/* mobile overlay */}
      {menuOpen && (
        <div onClick={() => setMenuOpen(false)} style={{
          position: "fixed", inset: 0, background: "rgba(0,0,0,0.6)", zIndex: 99,
        }} />
      )}
    </div>
  );
}
