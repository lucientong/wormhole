import { createSignal, createEffect, onCleanup } from "solid-js";

// Types
export interface RecordSummary {
  id: string;
  timestamp: string;
  method: string;
  url: string;
  host: string;
  path: string;
  status: number;
  duration: number;
  bodySize: number;
  respSize: number;
  error?: string;
}

export interface RequestRecord extends RecordSummary {
  headers: { [key: string]: string };
  body?: string;
  response?: {
    status: number;
    statusText: string;
    headers: { [key: string]: string };
    body?: string;
    bodySize: number;
  };
}

export interface Stats {
  count: number;
  capacity: number;
  enabled: boolean;
  wsClients?: number;
}

// WebSocket message types
interface WSMessage {
  type: string;
  payload?: unknown;
}

// Store
const [records, setRecords] = createSignal<RecordSummary[]>([]);
const [selectedId, setSelectedId] = createSignal<string | null>(null);
const [selectedRecord, setSelectedRecord] = createSignal<RequestRecord | null>(null);
const [stats, setStats] = createSignal<Stats>({ count: 0, capacity: 1000, enabled: true });
const [connected, setConnected] = createSignal(false);
const [isPaused, setIsPaused] = createSignal(false);

let ws: WebSocket | null = null;
let reconnectTimer: number | null = null;

// WebSocket connection
function connectWebSocket() {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${protocol}//${window.location.host}/api/inspector/ws`;
  
  try {
    ws = new WebSocket(wsUrl);
    
    ws.onopen = () => {
      setConnected(true);
      // Subscribe to get initial data
      ws?.send(JSON.stringify({ type: "subscribe" }));
    };
    
    ws.onclose = () => {
      setConnected(false);
      ws = null;
      // Reconnect after delay
      if (reconnectTimer) clearTimeout(reconnectTimer);
      reconnectTimer = window.setTimeout(connectWebSocket, 3000);
    };
    
    ws.onerror = () => {
      ws?.close();
    };
    
    ws.onmessage = (event) => {
      try {
        const msg: WSMessage = JSON.parse(event.data);
        handleMessage(msg);
      } catch {
        console.error("Failed to parse WebSocket message");
      }
    };
  } catch {
    console.error("Failed to create WebSocket");
    if (reconnectTimer) clearTimeout(reconnectTimer);
    reconnectTimer = window.setTimeout(connectWebSocket, 3000);
  }
}

function handleMessage(msg: WSMessage) {
  switch (msg.type) {
    case "record":
      if (!isPaused()) {
        const record = msg.payload as RecordSummary;
        setRecords((prev) => [record, ...prev].slice(0, 1000));
      }
      break;
      
    case "record_list":
      const list = msg.payload as RecordSummary[] | null;
      if (list) {
        setRecords(list);
      }
      break;
      
    case "stats":
      setStats(msg.payload as Stats);
      break;
      
    case "clear":
      setRecords([]);
      setSelectedId(null);
      setSelectedRecord(null);
      break;
  }
}

// Actions
export function initStore() {
  connectWebSocket();
  
  onCleanup(() => {
    if (reconnectTimer) clearTimeout(reconnectTimer);
    ws?.close();
  });
}

export async function fetchRecordDetail(id: string) {
  try {
    const resp = await fetch(`/api/inspector/records/${id}`);
    if (resp.ok) {
      const record = await resp.json();
      setSelectedRecord(record);
    }
  } catch (e) {
    console.error("Failed to fetch record detail:", e);
  }
}

export function selectRecord(id: string | null) {
  setSelectedId(id);
  if (id) {
    fetchRecordDetail(id);
  } else {
    setSelectedRecord(null);
  }
}

export async function clearRecords() {
  try {
    await fetch("/api/inspector/clear", { method: "POST" });
    setRecords([]);
    setSelectedId(null);
    setSelectedRecord(null);
  } catch (e) {
    console.error("Failed to clear records:", e);
  }
}

export async function toggleCapture() {
  try {
    const resp = await fetch("/api/inspector/toggle", { method: "POST" });
    if (resp.ok) {
      const data = await resp.json();
      setStats((prev) => ({ ...prev, enabled: data.enabled }));
    }
  } catch (e) {
    console.error("Failed to toggle capture:", e);
  }
}

export function togglePause() {
  setIsPaused((prev) => !prev);
}

// Computed/derived
export function useRecords() {
  return records;
}

export function useSelectedId() {
  return selectedId;
}

export function useSelectedRecord() {
  return selectedRecord;
}

export function useStats() {
  return stats;
}

export function useConnected() {
  return connected;
}

export function useIsPaused() {
  return isPaused;
}

// Utility functions
export function formatDuration(ns: number): string {
  if (ns < 1000000) {
    return `${(ns / 1000).toFixed(0)}µs`;
  }
  if (ns < 1000000000) {
    return `${(ns / 1000000).toFixed(0)}ms`;
  }
  return `${(ns / 1000000000).toFixed(2)}s`;
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function getMethodColor(method: string): string {
  const colors: Record<string, string> = {
    GET: "text-[var(--color-accent-green)]",
    POST: "text-[var(--color-accent-blue)]",
    PUT: "text-[var(--color-accent-yellow)]",
    PATCH: "text-[var(--color-accent-orange)]",
    DELETE: "text-[var(--color-accent-red)]",
    OPTIONS: "text-[var(--color-accent-purple)]",
    HEAD: "text-[var(--color-text-muted)]",
  };
  return colors[method] || "text-[var(--color-text-secondary)]";
}

export function getStatusColor(status: number): string {
  if (status >= 500) return "bg-[var(--color-accent-red)]";
  if (status >= 400) return "bg-[var(--color-accent-yellow)]";
  if (status >= 300) return "bg-[var(--color-accent-purple)]";
  if (status >= 200) return "bg-[var(--color-accent-green)]";
  return "bg-[var(--color-text-muted)]";
}
