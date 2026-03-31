import { Component, For, createMemo } from "solid-js";
import {
  useRecords,
  useSelectedId,
  selectRecord,
  formatDuration,
  formatBytes,
  getMethodColor,
  RecordSummary,
} from "../stores/requests";
import StatusBadge from "./StatusBadge";

const RequestList: Component = () => {
  const records = useRecords();
  const selectedId = useSelectedId();

  const extractPath = (url: string) => {
    try {
      const u = new URL(url, "http://localhost");
      return u.pathname + u.search;
    } catch {
      return url;
    }
  };

  return (
    <div class="flex flex-col h-full overflow-hidden">
      {/* Header */}
      <div class="flex items-center h-8 px-3 border-b border-[var(--color-border-default)] bg-[var(--color-bg-tertiary)] text-[11px] font-medium text-[var(--color-text-muted)] uppercase tracking-wide">
        <div class="w-12">Status</div>
        <div class="w-16">Method</div>
        <div class="flex-1 min-w-0">Path</div>
        <div class="w-16 text-right">Time</div>
        <div class="w-16 text-right">Size</div>
      </div>

      {/* List */}
      <div class="flex-1 overflow-y-auto">
        <For
          each={records()}
          fallback={
            <div class="flex items-center justify-center h-full text-[var(--color-text-muted)] text-sm">
              <div class="text-center">
                <div class="text-2xl mb-2">🕳️</div>
                <div>No requests captured yet</div>
                <div class="text-xs mt-1">
                  Requests will appear here as they flow through the tunnel
                </div>
              </div>
            </div>
          }
        >
          {(record) => (
            <RequestRow
              record={record}
              isSelected={selectedId() === record.id}
              onClick={() => selectRecord(record.id)}
              extractPath={extractPath}
            />
          )}
        </For>
      </div>
    </div>
  );
};

interface RequestRowProps {
  record: RecordSummary;
  isSelected: boolean;
  onClick: () => void;
  extractPath: (url: string) => string;
}

const RequestRow: Component<RequestRowProps> = (props) => {
  const path = createMemo(() => props.extractPath(props.record.url));

  return (
    <button
      type="button"
      class={`flex items-center w-full h-7 px-3 text-left text-[12px] border-b border-[var(--color-border-default)] transition-colors duration-75 hover:bg-[var(--color-bg-tertiary)] focus:outline-none focus:bg-[var(--color-bg-tertiary)] ${
        props.isSelected
          ? "bg-[var(--color-accent-blue)]/15 border-l-2 border-l-[var(--color-accent-blue)]"
          : ""
      }`}
      onClick={props.onClick}
    >
      <div class="w-12">
        <StatusBadge status={props.record.status} error={props.record.error} />
      </div>
      <div class={`w-16 font-mono font-medium ${getMethodColor(props.record.method)}`}>
        {props.record.method}
      </div>
      <div class="flex-1 min-w-0 truncate text-[var(--color-text-primary)] font-mono">
        {path()}
      </div>
      <div class="w-16 text-right text-[var(--color-text-secondary)] font-mono tabular-nums">
        {formatDuration(props.record.duration)}
      </div>
      <div class="w-16 text-right text-[var(--color-text-muted)] font-mono tabular-nums">
        {formatBytes(props.record.respSize || props.record.bodySize)}
      </div>
    </button>
  );
};

export default RequestList;
