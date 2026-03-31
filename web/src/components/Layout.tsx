import { Component, JSX, Show } from "solid-js";
import {
  useStats,
  useConnected,
  useIsPaused,
  useRecords,
  clearRecords,
  toggleCapture,
  togglePause,
} from "../stores/requests";

interface LayoutProps {
  children: JSX.Element;
}

const Layout: Component<LayoutProps> = (props) => {
  const stats = useStats();
  const connected = useConnected();
  const isPaused = useIsPaused();
  const records = useRecords();

  return (
    <div class="flex flex-col h-screen overflow-hidden bg-[var(--color-bg-primary)]">
      {/* Toolbar */}
      <header class="flex-shrink-0 h-10 flex items-center justify-between px-4 border-b border-[var(--color-border-default)] bg-[var(--color-bg-secondary)]">
        {/* Left: Logo + Status */}
        <div class="flex items-center gap-4">
          <div class="flex items-center gap-2">
            <span class="text-lg">🕳️</span>
            <span class="font-semibold text-sm text-[var(--color-text-primary)]">
              Wormhole Inspector
            </span>
          </div>

          {/* Connection status */}
          <div class="flex items-center gap-1.5">
            <span
              class={`w-2 h-2 rounded-full ${
                connected()
                  ? "bg-[var(--color-accent-green)] animate-pulse-dot"
                  : "bg-[var(--color-accent-red)]"
              }`}
            />
            <span class="text-[11px] text-[var(--color-text-muted)]">
              {connected() ? "Connected" : "Disconnected"}
            </span>
          </div>
        </div>

        {/* Center: Stats */}
        <div class="flex items-center gap-4 text-[11px] text-[var(--color-text-secondary)]">
          <span>
            <span class="text-[var(--color-text-muted)]">Requests: </span>
            <span class="font-mono tabular-nums">{records().length}</span>
          </span>
          <span>
            <span class="text-[var(--color-text-muted)]">Capacity: </span>
            <span class="font-mono tabular-nums">{stats().capacity}</span>
          </span>
        </div>

        {/* Right: Actions */}
        <div class="flex items-center gap-2">
          {/* Pause/Resume button */}
          <ToolbarButton
            onClick={togglePause}
            active={isPaused()}
            title={isPaused() ? "Resume" : "Pause"}
          >
            <Show when={isPaused()} fallback={<PauseIcon />}>
              <PlayIcon />
            </Show>
          </ToolbarButton>

          {/* Toggle capture */}
          <ToolbarButton
            onClick={toggleCapture}
            active={!stats().enabled}
            title={stats().enabled ? "Disable capture" : "Enable capture"}
          >
            <Show when={stats().enabled} fallback={<RecordOffIcon />}>
              <RecordIcon />
            </Show>
          </ToolbarButton>

          {/* Clear */}
          <ToolbarButton onClick={clearRecords} title="Clear all">
            <ClearIcon />
          </ToolbarButton>
        </div>
      </header>

      {/* Main content */}
      <main class="flex-1 overflow-hidden">{props.children}</main>

      {/* Status bar */}
      <footer class="flex-shrink-0 h-6 flex items-center justify-between px-3 border-t border-[var(--color-border-default)] bg-[var(--color-bg-tertiary)] text-[10px] text-[var(--color-text-muted)]">
        <div class="flex items-center gap-3">
          <span>
            {records().length} request{records().length !== 1 ? "s" : ""}
          </span>
          <Show when={isPaused()}>
            <span class="text-[var(--color-accent-yellow)]">• Paused</span>
          </Show>
          <Show when={!stats().enabled}>
            <span class="text-[var(--color-accent-red)]">• Capture disabled</span>
          </Show>
        </div>
        <div>
          <span class="font-mono">v1.0.0</span>
        </div>
      </footer>
    </div>
  );
};

interface ToolbarButtonProps {
  onClick: () => void;
  children: JSX.Element;
  title: string;
  active?: boolean;
}

const ToolbarButton: Component<ToolbarButtonProps> = (props) => (
  <button
    type="button"
    class={`w-7 h-7 flex items-center justify-center rounded transition-colors ${
      props.active
        ? "bg-[var(--color-accent-blue)]/20 text-[var(--color-accent-blue)]"
        : "text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-bg-elevated)]"
    }`}
    onClick={props.onClick}
    title={props.title}
  >
    {props.children}
  </button>
);

// Icons (simple SVG)
const PauseIcon = () => (
  <svg class="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
    <rect x="6" y="4" width="4" height="16" rx="1" />
    <rect x="14" y="4" width="4" height="16" rx="1" />
  </svg>
);

const PlayIcon = () => (
  <svg class="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
    <path d="M8 5v14l11-7z" />
  </svg>
);

const RecordIcon = () => (
  <svg class="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
    <circle cx="12" cy="12" r="6" fill="var(--color-accent-red)" />
  </svg>
);

const RecordOffIcon = () => (
  <svg class="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
    <circle cx="12" cy="12" r="6" fill="none" stroke="currentColor" stroke-width="2" />
  </svg>
);

const ClearIcon = () => (
  <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2">
    <path stroke-linecap="round" stroke-linejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
  </svg>
);

export default Layout;
