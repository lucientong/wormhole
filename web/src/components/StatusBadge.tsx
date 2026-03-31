import { Component, Show } from "solid-js";
import { getStatusColor } from "../stores/requests";

interface StatusBadgeProps {
  status: number;
  error?: string;
}

const StatusBadge: Component<StatusBadgeProps> = (props) => {
  const color = () => {
    if (props.error) return "bg-[var(--color-accent-red)]";
    return getStatusColor(props.status);
  };

  return (
    <Show
      when={props.status > 0}
      fallback={
        <span class="inline-flex items-center justify-center min-w-[3rem] px-1.5 py-0.5 text-xs font-medium rounded bg-[var(--color-bg-elevated)] text-[var(--color-text-muted)]">
          —
        </span>
      }
    >
      <span
        class={`inline-flex items-center justify-center min-w-[3rem] px-1.5 py-0.5 text-xs font-medium rounded text-[var(--color-bg-primary)] ${color()}`}
      >
        {props.status}
      </span>
    </Show>
  );
};

export default StatusBadge;
