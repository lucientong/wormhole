import { Component, createMemo, Show, For } from "solid-js";

interface JsonViewerProps {
  data: string | undefined;
  maxHeight?: string;
}

const JsonViewer: Component<JsonViewerProps> = (props) => {
  const formatted = createMemo(() => {
    if (!props.data) return null;

    try {
      // Try to parse as JSON
      const parsed = JSON.parse(props.data);
      return {
        type: "json" as const,
        data: parsed,
      };
    } catch {
      // Return as raw text
      return {
        type: "text" as const,
        data: props.data,
      };
    }
  });

  return (
    <div
      class="font-mono text-[12px] leading-relaxed overflow-auto bg-[var(--color-bg-primary)] rounded p-3"
      style={{ "max-height": props.maxHeight || "400px" }}
    >
      <Show
        when={formatted()}
        fallback={
          <span class="text-[var(--color-text-muted)] italic">No content</span>
        }
      >
        {(f) => (
          <Show
            when={f().type === "json"}
            fallback={
              <pre class="whitespace-pre-wrap break-all text-[var(--color-text-primary)]">
                {f().data as string}
              </pre>
            }
          >
            <JsonNode value={f().data} depth={0} />
          </Show>
        )}
      </Show>
    </div>
  );
};

interface JsonNodeProps {
  value: unknown;
  depth: number;
  keyName?: string;
}

const JsonNode: Component<JsonNodeProps> = (props) => {
  const indent = () => props.depth * 16;

  const renderValue = () => {
    const val = props.value;

    if (val === null) {
      return <span class="text-[var(--color-accent-purple)]">null</span>;
    }

    if (typeof val === "boolean") {
      return (
        <span class="text-[var(--color-accent-purple)]">
          {val ? "true" : "false"}
        </span>
      );
    }

    if (typeof val === "number") {
      return <span class="text-[var(--color-accent-blue)]">{val}</span>;
    }

    if (typeof val === "string") {
      return (
        <span class="text-[var(--color-accent-green)]">"{val}"</span>
      );
    }

    if (Array.isArray(val)) {
      if (val.length === 0) {
        return <span class="text-[var(--color-text-muted)]">[]</span>;
      }
      return (
        <span>
          <span class="text-[var(--color-text-muted)]">[</span>
          <div>
            <For each={val}>
              {(item, i) => (
                <div style={{ "padding-left": `${indent() + 16}px` }}>
                  <JsonNode value={item} depth={props.depth + 1} />
                  <Show when={i() < val.length - 1}>
                    <span class="text-[var(--color-text-muted)]">,</span>
                  </Show>
                </div>
              )}
            </For>
          </div>
          <span style={{ "padding-left": `${indent()}px` }} class="text-[var(--color-text-muted)]">]</span>
        </span>
      );
    }

    if (typeof val === "object") {
      const entries = Object.entries(val as Record<string, unknown>);
      if (entries.length === 0) {
        return <span class="text-[var(--color-text-muted)]">{"{}"}</span>;
      }
      return (
        <span>
          <span class="text-[var(--color-text-muted)]">{"{"}</span>
          <div>
            <For each={entries}>
              {([key, v], i) => (
                <div style={{ "padding-left": `${indent() + 16}px` }}>
                  <span class="text-[var(--color-accent-red)]">"{key}"</span>
                  <span class="text-[var(--color-text-muted)]">: </span>
                  <JsonNode value={v} depth={props.depth + 1} keyName={key} />
                  <Show when={i() < entries.length - 1}>
                    <span class="text-[var(--color-text-muted)]">,</span>
                  </Show>
                </div>
              )}
            </For>
          </div>
          <span style={{ "padding-left": `${indent()}px` }} class="text-[var(--color-text-muted)]">{"}"}</span>
        </span>
      );
    }

    return <span class="text-[var(--color-text-primary)]">{String(val)}</span>;
  };

  return <>{renderValue()}</>;
};

export default JsonViewer;
