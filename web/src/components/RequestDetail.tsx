import { Component, Show, createSignal, For } from "solid-js";
import {
  useSelectedRecord,
  useSelectedId,
  formatDuration,
  formatBytes,
  getMethodColor,
  getStatusColor,
} from "../stores/requests";
import JsonViewer from "./JsonViewer";

type Tab = "headers" | "payload" | "response";

const RequestDetail: Component = () => {
  const record = useSelectedRecord();
  const selectedId = useSelectedId();
  const [activeTab, setActiveTab] = createSignal<Tab>("headers");

  return (
    <Show
      when={selectedId()}
      fallback={
        <div class="flex items-center justify-center h-full text-[var(--color-text-muted)]">
          <div class="text-center">
            <div class="text-3xl mb-3">👈</div>
            <div class="text-sm">Select a request to view details</div>
          </div>
        </div>
      }
    >
      <Show
        when={record()}
        fallback={
          <div class="flex items-center justify-center h-full">
            <div class="animate-pulse text-[var(--color-text-muted)]">Loading...</div>
          </div>
        }
      >
        {(r) => (
          <div class="flex flex-col h-full overflow-hidden">
            {/* Request summary header */}
            <div class="flex-shrink-0 p-4 border-b border-[var(--color-border-default)] bg-[var(--color-bg-secondary)]">
              <div class="flex items-center gap-3 mb-2">
                <span
                  class={`inline-flex items-center justify-center min-w-[3rem] px-2 py-1 text-xs font-bold rounded ${getStatusColor(r().status)} text-[var(--color-bg-primary)]`}
                >
                  {r().status || "—"}
                </span>
                <span class={`font-mono font-semibold ${getMethodColor(r().method)}`}>
                  {r().method}
                </span>
                <span class="font-mono text-sm text-[var(--color-text-primary)] truncate flex-1">
                  {r().url}
                </span>
              </div>
              <div class="flex items-center gap-4 text-xs text-[var(--color-text-secondary)]">
                <span>
                  <span class="text-[var(--color-text-muted)]">Time: </span>
                  <span class="font-mono">{formatDuration(r().duration)}</span>
                </span>
                <span>
                  <span class="text-[var(--color-text-muted)]">Size: </span>
                  <span class="font-mono">{formatBytes(r().response?.bodySize || 0)}</span>
                </span>
                <span>
                  <span class="text-[var(--color-text-muted)]">Host: </span>
                  <span class="font-mono">{r().host}</span>
                </span>
              </div>
            </div>

            {/* Tabs */}
            <div class="flex-shrink-0 flex border-b border-[var(--color-border-default)] bg-[var(--color-bg-tertiary)]">
              <TabButton
                label="Headers"
                active={activeTab() === "headers"}
                onClick={() => setActiveTab("headers")}
              />
              <TabButton
                label="Payload"
                active={activeTab() === "payload"}
                onClick={() => setActiveTab("payload")}
                badge={r().bodySize > 0 ? formatBytes(r().bodySize) : undefined}
              />
              <TabButton
                label="Response"
                active={activeTab() === "response"}
                onClick={() => setActiveTab("response")}
                badge={r().response?.bodySize ? formatBytes(r().response.bodySize) : undefined}
              />
            </div>

            {/* Tab content */}
            <div class="flex-1 overflow-y-auto p-4">
              <Show when={activeTab() === "headers"}>
                <HeadersTab record={r()} />
              </Show>
              <Show when={activeTab() === "payload"}>
                <PayloadTab body={r().body} />
              </Show>
              <Show when={activeTab() === "response"}>
                <ResponseTab response={r().response} />
              </Show>
            </div>
          </div>
        )}
      </Show>
    </Show>
  );
};

interface TabButtonProps {
  label: string;
  active: boolean;
  onClick: () => void;
  badge?: string;
}

const TabButton: Component<TabButtonProps> = (props) => (
  <button
    type="button"
    class={`px-4 py-2 text-xs font-medium transition-colors relative ${
      props.active
        ? "text-[var(--color-text-primary)] border-b-2 border-[var(--color-accent-blue)]"
        : "text-[var(--color-text-muted)] hover:text-[var(--color-text-secondary)]"
    }`}
    onClick={props.onClick}
  >
    {props.label}
    <Show when={props.badge}>
      <span class="ml-1.5 px-1.5 py-0.5 text-[10px] bg-[var(--color-bg-elevated)] rounded">
        {props.badge}
      </span>
    </Show>
  </button>
);

interface HeadersTabProps {
  record: {
    url: string;
    method: string;
    status: number;
    headers: Record<string, string>;
    response?: {
      status: number;
      statusText: string;
      headers: Record<string, string>;
    };
  };
}

const HeadersTab: Component<HeadersTabProps> = (props) => (
  <div class="space-y-6">
    {/* General */}
    <section>
      <h3 class="text-xs font-semibold text-[var(--color-text-muted)] uppercase tracking-wide mb-3">
        General
      </h3>
      <div class="space-y-1.5 text-[12px] font-mono">
        <HeaderRow label="Request URL" value={props.record.url} />
        <HeaderRow label="Request Method" value={props.record.method} />
        <HeaderRow
          label="Status Code"
          value={`${props.record.response?.status || props.record.status} ${props.record.response?.statusText || ""}`}
        />
      </div>
    </section>

    {/* Response Headers */}
    <Show when={props.record.response?.headers}>
      <section>
        <h3 class="text-xs font-semibold text-[var(--color-text-muted)] uppercase tracking-wide mb-3">
          Response Headers
        </h3>
        <div class="space-y-1.5 text-[12px] font-mono">
          <For each={Object.entries(props.record.response!.headers)}>
            {([key, value]) => <HeaderRow label={key} value={value} />}
          </For>
        </div>
      </section>
    </Show>

    {/* Request Headers */}
    <Show when={props.record.headers && Object.keys(props.record.headers).length > 0}>
      <section>
        <h3 class="text-xs font-semibold text-[var(--color-text-muted)] uppercase tracking-wide mb-3">
          Request Headers
        </h3>
        <div class="space-y-1.5 text-[12px] font-mono">
          <For each={Object.entries(props.record.headers)}>
            {([key, value]) => <HeaderRow label={key} value={value} />}
          </For>
        </div>
      </section>
    </Show>
  </div>
);

interface HeaderRowProps {
  label: string;
  value: string;
}

const HeaderRow: Component<HeaderRowProps> = (props) => (
  <div class="flex gap-2">
    <span class="text-[var(--color-accent-purple)] flex-shrink-0">{props.label}:</span>
    <span class="text-[var(--color-text-primary)] break-all">{props.value}</span>
  </div>
);

interface PayloadTabProps {
  body: string | undefined;
}

const PayloadTab: Component<PayloadTabProps> = (props) => (
  <div>
    <Show
      when={props.body}
      fallback={
        <div class="text-[var(--color-text-muted)] text-sm italic">
          No request payload
        </div>
      }
    >
      <h3 class="text-xs font-semibold text-[var(--color-text-muted)] uppercase tracking-wide mb-3">
        Request Body
      </h3>
      <JsonViewer data={props.body} maxHeight="calc(100vh - 300px)" />
    </Show>
  </div>
);

interface ResponseTabProps {
  response:
    | {
        body?: string;
        bodySize: number;
      }
    | undefined;
}

const ResponseTab: Component<ResponseTabProps> = (props) => (
  <div>
    <Show
      when={props.response?.body}
      fallback={
        <div class="text-[var(--color-text-muted)] text-sm italic">
          No response body
        </div>
      }
    >
      <h3 class="text-xs font-semibold text-[var(--color-text-muted)] uppercase tracking-wide mb-3">
        Response Body
      </h3>
      <JsonViewer data={props.response?.body} maxHeight="calc(100vh - 300px)" />
    </Show>
  </div>
);

export default RequestDetail;
