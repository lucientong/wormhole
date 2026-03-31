import { Component, onMount } from "solid-js";
import Layout from "./components/Layout";
import RequestList from "./components/RequestList";
import RequestDetail from "./components/RequestDetail";
import { initStore } from "./stores/requests";

const App: Component = () => {
  onMount(() => {
    initStore();
  });

  return (
    <Layout>
      <div class="flex h-full">
        {/* Request list (left panel) */}
        <div class="w-2/5 min-w-[320px] max-w-[600px] border-r border-[var(--color-border-default)] bg-[var(--color-bg-secondary)]">
          <RequestList />
        </div>

        {/* Request detail (right panel) */}
        <div class="flex-1 bg-[var(--color-bg-secondary)]">
          <RequestDetail />
        </div>
      </div>
    </Layout>
  );
};

export default App;
