import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./styles/theme.css";
import { App } from "./App";
import { appStore } from "./store/appStore";

appStore.init();

const rootEl = document.getElementById("root");
if (rootEl) {
  createRoot(rootEl).render(
    <StrictMode>
      <App />
    </StrictMode>
  );
}
