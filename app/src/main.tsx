import React from "react";
import ReactDOM from "react-dom/client";
import "@fontsource-variable/space-grotesk";
import App from "./App";
import { installDevMock } from "./devMock";

if (import.meta.env.DEV) {
  installDevMock();
  // ?shot: niente animazioni, per screenshot stabili.
  if (new URLSearchParams(location.search).has("shot")) document.documentElement.classList.add("no-anim");
}

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
