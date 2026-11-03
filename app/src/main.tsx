import React, { Suspense, lazy } from "react";
import ReactDOM from "react-dom/client";
import "@fontsource-variable/space-grotesk";
import { installDevMock } from "./devMock";

const params = new URLSearchParams(location.search);

if (import.meta.env.DEV) {
  installDevMock();
  // ?shot: niente animazioni, per screenshot stabili.
  if (params.has("shot")) document.documentElement.classList.add("no-anim");
}

// La stessa interfaccia serve due tipi di finestra: l'app principale e gli avvisi
// a popup (?toast=<id>). Caricamento separato: ognuna porta solo i propri stili.
const App = lazy(() => import("./App"));
const ToastView = lazy(() => import("./Toast"));
const toastId = params.get("toast");

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <Suspense fallback={null}>{toastId ? <ToastView id={Number(toastId)} /> : <App />}</Suspense>
  </React.StrictMode>,
);
