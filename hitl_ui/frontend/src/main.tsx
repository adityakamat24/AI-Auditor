import React from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import NavBar from "./components/NavBar";
import { ToastProvider } from "./components/Toast";
import { AuthProvider } from "./context/AuthContext";
import { ChatProvider } from "./context/ChatContext";
import { ThemeProvider } from "./context/ThemeContext";
import "./index.css";
import Calibration from "./pages/Calibration";
import IncidentDetail from "./pages/IncidentDetail";
import IncidentQueue from "./pages/IncidentQueue";
import ReviewQueue from "./pages/ReviewQueue";
import RunAgent from "./pages/RunAgent";
import RunReplay from "./pages/RunReplay";
import Settings from "./pages/Settings";
import ShadowView from "./pages/ShadowView";
import TraceDetail from "./pages/TraceDetail";

function App(): React.ReactElement {
  return (
    <ThemeProvider>
      <ToastProvider>
        <AuthProvider>
          <ChatProvider>
            <BrowserRouter>
            <div className="min-h-screen bg-gray-50 dark:bg-gray-950 text-gray-900 dark:text-gray-100 antialiased" style={{ fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', sans-serif" }}>
              <NavBar />
              <main>
                <Routes>
                  <Route path="/" element={<Navigate to="/run" replace />} />
                  <Route path="/run" element={<RunAgent />} />
                  <Route path="/queue" element={<ReviewQueue />} />
                  <Route path="/flags/:flagId" element={<TraceDetail />} />
                  <Route path="/runs/:runId/replay" element={<RunReplay />} />
                  <Route path="/calibration" element={<Calibration />} />
                  <Route path="/incidents" element={<IncidentQueue />} />
                  <Route path="/incidents/:incidentId" element={<IncidentDetail />} />
                  <Route path="/shadow" element={<ShadowView />} />
                  <Route path="/settings" element={<Settings />} />
                  <Route
                    path="*"
                    element={
                      <div className="p-8 text-gray-500 dark:text-gray-400 text-center">
                        404 - page not found.{" "}
                        <a href="/run" className="text-indigo-600 dark:text-indigo-400 underline">
                          Back to console
                        </a>
                      </div>
                    }
                  />
                </Routes>
              </main>
            </div>
            </BrowserRouter>
          </ChatProvider>
        </AuthProvider>
      </ToastProvider>
    </ThemeProvider>
  );
}

const container = document.getElementById("root");
if (container) {
  createRoot(container).render(<App />);
}
