import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Route, Routes, NavLink } from "react-router-dom";
import { Activity, AlertTriangle, BarChart2, FileSearch, Home } from "lucide-react";
import Dashboard from "./pages/Dashboard";
import Incidents from "./pages/Incidents";
import IncidentDetail from "./pages/IncidentDetail";
import Logs from "./pages/Logs";
import Metrics from "./pages/Metrics";

const queryClient = new QueryClient({
  defaultOptions: { queries: { staleTime: 15_000, refetchInterval: 30_000 } },
});

const navItems = [
  { to: "/", label: "Overview", icon: Home },
  { to: "/incidents", label: "Incidents", icon: AlertTriangle },
  { to: "/logs", label: "Logs", icon: FileSearch },
  { to: "/metrics", label: "Metrics", icon: BarChart2 },
];

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <div className="flex min-h-screen bg-gray-950 text-gray-100">
          {/* Sidebar */}
          <aside className="w-56 shrink-0 border-r border-gray-800 bg-gray-900 flex flex-col">
            <div className="p-4 border-b border-gray-800 flex items-center gap-2">
              <Activity className="text-blue-400" size={20} />
              <span className="font-semibold text-sm">AI Observability</span>
            </div>
            <nav className="flex-1 p-3 space-y-1">
              {navItems.map(({ to, label, icon: Icon }) => (
                <NavLink
                  key={to}
                  to={to}
                  end={to === "/"}
                  className={({ isActive }) =>
                    `flex items-center gap-2 px-3 py-2 rounded-md text-sm transition-colors ${
                      isActive
                        ? "bg-blue-600 text-white"
                        : "text-gray-400 hover:bg-gray-800 hover:text-gray-100"
                    }`
                  }
                >
                  <Icon size={16} />
                  {label}
                </NavLink>
              ))}
            </nav>
            <div className="p-3 border-t border-gray-800 text-xs text-gray-500">
              v1.0.0
            </div>
          </aside>

          {/* Main content */}
          <main className="flex-1 overflow-auto">
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/incidents" element={<Incidents />} />
              <Route path="/incidents/:id" element={<IncidentDetail />} />
              <Route path="/logs" element={<Logs />} />
              <Route path="/metrics" element={<Metrics />} />
            </Routes>
          </main>
        </div>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
