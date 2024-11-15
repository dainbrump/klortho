import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { ClientConfigurationPage, ServerConfigurationPage, KeyManagementPage } from "@klortho/features";
import { AppSidebar, ThemeProvider } from "@klortho/components";
import { SidebarProvider } from "@klortho/components/ui/sidebar";
import "./index.css";

function App() {
  return (
    <ThemeProvider defaultTheme="system" storageKey="vite-ui-theme">
      <BrowserRouter>
        <SidebarProvider>
          <AppSidebar />
          <main>
            <Routes>
              <Route path="/client" element={<ClientConfigurationPage />} />
              <Route path="/server" element={<ServerConfigurationPage />} />
              <Route path="/key" element={<KeyManagementPage />} />
            </Routes>
          </main>
        </SidebarProvider>
      </BrowserRouter>
    </ThemeProvider>
  );
}

export default App;
