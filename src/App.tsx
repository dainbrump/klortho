import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { ClientConfigurationPage, ServerConfigurationPage, KeyManagementPage, WelcomePage } from "@klortho/features";
import { AppSidebar, ThemeProvider } from "@klortho/components";
import { SidebarProvider } from "@klortho/components/ui/sidebar";
import { Toaster } from "@klortho/components/ui/toaster";
import { useState, useEffect } from 'react';
import { invoke } from "@tauri-apps/api/core";
import "./index.css";

function App() {
  const shutReactRouterUp = {
    v7_startTransition: true,
    v7_fetcherPersist: true,
    v7_normalizeFormMethod: true,
    v7_partialHydration: true,
    v7_relativeSplatPath: true,
    v7_skipActionErrorRevalidation: true
  };

  const [themeData, setThemeData] = useState<{[key: string]: string} | null>(null);

  async function loadTheme() {
    // Currently, the app uses the default colors in the index.css unless it is
    // running under KDE. Then it will use the colors from the KDE theme.
    // Otherwise, the ThemeProvider will use the default colors based on the system
    // color mode (dark or light) as  defined in the index.css file.
    const data: { [key: string]: string } = JSON.parse(await invoke('fetch_theme'));
    setThemeData(data);
    // Inject CSS variables
    if (data) {
      const style = document.documentElement.style;
      for (const [key, value] of Object.entries(data)) {
        // Check if a CSS variable with the same name already exists
        const existingValue = style.getPropertyValue(`--${key}`); 
        // Only set the property if it doesn't already have a value
        if (!existingValue) { 
          style.setProperty(`--${key}`, value);
        }
      }
    }
  }

  useEffect(() => {
    loadTheme();
  }, []);


  return (
    <ThemeProvider defaultTheme="system" storageKey="vite-ui-theme">
      <BrowserRouter future={shutReactRouterUp}>
        <SidebarProvider>
          <AppSidebar />
          <main className='flex flex-col'>
            <Routes>
              <Route path="/" element={<WelcomePage />} />
              <Route path="/client" element={<ClientConfigurationPage />} />
              <Route path="/server" element={<ServerConfigurationPage />} />
              <Route path="/key" element={<KeyManagementPage />} />
            </Routes>
          </main>
        </SidebarProvider>
      </BrowserRouter>
      <Toaster />
    </ThemeProvider>
  );
}

export default App;
