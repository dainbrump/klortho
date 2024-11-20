import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { AppSidebar, ThemeProvider } from "@klortho/components";
import { SidebarProvider, SidebarInset } from "@klortho/components/ui/sidebar";
import { Toaster } from "@klortho/components/ui/toaster";
import { useEffect } from 'react';
import { invoke } from "@tauri-apps/api/core";
import { KlorthoFeatureMap, KlorthoFeature } from "@klortho/features";
import "./index.css";

function App() {
  const silenceRRDomWarnings = {
    v7_startTransition: true,
    v7_fetcherPersist: true,
    v7_normalizeFormMethod: true,
    v7_partialHydration: true,
    v7_relativeSplatPath: true,
    v7_skipActionErrorRevalidation: true
  };

  async function loadTheme() {
    // Currently, the app uses the default colors in the index.css unless it is
    // running under KDE. Then it will use the colors from the KDE theme.
    // Otherwise, the ThemeProvider will use the default colors based on the system
    // color mode (dark or light) as  defined in the index.css file.
    const data: { [key: string]: string } = JSON.parse(await invoke('fetch_theme'));
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

  const approutes: KlorthoFeature[] = KlorthoFeatureMap.reduce((_flat: KlorthoFeature[], route) => {
    let _T:KlorthoFeature[] = [];
    if (route.items && route.items.length > 0) {
      _T = _T.concat(route.items.filter((item: KlorthoFeature) => item.path !== undefined && item.component !== undefined));
    }
    if (route.path !== undefined && route.component !== undefined) {
      _T = _T.concat([route]);
    }
    return _flat.concat(_T);
  }, []);

  return (
    <ThemeProvider defaultTheme="system" storageKey="vite-ui-theme">
      <BrowserRouter future={silenceRRDomWarnings}>
        <SidebarProvider>
          <AppSidebar />
          <SidebarInset>
            <Routes>
              {approutes.map((route) => <Route key={route.path} path={route.path} Component={route.component} />)}
            </Routes>
          </SidebarInset>
        </SidebarProvider>
      </BrowserRouter>
      <Toaster />
    </ThemeProvider>
  );
}

export default App;
