// Page components
import NewClientConfPage from './ClientConfiguration/NewClientConfPage';
import LoadClientConfPage from './ClientConfiguration/LoadClientConfPage';
import ClientConfSettingsPage from './ClientConfiguration/ClientConfSettingsPage';
import NewServerConfPage from './ServerConfiguration/NewServerConfPage';
import LoadServerConfPage from './ServerConfiguration/LoadServerConfPage';
import ServerConfSettingsPage from './ServerConfiguration/ServerConfSettingsPage';
import KeyManagementPage from './KeyManagement/KeyManagementPage';
import GenerateKeysPage from './KeyManagement/GenerateKeysPage';
import ImportKeysPage from './KeyManagement/ImportKeysPage';
import KeyManagementSettingsPage from './KeyManagement/KeyManagementSettingsPage';
import KlorthoSettingsPage from './Settings/KlorthoSettingsPage';
import WelcomePage from './Welcome/WelcomePage';

// Page sub components
import HostEntry from './ClientConfiguration/HostEntry/HostEntry';
import HostEntryForm from './ClientConfiguration/HostEntry/HostEntryForm';

import {
  KeySquare,
  ServerCog,
  MonitorCog,
  Settings,
  type LucideIcon
} from "lucide-react";

export type KlorthoFeature = {
  title: string;
  sidebar?: boolean;
  path?: string;
  component?: React.ComponentType;
  icon?: LucideIcon;
  isActive?: boolean;
  items?: KlorthoFeature[];
};

const KlorthoFeatureMap: KlorthoFeature[] = [
  {
    title: "Client Configuration",
    sidebar: true,
    icon: MonitorCog,
    items: [
      {
        title: "New configuration",
        sidebar: true,
        path: "/client-new",
        component: NewClientConfPage,
      },
      {
        title: "Load configuration",
        sidebar: true,
        path: "/client-load",
        component: LoadClientConfPage,
      },
      {
        title: "Client Defaults",
        sidebar: true,
        path: "/client-settings",
        component: ClientConfSettingsPage,
      },
    ],
  },
  {
    title: "Server Configuration",
    sidebar: true,
    icon: ServerCog,
    items: [
      {
        title: "New configuration",
        sidebar: true,
        path: "/server-new",
        component: NewServerConfPage,
      },
      {
        title: "Load configuration",
        sidebar: true,
        path: "/server-load",
        component: LoadServerConfPage
      },
      {
        title: "Server Defaults",
        sidebar: true,
        path: "/server-settings",
        component: ServerConfSettingsPage
      },
    ],
  },
  {
    title: "Key Manager",
    sidebar: true,
    icon: KeySquare,
    items: [
      {
        title: "Key Management",
        sidebar: true,
        path: "/key",
        component: KeyManagementPage,
      },
      {
        title: "Generate keys",
        sidebar: true,
        path: "/key-generate",
        component: GenerateKeysPage,
      },
      {
        title: "Import keys",
        sidebar: true,
        path: "/key-import",
        component: ImportKeysPage,
      },
      {
        title: "Key Management Defaults",
        sidebar: true,
        path: "/key-settings",
        component: KeyManagementSettingsPage,
      },
    ],
  },
  {
    title: "Settings",
    sidebar: true,
    icon: Settings,
    path: "/settings",
    component: KlorthoSettingsPage,
  },
  {
    title: "Klortho",
    sidebar: false,
    path: "/",
    component: WelcomePage,
  },
];

export {
  NewClientConfPage,
  LoadClientConfPage,
  ClientConfSettingsPage,
  NewServerConfPage,
  LoadServerConfPage,
  ServerConfSettingsPage,
  KeyManagementPage,
  GenerateKeysPage,
  ImportKeysPage,
  KeyManagementSettingsPage,
  KlorthoSettingsPage,
  WelcomePage,
  HostEntry,
  HostEntryForm,
  KlorthoFeatureMap
};

