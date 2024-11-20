import { Sidebar, SidebarContent, SidebarHeader, SidebarMenu, SidebarMenuButton, SidebarMenuItem } from "@klortho/components/ui/sidebar";
import { Avatar, AvatarImage } from "@klortho/components/ui/avatar";
import { Link } from "react-router-dom";
import { AppFeatures } from "./app-features";
import { KlorthoFeature, KlorthoFeatureMap } from "@klortho/features";

export function AppSidebar() {
  const sidebarFeaturesOnly = KlorthoFeatureMap.filter((feature: KlorthoFeature) => {
    if (feature.sidebar) {
      if (feature.items && feature.items.length) {
        feature.items.filter((item) => item.sidebar);
      }
      return feature;
    }
  });

  return (
    <Sidebar>
      <SidebarHeader>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton asChild>
              <Link to="/">
                <Avatar className="h-8 w-8 rounded-lg">
                  <AvatarImage src="/klortho.png" alt="Klortho" />
                </Avatar>
                <div className="grid flex-1 text-left text-sm leading-tight">
                  <span className="truncate font-semibold">Klortho</span>
                  <span className="truncate text-xs">Easy SSH Management</span>
                </div>
              </Link>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarHeader>
      <SidebarContent>
        <AppFeatures features={sidebarFeaturesOnly} />
      </SidebarContent>
    </Sidebar>
  )
}
