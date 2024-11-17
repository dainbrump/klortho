
import { KeySquare, ServerCog, MonitorCog } from "lucide-react";
import {
  Sidebar,
  SidebarContent,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from "@klortho/components/ui/sidebar";
import { Link } from "react-router-dom";

const items = [
  {
    title: "Client Configuration",
    url: "/client",
    icon: MonitorCog,
  },
  {
    title: "Server Configuration",
    url: "/server",
    icon: ServerCog,
  },
  {
    title: "Key Manager",
    url: "/key",
    icon: KeySquare,
  }
]

export function AppSidebar() {
  return (
    <Sidebar>
      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupLabel><Link to="/">Klortho</Link></SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {items.map((item) => (
                <SidebarMenuItem key={item.title}>
                  <SidebarMenuButton asChild>
                    <Link to={item.url}>
                      <item.icon />
                      <span>{item.title}</span>
                    </Link>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              ))}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>
    </Sidebar>
  )
}
