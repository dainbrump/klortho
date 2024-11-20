import { ChevronRight } from "lucide-react"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@klortho/components/ui/collapsible"
import { SidebarGroup, SidebarMenu, SidebarMenuButton, SidebarMenuItem,
  SidebarMenuSub, SidebarMenuSubButton, SidebarMenuSubItem } from "@klortho/components/ui/sidebar"
import { KlorthoFeature } from "@klortho/features";
import { Link } from "react-router-dom";

type AppFeaturesProps = {
  features: KlorthoFeature[]
};

export function AppFeatures({ features }: { features: AppFeaturesProps["features"]}) {
  return (
    <SidebarGroup>
      <SidebarMenu>
        {features.map((feature) => (
          feature.sidebar && feature.items?.length ? (
          <Collapsible key={feature.title} asChild defaultOpen={feature.isActive} className="group/collapsible">
            <SidebarMenuItem>
              <CollapsibleTrigger asChild>
                <SidebarMenuButton tooltip={feature.title}>
                  {feature.icon && <feature.icon />}
                  <span>{feature.title}</span>
                  <ChevronRight className="ml-auto transition-transform duration-200 group-data-[state=open]/collapsible:rotate-90" />
                </SidebarMenuButton>
              </CollapsibleTrigger>
              <CollapsibleContent>
                <SidebarMenuSub>
                  {feature.items?.map((subItem) => (
                    <SidebarMenuSubItem key={subItem.title}>
                      <SidebarMenuSubButton asChild>
                        {subItem.path ? <Link to={subItem.path}>{subItem.title}</Link> : <span>{subItem.title}</span>}
                      </SidebarMenuSubButton>
                    </SidebarMenuSubItem>
                  ))}
                </SidebarMenuSub>
              </CollapsibleContent>
            </SidebarMenuItem>
          </Collapsible>
        ) : (
          <SidebarMenuItem>
            <SidebarMenuButton tooltip={feature.title} asChild>
              <div>
                {feature.icon && <feature.icon />}
                {feature.path ? <Link to={feature.path}>{feature.title}</Link> : <span>{feature.title}</span>}
              </div>
            </SidebarMenuButton>
          </SidebarMenuItem>
          )
        ))}
      </SidebarMenu>
    </SidebarGroup>
  )
}