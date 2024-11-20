import { Card, CardContent, CardHeader, CardFooter, CardTitle, CardDescription } from "@klortho/components/ui/card"
import { Button } from "@klortho/components/ui/button"
import { Link } from "react-router-dom";
import { KeySquare, ServerCog, MonitorCog } from "lucide-react"

function WelcomePage () {
  return (
    <div className="klortho-feature-page">
      <h1>Welcome to Klortho</h1>
      <div className="grid grid-cols-3 gap-4 py-4">
        <Card>
          <CardHeader>
            <CardTitle>
              <MonitorCog size={48} />
              <span>Client Configuration</span>
            </CardTitle>
            <CardDescription>Manage your existing SSH Client configuration or create new configurations.</CardDescription>
          </CardHeader>
          <CardContent>
            <p>From here, you can manage your SSH Client configuration files and settings.</p>
          </CardContent>
          <CardFooter className="flex justify-between">
            <Button asChild>
              <Link to="/client">Client Configuration</Link>
            </Button>
          </CardFooter>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>
              <ServerCog size={48} />
              <span>Server Configuration</span>
            </CardTitle>
            <CardDescription>Manage your existing SSH Server configuration or create new configurations.</CardDescription>
          </CardHeader>
          <CardContent>
            <p>From here, you can manage your SSH Server configuration files and settings.</p>
          </CardContent>
          <CardFooter className="flex justify-between">
            <Button asChild>
              <Link to="/server">Server Configuration</Link>
            </Button>
          </CardFooter>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>
              <KeySquare size={48} />
              <span>Key Management</span>
            </CardTitle>
            <CardDescription>Manage your existing SSH public / private keys or create new ones.</CardDescription>
          </CardHeader>
          <CardContent>
            <p>From here, you can manage or create SSH public / private keys.</p>
          </CardContent>
          <CardFooter className="flex justify-between">
            <Button asChild>
              <Link to="/key">Key Management</Link>
            </Button>
          </CardFooter>
        </Card>
      </div>
    </div>
  );
}

export default WelcomePage;
