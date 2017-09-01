# XenApp/XenDesktop Session State Monitor
The Session State Monitor Utility actively monitors remote connections and disconnections in the session for which it’s running. The utility provides the ability to specify custom commands for Disconnect, Reconnect, and Startup. The utility also has the ability to allow the endpoint (client) name to smooth roam in double-hop sessions to the second hop. The utility does this by disconnecting the session from first hop to second hop, updating the appropriate registry key for ‘clientname’, and then reconnecting the disconnected first hop to second hop session.

## Getting Started
To start using the SessionState Monitor Tool, read https://support.citrix.com/article/CTX127491.

### Prerequisites
Caution! When using this tool to update the clientname on a Pass-through XenApp session, 
the full 12.x client plug-in must be installed on the first hop and the client must have fix 215510. 
The public ICA client version 12.3 contains fix 215510.

Note: If using Windows Receiver 3.0/13.0 (or greater) and performing clientname Pass-through, 
Virtual Channel Driver must be used instead of Session State Monitor. 
Due to design changes in the receiver disallowing ‘reconnects’, 
Virtual Channel Driver has been released to allow real-time querying of clientname over a custom virtual channel. 
VCD does not disconnect and reconnect the session as Session State Monitor does with a 12.x client. 
VCD does require additional setup and configuration on both the client and server. 
See http://support.citrix.com/article/CTX129961 for additional information on this utility.

## Built
Building Session State Monitoring requires Visual Studio 2010 or later with .NET 3.5 or later tooling.  
To build, load SessionStateMonitor.sln in Visual Studio and build SessionStateMonitor.

## Contributing
Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct, and the process for submitting pull requests to us.

## License
The Session State Monitor Tools project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.  
Examples may use a different license (see LICENSE.md file in the example directory for details).
