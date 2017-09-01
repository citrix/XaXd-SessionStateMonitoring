// ============================================================================
// Copyright Citrix Systems, Inc. All rights reserved.
// ============================================================================

namespace ClientName
{
    using System;
    using System.Collections;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Drawing;
    using System.IO;
    using System.Runtime.InteropServices;
    using System.Security.Permissions;
    using System.Text;
    using System.Text.RegularExpressions;
    using System.Threading;
    using System.Windows.Forms;

    using Microsoft.Win32;

    #region Enumerations

    public enum WF_CONNECTSTATE_CLASS
    {
        WFActive,
        WFConnected,
        WFConnectQuery,
        WFShadow,
        WFDisconnected,
        WFIdle,
        WFListen,
        WFReset,
        WFDown,
        WFInit
    }

    public enum WF_INFO_CLASS
    {
        WFVersion,
        WFInitialProgram,
        WFWorkingDirectory,
        WFOEMId,
        WFSessionId,
        WFUserName,
        WFWinStationName,
        WFDomainName,
        WFConnectState,
        WFClientBuildNumber,
        WFClientName,
        WFClientDirectory,
        WFClientProductId,
        WFClientHardwareId,
        WFClientAddress,
        WFClientDisplay,
        WFClientCache,
        WFClientDrives,
        WFICABufferLength,
        WFLicenseEnabler,
        RESERVED2,
        WFApplicationName,
        WFVersionEx,
        WFClientInfo,
        WFUserInfo,
        WFAppInfo,
        WFClientLatency,
        WFSessionTime
    }

    enum WTSInfoClass
    {
        WTSInitialProgram,
        WTSApplicationName,
        WTSWorkingDirectory,
        WTSOEMId,
        WTSSessionId,
        WTSUserName,
        WTSWinStationName,
        WTSDomainName,
        WTSConnectState,
        WTSClientBuildNumber,
        WTSClientName,
        WTSClientDirectory,
        WTSClientProductId,
        WTSClientHardwareId,
        WTSClientAddress,
        WTSClientDisplay,
        WTSClientProtocolType,
        WTSIdleTime,
        WTSLogonTime,
        WTSIncomingBytes,
        WTSOutgoingBytes,
        WTSIncomingFrames,
        WTSOutgoingFrames,
        WTSClientInfo,
        WTSSessionInfo
    }

    #endregion Enumerations

    [StructLayout(LayoutKind.Sequential)]
    public struct WF_CLIENT_ADDRESS
    {
        public int AddressFamily;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 20)]
        public byte[] Address;
    }

    class ClientName : System.Windows.Forms.Form, System.IDisposable
    {
        #region Fields

        public const int AF_INET = 2;
        public const int AF_IPX = 6;
        public const int AF_NETBIOS = 17;
        public const int AF_UNSPEC = 0;
        public const int WF_CURRENT_SESSION = -1;

        public static IntPtr WTS_CURRENT_SERVER_HANDLE = IntPtr.Zero;
        public static int WTS_CURRENT_SESSION = -1;
        public static bool _connectEvent = true;

        //static Thread _windowThread;
        public static AutoResetEvent _windowMessageEvent = new AutoResetEvent(false);

        public IntPtr WF_CURRENT_SERVER = IntPtr.Zero;

        const int SMTO_ABORTIFHUNG = 0x0002;
        const UInt32 WM_SETTINGCHANGE = 0x001A;

        static IntPtr HWND_BROADCAST = (IntPtr)0xffff;
        static string _clientnameName = "CLIENTNAME";
        static ClientName _cn;
        static WFSession _currentSessionInfo = new WFSession();
        static ArrayList _DisconnectCommands = new ArrayList();
        // used to determine if client name should be set and whether _passthroughreconnectcommands are processed
        static bool _enablePassthroughCommands = false; 
        static string _environmentNameRegPath = "HKEY_CURRENT_USER\\Environment";

        //static String _serverName = null;
        static string _hiveKeyName = string.Empty;
        static string _hkcu = "HKEY_CURRENT_USER\\SOFTWARE\\Citrix\\ICA Client\\Engine\\Lockdown Profiles\\All Regions\\Lockdown\\Client Engine";
        static string _hkcuConfigurationKey = "HKEY_CURRENT_USER\\SOFTWARE\\CITRIX\\SessionStateMonitor\\";
        static string _hklm = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Citrix\\ICA Client\\Engine\\Lockdown Profiles\\All Regions\\Lockdown\\Client Engine";
        static string _hklmConfigurationKey = "HKEY_LOCAL_MACHINE\\SOFTWARE\\CITRIX\\SessionStateMonitor\\";
        static string _icaClientInstallPathKey = "HKEY_LOCAL_MACHINE\\SOFTWARE\\CITRIX\\Install\\ICA Client\\";
        static string _icaClientInstallPathName = "InstallFolder";
        static string _logfile;
        static ArrayList _PassthroughDisconnectCommands = new ArrayList();
        static ArrayList _PassthroughReconnectCommands = new ArrayList();
        static string _previousSessionsName = "PreviousSessions";
        static ArrayList _ReconnectCommands = new ArrayList();
        static bool _setClientName = false;
        static int _setClientNameRetry = 0;
        static ArrayList _StartupCommands = new ArrayList();
        static string _volatileEnvironmentNameRegPath = "HKEY_CURRENT_USER\\Volatile Environment";
        private static string _clientAddressName = "ClientAddress";

        #endregion Fields

        #region Methods

        [DllImport("wtsapi32.dll", SetLastError = false)]
        public static extern void WTSFreeMemory(IntPtr memory);

        [DllImport("Wtsapi32.dll")]
        public static extern bool WTSQuerySessionInformation(
            System.IntPtr hServer, int sessionId, WTSInfoClass wtsInfoClass, out System.IntPtr ppBuffer, out uint pBytesReturned);

        void IDisposable.Dispose()
        {
            throw new Exception("The method or operation is not implemented.");
        }

        /// <summary>
        /// Windows Message Pump handler.
        /// </summary>
        /// <param name="m">Message</param>
        protected override void WndProc(ref Message m)
        {

            if (m.Msg == WTS_SESSION_NOTIFICATION.WM_WTSSESSION_CHANGE)
            {
                WriteOutput(string.Format("WndProc:Received WM_WTSSESSION_CHANGE:{0}",m.WParam.ToInt32()));
                int value = m.WParam.ToInt32();
                if (value == WTS_SESSION_NOTIFICATION.WTS_CONSOLE_DISCONNECT
                    || value == WTS_SESSION_NOTIFICATION.WTS_REMOTE_DISCONNECT)
                {
                    ProcessEvent(WF_CONNECTSTATE_CLASS.WFDisconnected);
                }
                else if (value == WTS_SESSION_NOTIFICATION.WTS_CONSOLE_CONNECT
                    || value == WTS_SESSION_NOTIFICATION.WTS_REMOTE_CONNECT)
                {
                    ProcessEvent(WF_CONNECTSTATE_CLASS.WFConnected);
                }

            }
            base.WndProc(ref m);
        }

        /// <summary>
        /// Main Function.
        /// </summary>
        /// <param name="args"></param>
        [STAThread]
        static void Main(string[] args)
        {
            try
            {
                //make sure only one instance per session.
                bool firstInstance;
                Mutex mutex = new Mutex(false, "Local\\SessionStateMonitor", out firstInstance);
                if (!firstInstance)
                {
                    WriteOutput("not first instance. exiting!");
                    return;
                }
                _cn = new ClientName();

                if (!WTSRegisterSessionNotification(_cn.Handle, WTS_SESSION_NOTIFICATION.NOTIFY_FOR_THIS_SESSION))
                {
                    WriteOutput("handle:" + _cn.Handle.ToString());
                    WriteOutput(Marshal.GetLastWin32Error().ToString());
                    Marshal.ThrowExceptionForHR(Marshal.GetLastWin32Error());
                    return;
                }

                //load current session info
                _currentSessionInfo = QuerySessionInformation();

                //Read Config
                if (!ClientName.ReadConfig() && args.Length < 1) return;

                if (IntPtr.Size == 32)
                {
                    WriteOutput("OS bit = 32.");
                }
                else
                {
                    WriteOutput("OS bit = 64. Make sure to populate values under Wow6432node reg key");
                }

                if (args.Length < 1)
                {
                    UpdateClientName(true);
                    WriteOutput(Application.ProductVersion);
                    WriteOutput("Starting Monitor");
                    WriteOutput("------------------");
                    //process startup commands from registry
                    ProcessCommands(_StartupCommands);

                    Application.Run();
                    WriteOutput("terminated");
                }
                else
                {
                    for (int i = 0; i < args.Length; i++)
                    {
                        WriteOutput(string.Format("arg {0}:{1}", i.ToString(), args[i].ToString()));
                        switch (args[i].ToLower().ToString())
                        {
                            case @"/?":
                                WriteOutput(@"Used to monitor Citrix session state and run commands");
                                WriteOutput(@"Use /setclientname argument to query and set clientname variables once then exit");
                                return;

                            case @"/setclientname":
                                UpdateClientName(true);
                                break;
                            default:
                                break;
                        }
                    }
                }
                GC.KeepAlive(mutex);
                GC.KeepAlive(_cn);
            }
            catch (Exception e)
            {
                WriteOutput(string.Format("Main exception: {0}", e.ToString()));
            }
        }

        /// <summary>
        /// Parses all commands specified in arraylist to determine command and arguments for command.
        /// </summary>
        /// <param name="commands">ArrayList of command strings.</param>
        private static void ProcessCommands(ArrayList commands)
        {
            
            try
            {
                WriteOutput("ProcessCommands:enter:");
                string arguments = String.Empty;
                string command = String.Empty;
                bool commandset = false;
                string cleanarg = String.Empty;
                string cleancmd = String.Empty;
                Regex re;

                foreach (string cmd in commands)
                {
                    WriteOutput("ProcessCommands command:" + cmd);
                    if (cmd.Trim().Length < 1) continue;

                    List<string> args = new List<string>();
                    args.AddRange(cmd.Split(new char[] { ' ' }));

                    //looking for quoted strings
                    re = new Regex("(^\".*\")|(.*)");
                    MatchCollection reMatch = re.Matches(cmd);
                    re = new Regex("\"");
                    cleancmd = re.Replace(reMatch[0].ToString(), "");
                    cleanarg = re.Replace(reMatch[1].ToString(), "");

                    //if file found from quoted string, set command to file and rest as argument
                    if (File.Exists(cleancmd))
                    {
                        command = cleancmd;
                        arguments = cleanarg;
                    }
                    else
                    {
                        //file not found in quoted string
                        foreach (string arg in args)
                        {
                            cleanarg = arg.Replace("\"", "");
                            cleanarg = cleanarg.Replace("\\\\", "\\");

                            if (cleanarg != string.Empty && File.Exists(cleanarg) && !commandset)
                            {
                                command = cleanarg;
                                commandset = true;
                            }
                            else
                            {
                                arguments = arguments + " " + cleanarg;
                            }
                        }
                    }

                    //if nothing found then default to first arg
                    if (command == string.Empty && args.Count > 0)
                    {
                        command = args[0].ToString();
                        args.Remove(args[0]);
                        arguments = String.Join(" ", args.ToArray());
                    }

                    //run command
                    bool ret = RunCommand(command, arguments, false);
                    arguments = string.Empty;
                    command = string.Empty;
                    commandset = false;
                }
            }
            catch (Exception e)
            {
                WriteOutput("Error processing command strings:" + e.ToString());
            }
        }

        /// <summary>
        /// Processes MS Notification of a session state change for the specified configuration.
        /// </summary>
        /// <param name="wfMessage">WF_CONNECTSTATE_CLASS</param>
        /// <returns>false if event was bypassed.</returns>
        private static bool ProcessEvent(WF_CONNECTSTATE_CLASS wfMessage)
        {
            //see if client name changed
            WFSession wfcurrentsession = QuerySessionInformation();

            //run connect commands
            if (wfMessage == WF_CONNECTSTATE_CLASS.WFConnected
                 && wfMessage != _currentSessionInfo.ConnectionState)
            {
                _connectEvent = true;
                WriteOutput("Connect event received");
                UpdateClientName(false);
                ProcessCommands(_ReconnectCommands);

                if (_enablePassthroughCommands &&
                    (ReadRegValue(_hkcuConfigurationKey, _previousSessionsName).ToString() == "1"))
                {
                    WriteOutput("Connect:Previous passthrough sessions detected");
                    ProcessCommands(_PassthroughReconnectCommands);
                    WriteRegValue(_hkcuConfigurationKey, _previousSessionsName, "0", RegistryValueKind.String, false);
                }
                else
                {
                    WriteOutput("Connect:No passthrough sessions found");
                }
                
                //update current state
                _currentSessionInfo = wfcurrentsession;
                _currentSessionInfo.ConnectionState = wfMessage;
                return true;
            }

            //run disconnect commands
            if (wfMessage == WF_CONNECTSTATE_CLASS.WFDisconnected
                     && wfMessage != _currentSessionInfo.ConnectionState)
            {
                WriteOutput("Disconnect event received");
                //look for active passthrough ica sessions
                int processlistCount = Process.GetProcessesByName("wfica32").Length;
                WriteOutput(string.Format("Disconnect:passthrough sessions detected:{0}", processlistCount.ToString()));
                if (_connectEvent && _enablePassthroughCommands && processlistCount > 0)
                {

                    ProcessCommands(_PassthroughDisconnectCommands);
                    WriteRegValue(_hkcuConfigurationKey, _previousSessionsName, "1", RegistryValueKind.String, true);
                }
                else if(_connectEvent)
                {
                        WriteRegValue(_hkcuConfigurationKey, _previousSessionsName, "0", RegistryValueKind.String, false);
                }

                ProcessCommands(_DisconnectCommands);
                _connectEvent = false;

                //update current state
                _currentSessionInfo = wfcurrentsession;
                _currentSessionInfo.ConnectionState = wfMessage;
                return true;
            }
            else
            {
                WriteOutput("Bypassing event");
                return false;
            }
        }

        /// <summary>
        /// Queries MS API WTSQuerySessionInformation to retrieve current session information.
        /// </summary>
        /// <returns>WFSession</returns>
        private static WFSession QuerySessionInformation()
        {
            //query current session id from Terminal Services API
            //returns empty session on fail

            System.IntPtr wtsBuffer = IntPtr.Zero;
            System.IntPtr wfBuffer = IntPtr.Zero;
            uint bytesReturned;
            WFSession wfSession = new WFSession();
            bool ret;

            try
            {
                //determine protocol
                ret = WTSQuerySessionInformation(System.IntPtr.Zero, WTS_CURRENT_SESSION, WTSInfoClass.WTSClientProtocolType, out wtsBuffer, out bytesReturned);
                wfSession.Protocol = Convert.ToInt32(Marshal.ReadByte(wtsBuffer)); //2=rdp 0 = console 1 = ica

                WriteOutput("session protocol:" + wfSession.Protocol.ToString());

                if (wfSession.Protocol == 2)// | wfSession.Protocol == 0)
                {
                    WriteOutput("querying WTS");
                    ret = WTSQuerySessionInformation(System.IntPtr.Zero, WTS_CURRENT_SESSION, WTSInfoClass.WTSSessionId, out wtsBuffer, out bytesReturned);
                    wfSession.SessionID = Marshal.ReadInt32(wtsBuffer);

                    //only populate name if current name is not empty
                    //disconnected sessions do not have client name
                    ret = WTSQuerySessionInformation(System.IntPtr.Zero, WTS_CURRENT_SESSION, WTSInfoClass.WTSClientName, out wtsBuffer, out bytesReturned);
                    wfSession.ClientName = Marshal.PtrToStringAnsi(wtsBuffer) != String.Empty ? Marshal.PtrToStringAnsi(wtsBuffer) : _currentSessionInfo.ClientName;

                    ret = WTSQuerySessionInformation(System.IntPtr.Zero, WTS_CURRENT_SESSION, WTSInfoClass.WTSClientAddress, out wtsBuffer, out bytesReturned);
                    WTS_CLIENT_ADDRESS wtsClientAddress = (WTS_CLIENT_ADDRESS)Marshal.PtrToStructure(wtsBuffer, typeof(WTS_CLIENT_ADDRESS));

                    if (wtsClientAddress.Address.Length < 6)
                    {
                        wfSession.IpAddress = _currentSessionInfo.IpAddress;
                    }
                    else
                    {
                        wfSession.IpAddress = wtsClientAddress.Address[2] + "." + wtsClientAddress.Address[3] + "." + wtsClientAddress.Address[4] + "." + wtsClientAddress.Address[5];
                    }

                    ret = WTSQuerySessionInformation(System.IntPtr.Zero, WTS_CURRENT_SESSION, WTSInfoClass.WTSConnectState, out wtsBuffer, out bytesReturned);
                    wfSession.ConnectionState = (WF_CONNECTSTATE_CLASS)Marshal.ReadInt32(wtsBuffer);
                }
                else
                {
                    WriteOutput("querying WF");
                    //call WFQuerySessionInformation as on XD ICA session, clientname is never populated
                    ret = WFQuerySessionInformation(System.IntPtr.Zero, WF_CURRENT_SESSION, WF_INFO_CLASS.WFConnectState, out wfBuffer, out bytesReturned);
                    wfSession.ConnectionState = (WF_CONNECTSTATE_CLASS)Marshal.ReadInt32(wfBuffer);

                    ret = WFQuerySessionInformation(System.IntPtr.Zero, WF_CURRENT_SESSION, WF_INFO_CLASS.WFSessionId, out wfBuffer, out bytesReturned);
                    wfSession.SessionID = Marshal.ReadInt32(wfBuffer);

                    ret = WFQuerySessionInformation(System.IntPtr.Zero, WF_CURRENT_SESSION, WF_INFO_CLASS.WFClientName, out wfBuffer, out bytesReturned);
                    wfSession.ClientName = Marshal.PtrToStringAnsi(wfBuffer) != String.Empty ? Marshal.PtrToStringAnsi(wfBuffer) : _currentSessionInfo.ClientName;

                    WFQuerySessionInformation(System.IntPtr.Zero, WF_CURRENT_SESSION, WF_INFO_CLASS.WFClientAddress, out wfBuffer, out bytesReturned);
                    WF_CLIENT_ADDRESS wfClientAddress = (WF_CLIENT_ADDRESS)Marshal.PtrToStructure(wtsBuffer, typeof(WF_CLIENT_ADDRESS));

                    if (wfClientAddress.Address.Length < 6)
                    {
                        wfSession.IpAddress = _currentSessionInfo.IpAddress;
                    }
                    else
                    {
                        wfSession.IpAddress = wfClientAddress.Address[2] + "." + wfClientAddress.Address[3] + "." + wfClientAddress.Address[4] + "." + wfClientAddress.Address[5];
                    }

                }
                
                WriteOutput(string.Format("QuerySessionInformation: returning:{0}:{1}:{2}:{3}", wfSession.SessionID, wfSession.ClientName, wfSession.ConnectionState, wfSession.IpAddress));

                return wfSession;
            }
            catch (Exception e)
            {
                WriteOutput("Error querying session information:" + e.ToString());
                return new WFSession();
            }
            finally
            {
                if (wtsBuffer != IntPtr.Zero) WTSFreeMemory(wtsBuffer);
                if (wfBuffer != IntPtr.Zero) WFFreeMemory(wfBuffer);
            }
        }

        /// <summary>
        /// reads hklm and hkcu configuration keys to configure this instance
        /// </summary>
        /// <returns>false for certain read failures</returns>
        private static bool ReadConfig()
        {
            try
            {
                _logfile = Environment.ExpandEnvironmentVariables(ReadRegValue(_hklmConfigurationKey, "LogFileName").ToString());

                string val = ReadRegValue(_hklmConfigurationKey, "UseHKLM").ToString();
                if (val != string.Empty && val == "1" | val.ToLower() == "true")
                {
                    _hiveKeyName = _hklm;
                }
                else
                {
                    _hiveKeyName = _hkcu;
                }

                val = ReadRegValue(_hklmConfigurationKey, "SetClientName").ToString();
                if (val != string.Empty && val == "1" | val.ToLower() == "true")
                {
                    _setClientName = true;
                }
                else
                {
                    _setClientName = false;
                }

                val = ReadRegValue(_hklmConfigurationKey, "SetClientNameRetry").ToString();
                if (val != string.Empty)
                {
                    //see if it is a number
                    double num;
                    bool isNum = double.TryParse(val, out num);
                    if (isNum)
                    {
                        _setClientNameRetry = Convert.ToInt32(val);
                        WriteOutput(string.Format("SetClientNameDelay is set to:{0}", _setClientNameRetry.ToString()));
                    }
                }

                string hklm = ReadRegValue(_hklm, _clientnameName).ToString();
                string hkcu = ReadRegValue(_hklm, _clientnameName).ToString();

                //issue when hklm and hkcu are not string.empty and do not match
                if ((hklm != string.Empty & hkcu != string.Empty) && hklm != hkcu)
                {
                    WriteOutput(string.Format("Values exist and are mismatched. only one key can be populated. exiting:{0}:{1}", hklm, hkcu));
                    return false;
                }

                _DisconnectCommands.AddRange((string[])ReadRegValue(_hklmConfigurationKey, "DisconnectCommands"));
                _ReconnectCommands.AddRange((string[])ReadRegValue(_hklmConfigurationKey, "ReconnectCommands"));
                _PassthroughDisconnectCommands.AddRange((string[])ReadRegValue(_hklmConfigurationKey, "PassthroughDisconnectCommands"));
                _PassthroughReconnectCommands.AddRange((string[])ReadRegValue(_hklmConfigurationKey, "PassthroughReconnectCommands"));
                _StartupCommands.AddRange((string[])ReadRegValue(_hklmConfigurationKey, "StartupCommands"));

                val = ReadRegValue(_hklmConfigurationKey, "EnablePassthroughCommands").ToString();
                if (val == string.Empty | val == "0" | val.ToLower() == "false")
                {
                    _enablePassthroughCommands = false;
                }
                else
                {
                    _enablePassthroughCommands = true;

                    //make sure client is installed and verify location
                    string pnaLocation = ReadRegValue(_icaClientInstallPathKey, _icaClientInstallPathName).ToString();
                    if (pnaLocation != string.Empty && File.Exists(pnaLocation + "\\pnagent.exe"))
                    {
                        WriteOutput(string.Format("Client installed:{0}", pnaLocation));
                        
                        //populate passthrough commands with command string if not populated
                        if (_PassthroughDisconnectCommands.Count < 1)
                        {
                            WriteOutput("Populating PassthroughDisconnectCommands with pnagent /disconnect. To disable, set EnablePassthroughCommands = 0");
                            WriteRegValue(_hklmConfigurationKey, @"PassthroughDisconnectCommands", string.Format("\"{0}pnagent.exe\" /disconnect", pnaLocation), RegistryValueKind.MultiString, true);
                        }
                        if (_PassthroughReconnectCommands.Count < 1)
                        {
                            WriteOutput("Populating PassthroughReconnectCommands with pnagent /reconnect. To disable, set EnablePassthroughCommands = 0");
                            WriteRegValue(_hklmConfigurationKey, @"PassthroughReconnectCommands", string.Format("\"{0}pnagent.exe\" /reconnect", pnaLocation), RegistryValueKind.MultiString, true);
                        }

                    }
                }

                //clean out hkcu config key on startup in case it is stale
                if (ReadRegValue(_hkcuConfigurationKey, _previousSessionsName).ToString() == "1")
                {
                    WriteRegValue(_hkcuConfigurationKey, _previousSessionsName, "0", RegistryValueKind.String, false);
                }

                return (true);
            }
            catch (Exception e)
            {
                WriteOutput(string.Format("Warning: Error reading registry configuration:{0}", e.ToString()));
                return (false);
            }
        }

        /// <summary>
        /// Reads registry value from registry
        /// </summary>
        /// <param name="key">Registry key</param>
        /// <param name="value">Registry value name</param>
        /// <returns>returns object value on success , string.empty on failure</returns>
        private static object ReadRegValue(string key, string value)
        {
            try
            {
                WriteOutput(string.Format("Reading Key:{0}{1}", key,value));
                object retval = Registry.GetValue(key, value,null);

                if(retval == null)
                {
                    WriteOutput("Reading Key value does not exist");
                    return (string.Empty);
                }
                else
                {
                    if (retval.GetType() == typeof(string[]))
                    {
                        foreach (string s in (string[])retval)
                        {
                            WriteOutput(string.Format("Reading Key value:{0}", s));
                        }
                    }
                    else
                    {
                        WriteOutput(string.Format("Reading Key value:{0}", retval.ToString()));
                    }
                    return(retval);
                }
            }
            catch (Exception e)
            {
                WriteOutput(e.Message + e.StackTrace);
                return (string.Empty);
            }
        }

        /// <summary>
        /// runs specified command with argument
        /// </summary>
        /// <param name="command">process to execute</param>
        /// <param name="arguments">command arguments</param>
        /// <param name="wait">true to wait for process to terminate</param>
        /// <returns>returns true if successful</returns>
        private static bool RunCommand(string command, string arguments, bool wait)
        {
            try
            {
                Process process = new Process();
                process.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.FileName = command;
                process.StartInfo.Arguments = arguments;

                WriteOutput(string.Format("Running command: {0}", command));
                WriteOutput(string.Format("Running command arguments: {0}", process.StartInfo.Arguments));
                if (wait)
                {
                    process.StartInfo.RedirectStandardOutput = true;
                }

                bool ret = process.Start();
                WriteOutput(string.Format("Command return: {0}",ret));

                //get results if wait is true
                if (wait)
                {
                    System.IO.StreamReader processOutput = process.StandardOutput;
                    string outputString = processOutput.ReadToEnd();
                    WriteOutput("Waiting for process exit");
                    process.WaitForExit();
                    WriteOutput(string.Format("Return value: {0} for process: {1}", ret.ToString(), _DisconnectCommands));
                    WriteOutput(string.Format("Return output: {0}", outputString));
                    processOutput.Close();
                }
                return ret;
            }
            catch (Exception e)
            {
                WriteOutput(string.Format("RunCommand error:{0}", e.ToString()));
                return false;
            }
            finally
            {

            }
        }

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern IntPtr SendMessageTimeout(
            IntPtr hWnd,
            uint Msg,
            UIntPtr wParam,
            string lParam,
            uint fuFlags,
            uint uTimeout,
            out UIntPtr lpdwResult);

        /// <summary>
        /// updates 'clientname' in reg and sends window message broadcast
        /// </summary>
        /// <param name="force">true to force update</param>
        /// <returns>true if successful</returns>
        private static bool UpdateClientName(bool force)
        {
            
            WFSession session = QuerySessionInformation();
            if (!force && String.Compare(session.ClientName, _currentSessionInfo.ClientName)==0)
            {
                WriteOutput("session.ClientName" + session.ClientName);
                WriteOutput("_currentSessionInfo.ClientName" + _currentSessionInfo.ClientName);
                WriteOutput(string.Format("UpdateClientName:clientname has not changed. returning. current name:{0}", session.ClientName));
                return false;
            }

            if (!String.IsNullOrEmpty(session.ClientName))
            {
                WriteOutput(string.Format("New client name = {0}", session.ClientName));
                WriteOutput("setting env variables and broadcasting to all windows. can be slow");
                Environment.SetEnvironmentVariable(_clientnameName, session.ClientName, EnvironmentVariableTarget.User);
                Environment.SetEnvironmentVariable(_clientAddressName, session.IpAddress, EnvironmentVariableTarget.User);
                WriteOutput("finished setting env variables.");
                //add to registry if requested
                UIntPtr dwRet;
                //_currentClientName = session.ClientName;

                if (_setClientName | force)
                {
                    WriteOutput(string.Format("Setting client name in reg = {0}", session.ClientName));
                    for (int i = 0; i <= _setClientNameRetry; i++)
                    {
                        WriteOutput(string.Format("Trying to write key:{0}", i));
                        //in case registry key does not exist yet because of profile load it will retry for _setClientNameRetry value
                        if(!String.IsNullOrEmpty(WriteRegValue(_hiveKeyName, _clientnameName, session.ClientName, RegistryValueKind.String, false)))
                        {
                            break;
                        }
                        Thread.Sleep(1000);

                    }

                    // set the volatile name 2k3 - does not have session id underneath volatile
                    WriteOutput(string.Format("Setting volatile environment citrix client name legacy = {0}", session.ClientName));
                    WriteRegValue(_volatileEnvironmentNameRegPath, _clientnameName, session.ClientName, RegistryValueKind.String, false);
                    
                    WriteOutput(string.Format("Setting volatile environment citrix client address legacy = {0}", session.IpAddress));
                    WriteRegValue(_volatileEnvironmentNameRegPath, _clientAddressName, session.IpAddress, RegistryValueKind.String, false);

                    // set the volatile name 2k8 + has session id underneath volatile
                    WriteOutput(string.Format("Setting volatile environment citrix client name = {0}", session.ClientName));
                    WriteRegValue(_volatileEnvironmentNameRegPath + "\\" + QuerySessionInformation().SessionID, _clientnameName, session.ClientName, RegistryValueKind.String, false);

                    WriteOutput(string.Format("Setting volatile environment citrix client address = {0}", session.IpAddress));
                    WriteRegValue(_volatileEnvironmentNameRegPath + "\\" + QuerySessionInformation().SessionID, _clientAddressName, session.IpAddress, RegistryValueKind.String, false);

                    WriteOutput(string.Format("Setting environment citrix client name = {0}", session.ClientName));
                    WriteRegValue(_environmentNameRegPath, _clientnameName, session.ClientName, RegistryValueKind.String, false);

                    WriteOutput(string.Format("Setting environment citrix client address = {0}", session.IpAddress));
                    WriteRegValue(_environmentNameRegPath, _clientAddressName, session.IpAddress, RegistryValueKind.String, false);

                    // broadcast the event
                    WriteOutput(string.Format("Broadcasting WM_SETTINGCHANGE event"));
                    SendMessageTimeout(HWND_BROADCAST, WM_SETTINGCHANGE, UIntPtr.Zero, "Environment", SMTO_ABORTIFHUNG, 5000, out dwRet);
                }
                return true;

            }
            else
            {
                return false;
            }
        }

        [DllImport("WFAPI.dll")]
        static extern void WFCloseServer(IntPtr hServer);

        [DllImport("WFAPI.dll")]
        static extern Int32 WFEnumerateSessions(
            IntPtr hServer,
            [MarshalAs(UnmanagedType.U4)] Int32 Reserved,
            [MarshalAs(UnmanagedType.U4)] Int32 Version,
            ref IntPtr ppSessionInfo,
            [MarshalAs(UnmanagedType.U4)] ref Int32 pCount);

        [DllImport("WFAPI.dll", EntryPoint = "WFFreeMemory")]
        private static extern void WFFreeMemory(IntPtr pMemory);

        [DllImport("WFAPI.dll")]
        static extern IntPtr WFOpenServer([MarshalAs(UnmanagedType.LPStr)] String pServerName);

        [DllImport("WFAPI.dll", EntryPoint = "WFQuerySessionInformationA")]
        private static extern bool WFQuerySessionInformation(System.IntPtr hServer, int sessionId, WF_INFO_CLASS wtsInfoClass, out System.IntPtr ppBuffer, out uint pBytesReturned);

        [DllImport("WFAPI.dll", EntryPoint = "WFWaitSystemEvent", SetLastError = true)]
        private static extern bool WFWaitSystemEvent(IntPtr hServer,
            UInt32 EventMask,
            out IntPtr pEventFlags);
        
        /// <summary>
        /// Writes string output to Debug.Print and to log file if specified.
        /// </summary>
        /// <param name="output">output string</param>
        private static void WriteOutput(string output)
        {
            #if (DEBUG)
            {
                Debug.Print(DateTime.Now + ":" + output);
            }
            #endif

            Console.WriteLine(output);
            if (_logfile != null & _logfile != string.Empty)
            {
                System.IO.File.AppendAllText(_logfile, DateTime.Now + ":" + output + Environment.NewLine);
            }
        }

        /// <summary>
        /// Write registry value to registry.
        /// </summary>
        /// <param name="key">Key Name</param>
        /// <param name="valueName">Value Name</param>
        /// <param name="value">Value </param>
        /// <param name="valueKind">Value Type</param>
        /// <param name="create">Create Key if enabled</param>
        /// <returns>returns string.empty on failure, string 'Value' on success</returns>
        private static string WriteRegValue(string key, string valueName, string value, RegistryValueKind valueKind, bool create)
        {
            try
            {
                    if (Registry.GetValue(key, valueName, null) == null)
                    {
                        WriteOutput(string.Format("Key does not exist:{0}", key));

                        if (create)
                        {
                            WriteOutput(string.Format("Creating Key:{0}", key));
                            Registry.SetValue(key, valueName, value, valueKind);
                        }
                        else
                        {
                            WriteOutput(string.Format("Key will not be written:{0}", key));
                            return (string.Empty);
                        }

                    }

                WriteOutput(string.Format("Writing value:{0}\\{1}:{2}", key, valueName, value));
                if (valueKind == RegistryValueKind.MultiString)
                {
                    Registry.SetValue(key, valueName, new string[] { value }, valueKind);
                }
                else
                {
                    Registry.SetValue(key, valueName, value, valueKind);
                }
                return (value);
            }
            catch (Exception e)
            {
                WriteOutput(e.Message + e.StackTrace);
                return (string.Empty);
            }
        }

        [DllImport("Kernel32.dll")]
        static extern Int32 WTSGetActiveConsoleSessionId();

        [DllImport("Wtsapi32.dll")]
        static extern IntPtr WTSOpenServer([MarshalAs(UnmanagedType.LPStr)] String pServerName);

        [DllImport("wtsapi32.dll", SetLastError = true)]
        static extern bool WTSRegisterSessionNotification(IntPtr hWnd, [MarshalAs(UnmanagedType.U4)] int dwFlags);

        [DllImport("wtsapi32.dll", SetLastError = true)]
        static extern bool WTSRegisterSessionNotificationEx(IntPtr hServer, IntPtr hWnd, [MarshalAs(UnmanagedType.U4)] int dwFlags);

        [DllImport("WtsApi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool WTSUnRegisterSessionNotification(IntPtr hWnd);

        [DllImport("wtsapi32.dll", EntryPoint = "WTSWaitSystemEvent", SetLastError = true)]
        private static extern bool WTSWaitSystemEvent(IntPtr hServer,
            UInt32 EventMask,
            out IntPtr pEventFlags);

        #endregion Methods
    }

    public static class WF_EVENT
    {
        #region Fields

        public static UInt32 WF_EVENT_ALL = 0x7fffffff; // wait for all event types
        public static UInt32 WF_EVENT_CONNECT = 0x00000008; // WinStation connect to client
        public static UInt32 WF_EVENT_CREATE = 0x00000001; // new WinStation created
        public static UInt32 WF_EVENT_DELETE = 0x00000002; // existing WinStation deleted
        public static UInt32 WF_EVENT_DISCONNECT = 0x00000010; // WinStation logged on without client
        public static UInt32 WF_EVENT_FLUSH = 0x80000000; // unblock all waiters
        public static UInt32 WF_EVENT_LICENSE = 0x00000100; // license state change
        public static UInt32 WF_EVENT_LOGOFF = 0x00000040; // user logged off from existing WinStation
        public static UInt32 WF_EVENT_LOGON = 0x00000020; // user logged on to existing WinStation
        public static UInt32 WF_EVENT_NONE = 0x00000000; // return no event
        public static UInt32 WF_EVENT_RENAME = 0x00000004; // existing WinStation renamed
        public static UInt32 WF_EVENT_STATECHANGE = 0x00000080; // WinStation state change

        #endregion Fields
    }

    public static class WTS_SESSION_NOTIFICATION
    {
        #region Fields

        public const int NOTIFY_FOR_ALL_SESSIONS = 1;

        // constants that can be passed for the dwFlags parameter
        public const int NOTIFY_FOR_THIS_SESSION = 0;

        // message id to look for when processing the message (see sample code)
        public const int WM_WTSSESSION_CHANGE = 0x2b1;

        // WParam values that can be received:
        public const int WTS_CONSOLE_CONNECT = 0x1; // A session was connected to the console terminal.
        public const int WTS_CONSOLE_DISCONNECT = 0x2; // A session was disconnected from the console terminal.
        public const int WTS_REMOTE_CONNECT = 0x3; // A session was connected to the remote terminal.
        public const int WTS_REMOTE_DISCONNECT = 0x4; // A session was disconnected from the remote terminal.
        public const int WTS_SESSION_LOCK = 0x7; // A session has been locked.
        public const int WTS_SESSION_LOGOFF = 0x6; // A user has logged off the session.
        public const int WTS_SESSION_LOGON = 0x5; // A user has logged on to the session.
        public const int WTS_SESSION_REMOTE_CONTROL = 0x9; // A session has changed its remote controlled status.
        public const int WTS_SESSION_UNLOCK = 0x8; // A session has been unlocked.

        #endregion Fields
    }
    
    /// <summary>
    /// WF_SESSION is used to store Session information output from unmanaged api call.
    /// </summary>
    class WFSession
    {
        #region Fields

        public string ClientName = string.Empty;
        public WF_CONNECTSTATE_CLASS ConnectionState = WF_CONNECTSTATE_CLASS.WFReset;
        public string DomainName = string.Empty;
        public string IpAddress = string.Empty;
        public int Protocol = 0;
        public int SessionID = -2;
        public string StationName = string.Empty;
        public string UserName = string.Empty;

        #endregion Fields
    }

    /// <summary>
    /// WTS_CLIENT_ADDRESS is used to store IP Address output from unmanaged api call.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct WTS_CLIENT_ADDRESS
    {
        public uint AddressFamily;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 20)]
        public byte[] Address;
    }
}