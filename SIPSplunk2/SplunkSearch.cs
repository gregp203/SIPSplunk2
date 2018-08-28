using Splunk.Client;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;

namespace SIPSplunk2
{
    class SplunkSearch
    {
        string server;
        string user;
        SecureString password;        
        string index;
        string source;
        DateTime earliest;
        DateTime latest;
        String splunkUrl;
        String searchStrg;
        bool splunkExceptions;
        bool CancelSplunkJob;
        public int splunkMaxEvents { get; set; }
        public int splunkMaxTime { get; set; }
        int splunkStatusInterval;        
        string logMode;
        DateTime SelectedCallsEarliestTime;
        DateTime SelectedCallsLatestTime;
        bool SplunkReadDone = false;
        List<string> callIDsOfIntrest = new List<string>(); // all the callIDs from the selectedmesages 
        static readonly object _QueryAgainlocker = new object();
        public List<string[]> Calls  { get; set;}
        SipMessageReader sipMessageReader;
                
        public SplunkSearch(
                String serverArg,
                String userArg,
                String passwordArg,
                String indexArg,            
                String sourceArg,
                DateTime earliestArg,
                DateTime latestArg,
                String logModeArg,
                SipMessageReader smr)
        {
            server= serverArg;
            user = userArg;
            index = indexArg;
            password = StringToSecureString(passwordArg);
            source = sourceArg;
            earliest = earliestArg;
            latest = latestArg;
            logMode = logModeArg;
            SipMessageReader sipMessageReader = smr;
            splunkUrl = "https://" + server + ":8089";
            searchStrg = "search index=" + index + " " + source;
            Calls = new List<string[]>();
            splunkExceptions = false;
            //timeMode = TZmode.local;
            password = new SecureString();
            CancelSplunkJob = false;
            splunkMaxEvents = 10000;
            splunkMaxTime = 60000;
            splunkStatusInterval = 5000;
        }
        public async Task SplunkGetCallsAsync(CancellationToken cancelToken = new CancellationToken())
        {
            await Task.Run(() =>
            {
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                ServicePointManager.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) =>
                {
                    return true;
                };
                SelectedCallsEarliestTime = DateTime.Now;
                SelectedCallsLatestTime = DateTime.Parse("2000-01-01T00:00:00.000-05:00");
                splunkExceptions = false;
                using (Service service = new Service(new Uri(splunkUrl)))
                {
                     //login to splunk server and call SplunkQuery
                    try
                    {
                        SplunkReadDone = false;
                        Status("Connecting to splunk server "+ splunkUrl.ToString());
                        service.LogOnAsync(user, SecureStringToString(password)).Wait();
                        Status("Creating splunk job " + searchStrg);
                        switch (logMode)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            
                        {
                            case "tcpdump":
                                SplunkCallLegsQuery(service, cancelToken).Wait();
                                break;
                            case "audiocodes":
                                AcSplunkCallLegsQuery(service).Wait();
                                break;
                            case "audiocodesSyslog":
                                AcSyslogSplunkCallLegsQuery(service).Wait();
                                break;
                        }
                        SplunkReadDone = true;
                    }
                    catch (AggregateException ex)
                    {
                        //if the wrong splunk URL
                        if (ex.ToString().Contains("System.Net.Sockets.SocketException"))
                        {
                            Status(Regex.Match(ex.InnerException.ToString(), @"(?<=System.Net.Sockets.SocketException:).*").ToString());
                        }
                        //if the wrong user or password
                        else if (ex.ToString().Contains("Splunk.Client.AuthenticationFailureException"))
                        {
                            Status(Regex.Match(ex.ToString(), @"(?<=Splunk.Client.AuthenticationFailureException).*").ToString());
                        }
                        else if (ex.InnerException.Message.Contains("Unknown search command"))
                        {
                            Status(Regex.Match(ex.InnerException.Message, @"(?<=Search Factory: ).*\s*").ToString());
                        }
                        else if (ex.ToString().Contains("System.Net.WebException:"))
                        {
                            Status(Regex.Match(ex.ToString(), @"(?<=System.Net.WebException: ).*\s*").ToString());
                        }
                        else
                        {
                            Status(ex.ToString());
                        }
                        SIPSplunk2.Log(ex.ToString());
                        splunkExceptions = true;
                        SplunkReadDone = true;
                    }
                    finally
                    {
                        try
                        {
                            if (!splunkExceptions) service.LogOffAsync().Wait();
                        }
                        catch (Exception ex)
                        {
                            SIPSplunk2.Log(ex.ToString());
                        }
                       
                    }                    
                    CancelSplunkJob = false;
                }
            });
        }

        async Task SplunkCallLegsQuery(Service service, CancellationToken cancelToken = new CancellationToken())
        {
            try
            {
                string front = searchStrg + " |";
                string splunkSrcIpPortRgxStr = @"(?<SIP_SrcIP>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:|.)\d*(?= >)";
                string splunkDstIpPortRgxStr = @"(?<SIP_DstIP>(?<=> )\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:|.)\d*";
                string splunkRequestRgxStr = @"(?<SIP_Req>ACK.*SIP\/2\.0|BYE.*SIP\/2\.0|CANCEL.*SIP\/2\.0|INFO.*SIP\/2\.0|INVITE.*SIP\/2\.0|MESSAGE.*SIP\/2\.0|NOTIFY.*SIP\/2\.0|OPTIONS.*SIP\/2\.0|PRACK.*SIP\/2\.0|PUBLISH.*SIP\/2\.0|REFER.*SIP\/2\.0|REGISTER.*SIP\/2\.0|SUBSCRIBE.*SIP\/2\.0|UPDATE.*SIP\/2\.0|SIP\/2\.0 \d{3}(\s*\w*))";
                string splunkCallidRgxStr = @"(?<!-.{8})(?<=Call-ID:)\s*(?<SIP_CallId>\S*)";//do not match if -Call-ID instead of Call-ID
                string splunkToRgxStr = @"(?<=To:)\s*(\x22.+\x22)?.*<?(sip:)(?<SIP_To>[^@>]+)";
                string splunkFromRgxStr = @"(?<=From:)\s*(\x22.+\x22)?.*<?(sip:)(?<SIP_From>[^@>]+)";
                string splunkMethodRgxStr = @"(?<SIP_method>^[a-zA-Z]+)";
                string splunkMethodRex = "rex field=SIP_Req \"";
                string back = "eval timeForamted=strftime(_time, \"%Y-%m-%d %H:%M:%S.%6N%:z\")|search SIP_Req = *INVITE* OR SIP_Req =*NOTIFY* OR SIP_Req =*REGISTER* OR SIP_Req =*SUBSCRIBE*| reverse |stats first(SIP_To) as To, first(SIP_From) as From, first(SIP_SrcIP) as Source_IP, first(SIP_DstIP) as Destination_IP, first(timeForamted)  as DateTime last(timeForamted) as endDateTime first(SIP_method) as Method by SIP_CallId| table DateTime, UTC, To, From, SIP_CallId, selected, Source_IP, Destination_IP, endDateTime, Method | sort DateTime";
                string rex = "rex field=_raw \"";
                string rexend = "\"|";
                var splunkJob = await service.Jobs.CreateAsync(
                    front +
                    rex + splunkSrcIpPortRgxStr + rexend +
                    rex + splunkDstIpPortRgxStr + rexend +
                    rex + splunkRequestRgxStr + rexend +
                    rex + splunkCallidRgxStr + rexend +
                    rex + splunkToRgxStr + rexend +
                    rex + splunkFromRgxStr + rexend +
                    splunkMethodRex + splunkMethodRgxStr + rexend +
                    back, splunkMaxEvents, ExecutionMode.Normal,
                    new JobArgs()
                    {
                        EarliestTime = earliest.ToString("yyyy-MM-ddTHH:mm:ss.fffzzz"),
                        LatestTime = latest.ToString("yyyy-MM-ddTHH:mm:ss.fffzzz"),
                        MaxCount = splunkMaxEvents
                    });

                //loop until Job is done or cancelled 
                Stopwatch elapsedTime = new Stopwatch();
                elapsedTime.Start();
                for (int count = 1; ; ++count)
                {
                    if (cancelToken.IsCancellationRequested)
                    {
                        await splunkJob.CancelAsync();
                        Status("Splunk query is canceled.");
                        break;
                    }
                    if (count >= splunkMaxTime / splunkStatusInterval)
                    {
                        await splunkJob.FinalizeAsync();
                        Status("Exceeded maximum wait time of " + splunkMaxTime / 1000 + " seconds. Finalizing...");
                        break;
                    }
                    if (splunkJob.IsFinalized)
                    {
                        Status("Splunk query is finalized");
                        break;
                    }
                    if (splunkJob.DispatchState == DispatchState.Finalizing)
                    {
                        string formatedString = String.Format("Splunk job " + splunkJob.Sid + " Finalizing. Time elapsed: {0:hh\\:mm\\:ss} ", elapsedTime.Elapsed);
                    }
                    try
                    {
                        await splunkJob.TransitionAsync(DispatchState.Done, splunkStatusInterval);
                        break;
                    }
                    catch (TaskCanceledException)
                    {
                        string formatedString = String.Format("Waiting on splunk job " + splunkJob.Sid + " to complete. " + splunkJob.DoneProgress * 100 + "% Time elapsed: {0:hh\\:mm\\:ss} ", elapsedTime.Elapsed);
                        Status(formatedString);
                    }
                }
                elapsedTime.Restart();
                using (var results = await splunkJob.GetSearchResponseMessageAsync(outputMode: OutputMode.Csv))
                {
                    Stream contentstream = await results.Content.ReadAsStreamAsync();
                    StreamReader contentSR = new StreamReader(contentstream);
                    //Console.WriteLine(content);
                    String[] line = new String[5];
                    long lastElapsedMs = elapsedTime.ElapsedMilliseconds;                   
                    while (!contentSR.EndOfStream && !CancelSplunkJob)
                    {
                        if ((elapsedTime.ElapsedMilliseconds - lastElapsedMs) > 5000)
                        {
                            lastElapsedMs = elapsedTime.ElapsedMilliseconds;
                            string formatedString = String.Format("Fetching results from splunk job " + splunkJob.ResultCount + " results. Time elapsed: {0:hh\\:mm\\:ss}", elapsedTime.Elapsed);
                            Status(formatedString);
                        }
                        line = contentSR.ReadLine().Replace("\"", "").Split(',');

                        //if line has a valid time stamp collect it
                        if (Regex.IsMatch(line[0], @"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{6}-\d{2}:\d{2}"))
                        {
                            line[1] = DateTime.Parse(line[0]).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);
                            Calls.Add(line);
                        }
                    }
                    elapsedTime.Stop();
                    Status("Completed splunk query with " + splunkJob.ResultCount + " results out of " + splunkJob.EventCount + " Events found");
                    //TODO update display
                }
            }
            catch (Exception ex)
            {
                if (ex.ToString().Contains("System.Net.WebException:"))
                {
                    Status(Regex.Match(ex.ToString(), @"(?<=System.Net.WebException: ).*\s*").ToString());
                }
                else
                {
                    Status(ex.Message);
                }
                SIPSplunk2.Log(ex.ToString());
                splunkExceptions = true;
            }
        }

        async Task AcSplunkCallLegsQuery(Service service, CancellationToken cancelToken = new CancellationToken())
        {
            try
            {
                string query = searchStrg + " | rex field=_raw \"" + @"(?<SIP_Req>ACK.*SIP\/2\.0|BYE.*SIP\/2\.0|CANCEL.*SIP\/2\.0|INFO.*SIP\/2\.0|INVITE.*SIP\/2\.0|MESSAGE.*SIP\/2\.0|NOTIFY.*SIP\/2\.0|OPTIONS.*SIP\/2\.0|PRACK.*SIP\/2\.0|PUBLISH.*SIP\/2\.0|REFER.*SIP\/2\.0|REGISTER.*SIP\/2\.0|SUBSCRIBE.*SIP\/2\.0|UPDATE.*SIP\/2\.0|SIP\/2\.0 \d{3}(\s*\w*))" + "\" | " +
                                "rex field=_raw \"" + @"(?<!-.{8})(?<=Call-ID:)\s*(?<SIP_CallId>\S*)" + "\" | " +
                                "rex field=SIP_Req \"(?<SIP_method>^[a-zA-Z]+)\" | " +
                                "rex field=_raw \"\\[.*\\]\\s*\\[.*\\]\\s*(?<MGIP>\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\" | " +
                                "rex field=_raw \"(?<=Incoming SIP Message from)\\s*(?<SrcIP>\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\" | " +
                                "rex field=_raw \"(?<=Outgoing SIP Message to)\\s*(?<DstIP>\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\" | " +
                                "rex field=_raw \"" + @"(?<=To:) *(\x22.+\x22)? *<?(sip:)(?<SIP_To>[^@>]+)" + "\" | " +
                                "rex field=_raw \"" + @"(?<=From:) *(\x22.+\x22)? *<?(sip:)(?<SIP_From>[^@>]+)" + "\" | " +
                                "eval timeForamted = strftime(_time, \"%Y-%m-%d %H:%M:%S.%6N%:z\") |" +
                                "eval UTC = \"\" |" +
                                "eval selected = \"\" |" +
                                "eval filtered = \"\" |" +
                                "reverse | streamstats current=f window=5 last(DstIP) as prev_DstIP last(SrcIP) as prev_SrcIP |" +
                                "eval SIP_dstIP =if (prev_DstIP != \"\",prev_DstIP,MGIP) | eval SIP_srcIP =if (prev_SrcIP != \"\",prev_SrcIP,MGIP) |" +
                                "search SIP_Req = *INVITE* OR SIP_Req = *NOTIFY* OR SIP_Req = *REGISTER* OR SIP_Req = *SUBSCRIBE* |" +
                                "stats first(SIP_To) as To, first(SIP_From) as From, first(SIP_srcIP) as Source_IP, first(SIP_dstIP) as Destination_IP, first(timeForamted) as DateTime first(SIP_method) as Method by SIP_CallId|" +
                                "table DateTime,UTC,To,From,SIP_CallId,selected,Source_IP,Destination_IP,filtered,Method |" +
                                "sort DateTime";

                var splunkJob = await service.Jobs.CreateAsync(query, splunkMaxEvents, ExecutionMode.Normal, new JobArgs()
                {
                    EarliestTime = earliest.ToString("u"),
                    LatestTime = latest.ToString("u"),
                    MaxCount = splunkMaxEvents
                });

                //loop until Job is done or cancelled 
                Stopwatch elapsedTime = new Stopwatch();
                elapsedTime.Start();
                for (int count = 1; ; ++count)
                {
                    if (cancelToken.IsCancellationRequested)
                    {
                        await splunkJob.CancelAsync();
                        Status("Splunk query is canceled.");
                        break;
                    }
                    if (count >= splunkMaxTime / splunkStatusInterval)
                    {
                        await splunkJob.FinalizeAsync();
                        Status("Exceeded maximum wait time of " + splunkMaxTime / 1000 + " seconds. Finalizing...");
                        break;
                    }
                    if (splunkJob.IsFinalized)
                    {
                        Status("Splunk query is finalized");
                        break;
                    }
                    if (splunkJob.DispatchState == DispatchState.Finalizing)
                    {
                        string formatedString = String.Format("Splunk job " + splunkJob.Sid + " Finalizing. Time elapsed: {0:hh\\:mm\\:ss} ", elapsedTime.Elapsed);
                    }
                    try
                    {
                        await splunkJob.TransitionAsync(DispatchState.Done, splunkStatusInterval);
                        break;
                    }
                    catch (TaskCanceledException)
                    {
                        string formatedString = String.Format("Waiting on splunk job " + splunkJob.Sid + " to complete. " + splunkJob.DoneProgress * 100 + "% Time elapsed: {0:hh\\:mm\\:ss} ", elapsedTime.Elapsed);
                        Status(formatedString);
                    }
                }
                elapsedTime.Restart();
                using (var results = await splunkJob.GetSearchResponseMessageAsync(outputMode: OutputMode.Csv))
                {
                    Stream contentstream = await results.Content.ReadAsStreamAsync();
                    StreamReader contentSR = new StreamReader(contentstream);
                    //Console.WriteLine(content);
                    String[] line = new String[5];
                    long lastElapsedMs = elapsedTime.ElapsedMilliseconds;
                    while (!contentSR.EndOfStream && !CancelSplunkJob)
                    {
                        if ((elapsedTime.ElapsedMilliseconds - lastElapsedMs) > 5000)
                        {
                            lastElapsedMs = elapsedTime.ElapsedMilliseconds;
                            string formatedString = String.Format("Fetching results from splunk job " + splunkJob.ResultCount + " results. Time elapsed: {0:hh\\:mm\\:ss}", elapsedTime.Elapsed);
                            Status(formatedString);
                        }
                        line = contentSR.ReadLine().Replace("\"", "").Split(',');

                        //if line has a valid time stamp collect it
                        if (Regex.IsMatch(line[0], @"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{6}-\d{2}:\d{2}"))
                        {
                            line[1] = DateTime.Parse(line[0]).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);
                            Calls.Add(line);
                        }
                    }
                    elapsedTime.Stop();
                    Status("Completed splunk query with " + splunkJob.ResultCount + " results out of " + splunkJob.EventCount + " Events found");
                    //TODO update display
                }
            }
            catch (AggregateException ex)
            {

                Status(ex.Message);
                SIPSplunk2.Log(ex.ToString());
                splunkExceptions = true;
            }
        }

        async Task AcSyslogSplunkCallLegsQuery(Service service, CancellationToken cancelToken = new CancellationToken())
        {
            try
            {
                string query = searchStrg + " | rex field=_raw \"" + @"(?<SIP_Req>ACK.*SIP\/2\.0|BYE.*SIP\/2\.0|CANCEL.*SIP\/2\.0|INFO.*SIP\/2\.0|INVITE.*SIP\/2\.0|MESSAGE.*SIP\/2\.0|NOTIFY.*SIP\/2\.0|OPTIONS.*SIP\/2\.0|PRACK.*SIP\/2\.0|PUBLISH.*SIP\/2\.0|REFER.*SIP\/2\.0|REGISTER.*SIP\/2\.0|SUBSCRIBE.*SIP\/2\.0|UPDATE.*SIP\/2\.0|SIP\/2\.0 \d{3}(\s*\w*))" + "\" | " +
                                "rex field=_raw \"" + @"(?<!-.{8})(?<=Call-ID:)\s*(?<SIP_CallId>\S*)" + "\" | " +
                                "rex field=SIP_Req \"(?<SIP_method>^[a-zA-Z]+)\" | " +
                                "rex field=_raw \"" + @"\d{2}:\d{2}:\d{2}.\d{3}\s*(?<MGIP>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})" + "\" | " +
                                "rex field=_raw \"(?<=Incoming SIP Message from)\\s*(?<SrcIP>\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\" | " +
                                "rex field=_raw \"(?<=Outgoing SIP Message to)\\s*(?<DstIP>\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\" | " +
                                "rex field=_raw \"" + @"(?<=To:) *(\x22.+\x22)? *<?(sip:)(?<SIP_To>[^@>]+)" + "\" | " +
                                "rex field=_raw \"" + @"(?<=From:) *(\x22.+\x22)? *<?(sip:)(?<SIP_From>[^@>]+)" + "\" | " +
                                "eval timeForamted = strftime(_time, \"%Y-%m-%d %H:%M:%S.%6N%:z\") |" +
                                "eval UTC = \"\" |" +
                                "eval selected = \"\" |" +
                                "eval filtered = \"\" |" +
                                "reverse | streamstats current=f window=5 last(DstIP) as prev_DstIP last(SrcIP) as prev_SrcIP |" +
                                "eval SIP_dstIP =if (prev_DstIP != \"\",prev_DstIP,MGIP) | eval SIP_srcIP =if (prev_SrcIP != \"\",prev_SrcIP,MGIP) |" +
                                "search SIP_Req = *INVITE* OR SIP_Req = *NOTIFY* OR SIP_Req = *REGISTER* OR SIP_Req = *SUBSCRIBE* |" +
                                "stats first(SIP_To) as To, first(SIP_From) as From, first(SIP_srcIP) as Source_IP, first(SIP_dstIP) as Destination_IP, first(timeForamted) as DateTime first(SIP_method) as Method by SIP_CallId|" +
                                "table DateTime,UTC,To,From,SIP_CallId,selected,Source_IP,Destination_IP,filtered,Method |" +
                                "sort DateTime";

                var splunkJob = await service.Jobs.CreateAsync(query, splunkMaxEvents, ExecutionMode.Normal, new JobArgs()
                {
                    EarliestTime = earliest.ToString("u"),
                    LatestTime = latest.ToString("u"),
                    MaxCount = splunkMaxEvents
                });

                //loop until Job is done or cancelled 
                Stopwatch elapsedTime = new Stopwatch();
                elapsedTime.Start();
                for (int count = 1; ; ++count)
                {
                    if (cancelToken.IsCancellationRequested)
                    {
                        await splunkJob.CancelAsync();
                        Status("Splunk query is canceled.");
                        break;
                    }
                    if (count >= splunkMaxTime / splunkStatusInterval)
                    {
                        await splunkJob.FinalizeAsync();
                        Status("Exceeded maximum wait time of " + splunkMaxTime / 1000 + " seconds. Finalizing...");
                        break;
                    }
                    if (splunkJob.IsFinalized)
                    {
                        Status("Splunk query is finalized");
                        break;
                    }
                    if (splunkJob.DispatchState == DispatchState.Finalizing)
                    {
                        string formatedString = String.Format("Splunk job " + splunkJob.Sid + " Finalizing. Time elapsed: {0:hh\\:mm\\:ss} ", elapsedTime.Elapsed);
                    }
                    try
                    {
                        await splunkJob.TransitionAsync(DispatchState.Done, splunkStatusInterval);
                        break;
                    }
                    catch (TaskCanceledException)
                    {
                        string formatedString = String.Format("Waiting on splunk job " + splunkJob.Sid + " to complete. " + splunkJob.DoneProgress * 100 + "% Time elapsed: {0:hh\\:mm\\:ss} ", elapsedTime.Elapsed);
                        Status(formatedString);
                    }
                }
                elapsedTime.Restart();
                using (var results = await splunkJob.GetSearchResponseMessageAsync(outputMode: OutputMode.Csv))
                {
                    Stream contentstream = await results.Content.ReadAsStreamAsync();
                    StreamReader contentSR = new StreamReader(contentstream);
                    //Console.WriteLine(content);
                    String[] line = new String[5];
                    long lastElapsedMs = elapsedTime.ElapsedMilliseconds;
                    while (!contentSR.EndOfStream && !CancelSplunkJob)
                    {
                        if ((elapsedTime.ElapsedMilliseconds - lastElapsedMs) > 5000)
                        {
                            lastElapsedMs = elapsedTime.ElapsedMilliseconds;
                            string formatedString = String.Format("Fetching results from splunk job " + splunkJob.ResultCount + " results. Time elapsed: {0:hh\\:mm\\:ss}", elapsedTime.Elapsed);
                            Status(formatedString);
                        }
                        line = contentSR.ReadLine().Replace("\"", "").Split(',');

                        //if line has a valid time stamp collect it
                        if (Regex.IsMatch(line[0], @"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{6}-\d{2}:\d{2}"))
                        {
                            line[1] = DateTime.Parse(line[0]).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);
                            Calls.Add(line);
                        }
                    }
                    elapsedTime.Stop();
                    Status("Completed splunk query with " + splunkJob.ResultCount + " results out of " + splunkJob.EventCount + " Events found");
                    //TODO update display
                }
            }
            catch (AggregateException ex)
            {

                Status(ex.Message);
                SIPSplunk2.Log(ex.ToString());
                splunkExceptions = true;
            }
        }

        void SplunkGetSIPMessages()
        {
           
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            ServicePointManager.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) => {
                return true;
            };

            splunkExceptions = false;
            using (Service service = new Service(new Uri(splunkUrl)))
            {//login to splunk server and call SplunkQuery
                try
                {
                    SplunkReadDone = false;
                    Status("Connecting to splunk");
                    service.LogOnAsync(user, SecureStringToString(password)).Wait();
                    Status("Creating splunk job  for SIP messages " + searchStrg);
                    switch (logMode)
                    {
                        case "tcpdump":
                            SplunkSIPMessagesQuery(service).Wait();
                            break;
                        case "audiocodes":
                            AcSplunkSIPMessagesQuery(service).Wait();
                            break;
                        case "audiocodesSyslog":
                            AcSyslogSplunkSIPMessagesQuery(service).Wait();
                            break;
                    }
                }
                catch (Exception ex)
                {
                    //if the wrong splunk URL
                    if (ex.ToString().Contains("System.Net.Sockets.SocketException"))
                    {
                        Status(Regex.Match(ex.InnerException.ToString(), @"(?<=System.Net.Sockets.SocketException:).*").ToString());
                    }
                    //if the wrong user or password
                    else if (ex.ToString().Contains("Splunk.Client.AuthenticationFailureException"))
                    {
                        Status(Regex.Match(ex.ToString(), @"(?<=Splunk.Client.AuthenticationFailureException).*").ToString());
                    }
                    else if (ex.InnerException.Message.Contains("Unknown search command"))
                    {
                        Status(Regex.Match(ex.InnerException.Message, @"(?<=Search Factory: ).*\s*").ToString());
                    }
                    else
                    {
                        Status(ex.InnerException.Message);
                        SIPSplunk2.Log(ex.ToString());
                    }
                    splunkExceptions = true;
                    SplunkReadDone = true;
                }
                finally
                {
                    try
                    {
                        if (!splunkExceptions) service.LogOffAsync().Wait();
                    }
                    catch (Exception ex)
                    {
                        SIPSplunk2.Log(ex.ToString());
                    }
                }
            }
        }

        async Task SplunkSIPMessagesQuery(Service service)
        {
            string msgSearchString = searchStrg + "|rex field=_raw \"(?<!-.{8})(?<=Call-ID:)\\s*(?<SIP_CallId>\\S*)\"| search ";
            for (int i = 0; i < callIDsOfIntrest.Count; i++)
            {
                string callId = callIDsOfIntrest[i];
                msgSearchString += ("SIP_CallId=" + callId);
                if (i < callIDsOfIntrest.Count - 1)
                {
                    msgSearchString += " OR ";
                }
            }

            // create splunk job
            try
            {
                var splunkJob = await service.Jobs.CreateAsync(msgSearchString + " | dedup _raw | reverse", 0, ExecutionMode.Normal,
                new JobArgs()
                {
                    EarliestTime = SelectedCallsEarliestTime.ToString("O"),
                    LatestTime = SelectedCallsLatestTime.ToString("O"),
                    MaxCount = splunkMaxEvents
                });

                //loop until Job is done or cancelled
                Stopwatch elapsedTime = new Stopwatch();
                elapsedTime.Start();
                for (int count = 1; ; ++count)
                {
                    if (Console.KeyAvailable)
                    {
                        if (Console.ReadKey(true).Key == ConsoleKey.Escape)
                        {
                            break;
                        }
                    }
                    if (count >= splunkMaxTime / splunkStatusInterval)
                    {
                        await splunkJob.FinalizeAsync();
                        Status("Exceeded maximum wait time of " + splunkMaxTime / 1000 + " seconds. Finalizing...");
                        SIPSplunk2.Log("Exceeded maximum wait time of " + splunkMaxTime / 1000 + " seconds. Finalizing...");
                        break;
                    }
                    if (splunkJob.IsFinalized)
                    {
                        Status("Splunk query is finalized");
                        SIPSplunk2.Log("Splunk query is finalized");
                        break;
                    }
                    if (splunkJob.DispatchState == DispatchState.Finalizing)
                    {
                        string formatedString = String.Format("Splunk job " + splunkJob.Sid + " Finalizing. Time elapsed: {0:hh\\:mm\\:ss} ", elapsedTime.Elapsed);
                    }
                    try
                    {
                        await splunkJob.TransitionAsync(DispatchState.Done, splunkStatusInterval);
                        break;
                    }
                    catch (TaskCanceledException)
                    {
                        string formatedString = String.Format("Waiting on splunk job " + splunkJob.Sid + " to complete. " + splunkJob.DoneProgress * 100 + "% Time elapsed: {0:hh\\:mm\\:ss} Press Esc to quit.", elapsedTime.Elapsed);
                        Status(formatedString);
                    }
                }
                elapsedTime.Restart();
                //Get results of job as stream instantiate streamreader splunkSR to read it
                if (splunkJob.IsFinalized || splunkJob.IsDone)
                {
                    
                    using (var message = await splunkJob.GetSearchResponseMessageAsync(outputMode: OutputMode.Raw))
                    {
                        Stream splunkStream = await message.Content.ReadAsStreamAsync();

                        sipMessageReader.ReadData(splunkStream);
                    }
                    
                    SplunkReadDone = true;
                }
                else
                {
                    Status("Splunk query failed");
                }
            }
            catch (Exception ex)
            {
                SIPSplunk2.Log(ex.ToString());
                splunkExceptions = true;
            }
        }

        async Task AcSplunkSIPMessagesQuery(Service service)
        {
            string msgSearchString = searchStrg +
                    "| rex field=_raw \"" + @"(?<SIP_Req>ACK.*SIP\/2\.0|BYE.*SIP\/2\.0|CANCEL.*SIP\/2\.0|INFO.*SIP\/2\.0|INVITE.*SIP\/2\.0|MESSAGE.*SIP\/2\.0|NOTIFY.*SIP\/2\.0|OPTIONS.*SIP\/2\.0|PRACK.*SIP\/2\.0|PUBLISH.*SIP\/2\.0|REFER.*SIP\/2\.0|REGISTER.*SIP\/2\.0|SUBSCRIBE.*SIP\/2\.0|UPDATE.*SIP\/2\.0|SIP\/2\.0 \d{3}(\s*\w*))" + "\" | " +
                    "rex field=_raw \"" + @"(?<!-.{8})(?<=Call-ID:)\s*(?<SIP_CallId>\S*)" + "\" | " +
                    "rex field=SIP_Req \"(?<SIP_method>^[a-zA-Z]+)\" | " +
                    "rex field=_raw \"\\[.*\\]\\s*\\[.*\\]\\s*(?<MGIP>\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\" | " +
                    "rex field=_raw \"(?<=Incoming SIP Message from)\\s*(?<SrcIP>\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\" | " +
                    "rex field=_raw \"(?<=Outgoing SIP Message to)\\s*(?<DstIP>\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\" | " +
                    "reverse |streamstats current=f window=5 last(DstIP) as prev_DstIP last(SrcIP) as prev_SrcIP | " +
                    "eval SIP_dstIP=if(prev_DstIP != \"\",prev_DstIP,MGIP) | eval SIP_srcIP=if(prev_SrcIP != \"\",prev_SrcIP,MGIP) | " +
                    "search ";
            string msgSearchStringEnd = " | eval srcIpOut=\"srcip=\"+SIP_srcIP | eval dstIpOut=\"dstip=\"+SIP_dstIP |" +
                    "table srcIpOut,dstIpOut,_raw | ";
            for (int i = 0; i < callIDsOfIntrest.Count; i++)
            {
                string callId = callIDsOfIntrest[i];
                msgSearchString += ("SIP_CallId=" + callId);
                if (i < callIDsOfIntrest.Count - 1)
                {
                    msgSearchString += " OR ";
                }
            }

            // create splunk job
            try
            {
                var splunkJob = await service.Jobs.CreateAsync(msgSearchString + msgSearchStringEnd, 0, ExecutionMode.Normal,
                new JobArgs()
                {
                    EarliestTime = SelectedCallsEarliestTime.ToString("O"),
                    LatestTime = SelectedCallsLatestTime.ToString("O"),
                    MaxCount = splunkMaxEvents
                });

                //loop until Job is done or cancelled
                Stopwatch elapsedTime = new Stopwatch();
                elapsedTime.Start();
                for (int count = 1; ; ++count)
                {
                    if (Console.KeyAvailable)
                    {
                        if (Console.ReadKey(true).Key == ConsoleKey.Escape)
                        {
                            break;
                        }
                    }
                    if (count >= splunkMaxTime / splunkStatusInterval)
                    {
                        await splunkJob.FinalizeAsync();
                        Status("Exceeded maximum wait time of " + splunkMaxTime / 1000 + " seconds. Finalizing...");
                        SIPSplunk2.Log("Exceeded maximum wait time of " + splunkMaxTime / 1000 + " seconds. Finalizing...");
                        break;
                    }
                    if (splunkJob.IsFinalized)
                    {
                        Status("Splunk query is finalized");
                        break;
                    }
                    if (splunkJob.DispatchState == DispatchState.Finalizing)
                    {
                        string formatedString = String.Format("Splunk job " + splunkJob.Sid + " Finalizing. Time elapsed: {0:hh\\:mm\\:ss} ", elapsedTime.Elapsed);
                    }
                    try
                    {
                        await splunkJob.TransitionAsync(DispatchState.Done, splunkStatusInterval);
                        break;
                    }
                    catch (TaskCanceledException)
                    {
                        string formatedString = String.Format("Waiting on splunk job " + splunkJob.Sid + " to complete. " + splunkJob.DoneProgress * 100 + "% Time elapsed: {0:hh\\:mm\\:ss} Press Esc to quit.", elapsedTime.Elapsed);
                        Status(formatedString);
                    }
                }
                elapsedTime.Restart();
                //Get results of job as stream instantiate streamreader splunkSR to read it
                if (splunkJob.IsFinalized || splunkJob.IsDone)
                {
                    
                    using (var message = await splunkJob.GetSearchResponseMessageAsync(outputMode: OutputMode.Csv))
                    {
                        Stream splunkStream = await message.Content.ReadAsStreamAsync();
                        sipMessageReader.AcReadData(splunkStream);
                    }
                    if (!splunkExceptions) Status("Completed splunk query with  lines of data");
                    SplunkReadDone = true;
                }
                else
                {
                    Status("Splunk query failed");
                }
            }
            catch (Exception ex)
            {
                SIPSplunk2.Log(ex.ToString());
                splunkExceptions = true;
            }
        }

        async Task AcSyslogSplunkSIPMessagesQuery(Service service)
        {
            string msgSearchString = searchStrg +
                    "| rex field=_raw \"" + @"(?<SIP_Req>ACK.*SIP\/2\.0|BYE.*SIP\/2\.0|CANCEL.*SIP\/2\.0|INFO.*SIP\/2\.0|INVITE.*SIP\/2\.0|MESSAGE.*SIP\/2\.0|NOTIFY.*SIP\/2\.0|OPTIONS.*SIP\/2\.0|PRACK.*SIP\/2\.0|PUBLISH.*SIP\/2\.0|REFER.*SIP\/2\.0|REGISTER.*SIP\/2\.0|SUBSCRIBE.*SIP\/2\.0|UPDATE.*SIP\/2\.0|SIP\/2\.0 \d{3}(\s*\w*))" + "\" | " +
                    "rex field=_raw \"" + @"(?<!-.{8})(?<=Call-ID:)\s*(?<SIP_CallId>\S*)" + "\" | " +
                    "rex field=SIP_Req \"(?<SIP_method>^[a-zA-Z]+)\" | " +
                    "rex field=_raw \"" + @"\d{2}:\d{2}:\d{2}.\d{3}\s*(?<MGIP>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})" + "\" | " +
                    "rex field=_raw \"(?<=Incoming SIP Message from)\\s*(?<SrcIP>\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\" | " +
                    "rex field=_raw \"(?<=Outgoing SIP Message to)\\s*(?<DstIP>\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\" | " +
                    "reverse |streamstats current=f window=5 last(DstIP) as prev_DstIP last(SrcIP) as prev_SrcIP | " +
                    "eval SIP_dstIP=if(prev_DstIP != \"\",prev_DstIP,MGIP) | eval SIP_srcIP=if(prev_SrcIP != \"\",prev_SrcIP,MGIP) | " +
                    "search ";
            string msgSearchStringEnd = " | eval srcIpOut=\"srcip=\"+SIP_srcIP | eval dstIpOut=\"dstip=\"+SIP_dstIP |" +
                    "table srcIpOut,dstIpOut,_raw | ";

            for (int i = 0; i < callIDsOfIntrest.Count; i++)
            {
                string callId = callIDsOfIntrest[i];
                msgSearchString += ("SIP_CallId=" + callId);
                if (i < callIDsOfIntrest.Count - 1)
                {
                    msgSearchString += " OR ";
                }
            }

            // create splunk job
            try
            {

                var splunkJob = await service.Jobs.CreateAsync(msgSearchString + msgSearchStringEnd, 0, ExecutionMode.Normal,
                new JobArgs()
                {
                    EarliestTime = SelectedCallsEarliestTime.ToString("O"),
                    LatestTime = SelectedCallsLatestTime.ToString("O"),
                    MaxCount = splunkMaxEvents
                });

                //loop until Job is done or cancelled
                Stopwatch elapsedTime = new Stopwatch();
                elapsedTime.Start();
                for (int count = 1; ; ++count)
                {
                    if (Console.KeyAvailable)
                    {
                        if (Console.ReadKey(true).Key == ConsoleKey.Escape)
                        {
                            break;
                        }
                    }
                    if (count >= splunkMaxTime / splunkStatusInterval)
                    {
                        await splunkJob.FinalizeAsync();
                        Status("Exceeded maximum wait time of " + splunkMaxTime / 1000 + " seconds. Finalizing...");
                        SIPSplunk2.Log("Exceeded maximum wait time of " + splunkMaxTime / 1000 + " seconds. Finalizing...");
                        break;
                    }
                    if (splunkJob.IsFinalized)
                    {
                        Status("Splunk query is finalized");
                        break;
                    }
                    if (splunkJob.DispatchState == DispatchState.Finalizing)
                    {
                        string formatedString = String.Format("Splunk job " + splunkJob.Sid + " Finalizing. Time elapsed: {0:hh\\:mm\\:ss} ", elapsedTime.Elapsed);
                    }
                    try
                    {
                        await splunkJob.TransitionAsync(DispatchState.Done, splunkStatusInterval);
                        break;
                    }
                    catch (TaskCanceledException)
                    {
                        string formatedString = String.Format("Waiting on splunk job " + splunkJob.Sid + " to complete. " + splunkJob.DoneProgress * 100 + "% Time elapsed: {0:hh\\:mm\\:ss} Press Esc to quit.", elapsedTime.Elapsed);
                        Status(formatedString);
                    }
                }
                elapsedTime.Restart();
                //Get results of job as stream instantiate streamreader splunkSR to read it
                if (splunkJob.IsFinalized || splunkJob.IsDone)
                {
                    using (var message = await splunkJob.GetSearchResponseMessageAsync(outputMode: OutputMode.Csv))
                    {
                        Stream splunkStream = await message.Content.ReadAsStreamAsync();
                        sipMessageReader.AcSyslogReadData(splunkStream);
                    }
                    if (!splunkExceptions) Status("Completed splunk query with  lines of data");
                    SplunkReadDone = true;
                }
                else
                {
                    Status("Splunk query failed");
                }
            }
            catch (Exception ex)
            {
                SIPSplunk2.Log(ex.ToString());
                splunkExceptions = true;
            }
        }

        void Status(String inputString)
        {
            StatusUpdateEventArgs arg = new StatusUpdateEventArgs();
            arg.text = inputString;
            OnStatsUpdate(arg);           
        }

        

        protected virtual void OnStatsUpdate(StatusUpdateEventArgs e)
        {
            StatusUpdateEventHandler handler = StatusUpdateHandler; 
            if (handler != null)
            {
                handler(this, e);
            }
        }

        public event StatusUpdateEventHandler StatusUpdateHandler;

        static String SecureStringToString(SecureString value)
        {
            IntPtr valuePtr = IntPtr.Zero;
            try
            {
                valuePtr = Marshal.SecureStringToGlobalAllocUnicode(value);
                return Marshal.PtrToStringUni(valuePtr);
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocUnicode(valuePtr);
            }
        }

        static SecureString StringToSecureString(String inputString)
        {
            var secure = new SecureString();
            foreach (char c in inputString)
            {
                secure.AppendChar(c);
            }
            return secure;
        }
    }

    public class StatusUpdateEventArgs : EventArgs
    {
        public string text { get; set; }
    }

    public delegate void StatusUpdateEventHandler(Object sender, StatusUpdateEventArgs e);
}
