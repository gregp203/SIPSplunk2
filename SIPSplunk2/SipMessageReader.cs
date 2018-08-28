using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace SIPSplunk2
{
    public class SipMessageReader
    {
        
        string beginMsgRgxStr = @"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}.\d{6}.*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"; //regex to match the begining of the sip message (if it starts with a date and has time and two IP addresses)  for tcpdumpdump
        string acBeginMsgRgxStr = @".srcip=(?<SrcIP>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*dstip=(?<DstIP>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*Sent:(?<timedate>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3}.\d{2}:\d{2}).*(?<req>ACK.*SIP\/2\.0|BYE.*SIP\/2\.0|CANCEL.*SIP\/2\.0|INFO.*SIP\/2\.0|INVITE.*SIP\/2\.0|MESSAGE.*SIP\/2\.0|NOTIFY.*SIP\/2\.0|OPTIONS.*SIP\/2\.0|PRACK.*SIP\/2\.0|PUBLISH.*SIP\/2\.0|REFER.*SIP\/2\.0|REGISTER.*SIP\/2\.0|SUBSCRIBE.*SIP\/2\.0|UPDATE.*SIP\/2\.0|SIP\/2\.0 \d{3}(\s*\w*))";
        string acSyslogBeginMsgRgxStr = @".srcip=(?<SrcIP>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*dstip=(?<DstIP>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*\d{2}:\d{2}:\d{2}.(?<ms>\d{3}).*(?<req>ACK.*SIP\/2\.0|BYE.*SIP\/2\.0|CANCEL.*SIP\/2\.0|INFO.*SIP\/2\.0|INVITE.*SIP\/2\.0|MESSAGE.*SIP\/2\.0|NOTIFY.*SIP\/2\.0|OPTIONS.*SIP\/2\.0|PRACK.*SIP\/2\.0|PUBLISH.*SIP\/2\.0|REFER.*SIP\/2\.0|REGISTER.*SIP\/2\.0|SUBSCRIBE.*SIP\/2\.0|UPDATE.*SIP\/2\.0|SIP\/2\.0 \d{3}(\s*\w*))";
        string acSyslogTimeRgxStr = @"\[Time:(?<day>\d{2})-(?<month>\d{2})@(?<time>\d{2}:\d{2}:\d{2})\]";
        string dateRgxStr = @"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}.\d{6})"; //for tcpdumpdump 
        string srcIpRgxStr = @"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?=(.|:)\d* >)";
        string dstIpRgxStr = @"(?<=> )(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})";
        string requestRgxStr = @"ACK.*SIP\/2\.0|BYE.*SIP\/2\.0|CANCEL.*SIP\/2\.0|INFO.*SIP\/2\.0|INVITE.*SIP\/2\.0|MESSAGE.*SIP\/2\.0|NOTIFY.*SIP\/2\.0|OPTIONS.*SIP\/2\.0|PRACK.*SIP\/2\.0|PUBLISH.*SIP\/2\.0|REFER.*SIP\/2\.0|REGISTER.*SIP\/2\.0|SUBSCRIBE.*SIP\/2\.0|UPDATE.*SIP\/2\.0|SIP\/2\.0 \d{3}(\s*\w*)";
        //string callidRgxStr = @"(?<!-.{8})(?<=Call-ID:)\S*";//do not match if -Call-ID instead of Call-ID
        string callidRgxStr = @"(?<!-.{8})(?<=Call-ID:)\s* (\S*)";
        string toRgxStr = @"(?<=To:) *(\x22.+\x22)? *<?(sip:)([^@>]+)";
        string fromRgxStr = @"(?<=From:) *(\x22.+\x22)? *<?(sip:)([^@>]+)";
        string uaRgxStr = @"(?<=User-Agent:).*";
        string serverRgxStr = @"(?<=Server:).*";
        string portRgxStr = @"(?<=m=audio )\d*";
        string codecRgxStr = @"(?<=RTP\/AVP )\d*";
        string SDPIPRgxStr = @"(?<=c=IN IP4 )(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})";
        string mAudioRgxStr = @"m=audio \d* RTP\/AVP \d*";
        string occasRgxStr = @"(?<=Contact: ).*wlssuser";
        string cseqRgxStr = @"CSeq:\s?(\d{1,3})\s?(\w*)";
        Regex beginmsgRgx;
        Regex acBeginMsgRgx;
        Regex acSyslogBeginMsgRgx;
        Regex acSyslogTimeRgx;
        Regex dateRgx;
        Regex srcIpRgx;
        Regex dstIpRgx;
        Regex requestRgx;
        Regex callidRgx;
        Regex toRgx;
        Regex fromRgx;
        Regex uaRgx;
        Regex serverRgx;
        Regex portRgx;
        Regex codecRgx;
        Regex SDPIPRgx;
        Regex mAudioRgx;
        Regex occasRgx;
        Regex cseqRgx;
        long currentLoadProg;
        List<string[]> messages = new List<string[]>();
        List<string> streamData = new List<string>();
        static readonly object _DataLocker = new object();

        public SipMessageReader()
        {
            
            Regex.CacheSize = 19;
            beginmsgRgx = new Regex(beginMsgRgxStr, RegexOptions.Compiled);
            acBeginMsgRgx = new Regex(acBeginMsgRgxStr, RegexOptions.Compiled);
            acSyslogBeginMsgRgx = new Regex(acSyslogBeginMsgRgxStr, RegexOptions.Compiled);
            acSyslogTimeRgx = new Regex(acSyslogTimeRgxStr, RegexOptions.Compiled);
            dateRgx = new Regex(dateRgxStr, RegexOptions.Compiled);
            srcIpRgx = new Regex(srcIpRgxStr, RegexOptions.Compiled);
            dstIpRgx = new Regex(dstIpRgxStr, RegexOptions.Compiled);
            requestRgx = new Regex(requestRgxStr, RegexOptions.Compiled);
            callidRgx = new Regex(callidRgxStr, RegexOptions.Compiled);
            toRgx = new Regex(toRgxStr, RegexOptions.Compiled);
            fromRgx = new Regex(fromRgxStr, RegexOptions.Compiled);
            uaRgx = new Regex(uaRgxStr, RegexOptions.Compiled);
            serverRgx = new Regex(serverRgxStr, RegexOptions.Compiled);
            portRgx = new Regex(portRgxStr, RegexOptions.Compiled);
            codecRgx = new Regex(codecRgxStr, RegexOptions.Compiled);
            SDPIPRgx = new Regex(SDPIPRgxStr, RegexOptions.Compiled);
            mAudioRgx = new Regex(mAudioRgxStr, RegexOptions.Compiled);
            occasRgx = new Regex(occasRgxStr, RegexOptions.Compiled);
            cseqRgx = new Regex(cseqRgxStr, RegexOptions.Compiled);
        }

        public void ReadData(Stream stream)
        {
            streamData.Clear();
            messages.Clear();
            StreamReader streamReader = new StreamReader(stream);
            currentLoadProg = 0;
            while (!streamReader.EndOfStream)
            {
                string line = GetNextLine(streamReader);
                if (line != null)
                {
                    while (!string.IsNullOrEmpty(line) && beginmsgRgx.IsMatch(line))
                    {
                        String[] outputarray = new String[18];

                        // get the index of the start of the msg
                        outputarray[0] = currentLoadProg.ToString();
                        outputarray[1] = dateRgx.Match(line).ToString();
                        outputarray[2] = DateTime.Parse(dateRgx.Match(line).ToString()).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);
                        outputarray[3] = srcIpRgx.Match(line).ToString();                              //src IP                                                                        
                        outputarray[4] = dstIpRgx.Match(line).ToString();
                        line = GetNextLine(streamReader);
                        if (line == null) { break; }

                        //check to match these only once. no need match a field if it is already found
                        bool sipTwoDotOfound = false;
                        Match sipTwoDotO;
                        Match callid;
                        Match cseq;
                        Match to;
                        Match from; ;
                        Match SDPIP;
                        Match ua;
                        Match serv;

                        //untill the begining of the next msg
                        while (!beginmsgRgx.IsMatch(line))
                        { //match line against regexs
                            switch (line)
                            {
                                case string s when (sipTwoDotO = requestRgx.Match(s)) != Match.Empty:
                                    outputarray[5] = sipTwoDotO.ToString();
                                    sipTwoDotOfound = true;
                                    break;
                                case string s when (callid = callidRgx.Match(s)) != Match.Empty:
                                    outputarray[6] = callid.Groups[1].ToString();
                                    break;
                                case string s when (cseq = cseqRgx.Match(s)) != Match.Empty:
                                    outputarray[17] = cseq.Groups[2].ToString();
                                    break;
                                case string s when (to = toRgx.Match(s)) != Match.Empty:
                                    outputarray[7] = to.Groups[1].ToString() + to.Groups[3].ToString();
                                    break;
                                case string s when (from = fromRgx.Match(s)) != Match.Empty:
                                    outputarray[8] = from.Groups[1].ToString() + from.Groups[3].ToString();
                                    break;
                                case string s when s.Contains("Content-Type: application/sdp"):
                                    outputarray[11] = " SDP";
                                    break;
                                case string s when (SDPIP = SDPIPRgx.Match(s)) != Match.Empty:
                                    outputarray[13] = SDPIP.ToString();
                                    break;
                                case string s when mAudioRgx.IsMatch(s):
                                    outputarray[14] = portRgx.Match(s).ToString().Trim();
                                    outputarray[15] = codecRgx.Match(s).ToString().Trim();
                                    if (outputarray[15] == "0") { outputarray[15] = "G711u"; }
                                    else if (outputarray[15] == "8") { outputarray[15] = "G711a"; }
                                    else if (outputarray[15] == "9") { outputarray[15] = "G722"; }
                                    else if (outputarray[15] == "18") { outputarray[15] = "G729"; }
                                    else { outputarray[15] = "rtp-payload type:" + outputarray[15]; }
                                    break;
                                case string s when (ua = uaRgx.Match(s)) != Match.Empty:
                                    outputarray[16] = ua.ToString().Trim();
                                    break;
                                case string s when (serv = serverRgx.Match(s)) != Match.Empty:
                                    outputarray[16] = serv.ToString().Trim();
                                    break;
                                case string s when occasRgx.IsMatch(s):
                                    outputarray[16] = "occas";
                                    break;
                            }
                            line = GetNextLine(streamReader);
                            if (line == null) { break; }
                        }

                        // get the index of the end of the msg
                        outputarray[9] = currentLoadProg.ToString();
                        outputarray[10] = "Gray";
                        outputarray[12] = "splunk"; //add file name 
                        if (outputarray[5] == null) { outputarray[5] = "Invalid SIP characters"; }
                        if (sipTwoDotOfound)
                        {
                            lock (_DataLocker) //messages touched by another thread 
                            {
                                messages.Add(outputarray);
                            }
                        }
                    }
                }
                else
                {
                    currentLoadProg++;
                }
            }
            streamReader.Close();
        }

        public void AcReadData(Stream stream)
        {
            streamData.Clear();
            messages.Clear();
            StreamReader streamReader = new StreamReader(stream);
            currentLoadProg = 0;
            while (!streamReader.EndOfStream)
            {
                string line = GetNextLine(streamReader);
                if (line != null)
                {
                    while (!string.IsNullOrEmpty(line) && acBeginMsgRgx.IsMatch(line))
                    {

                        String[] outputarray = new String[18];

                        // get the index of the start of the msg
                        outputarray[0] = currentLoadProg.ToString();
                        outputarray[1] = acBeginMsgRgx.Match(line).Groups["timedate"].ToString();
                        outputarray[2] = DateTime.Parse(acBeginMsgRgx.Match(line).Groups["timedate"].ToString()).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);
                        outputarray[3] = acBeginMsgRgx.Match(line).Groups["SrcIP"].ToString(); //src IP                                                                        
                        outputarray[4] = acBeginMsgRgx.Match(line).Groups["DstIP"].ToString();
                        outputarray[5] = acBeginMsgRgx.Match(line).Groups["req"].ToString();
                        line = GetNextLine(streamReader);

                        //check to match these only once. no need match a field if it is already found                
                        Match callid;
                        Match cseq;
                        Match to;
                        Match from; ;
                        Match SDPIP;
                        Match ua;
                        Match serv;

                        //untill the begining of the next msg
                        while (!acBeginMsgRgx.IsMatch(line))
                        { //match line against regexs
                            switch (line)
                            {
                                case string s when (callid = callidRgx.Match(s)) != Match.Empty:
                                    outputarray[6] = callid.Groups[1].ToString();
                                    break;
                                case string s when (cseq = cseqRgx.Match(s)) != Match.Empty:
                                    outputarray[17] = cseq.Groups[2].ToString();
                                    break;
                                case string s when (to = toRgx.Match(s)) != Match.Empty:
                                    outputarray[7] = to.Groups[1].ToString() + to.Groups[3].ToString();
                                    break;
                                case string s when (from = fromRgx.Match(s)) != Match.Empty:
                                    outputarray[8] = from.Groups[1].ToString() + from.Groups[3].ToString();
                                    break;
                                case string s when s.Contains("Content-Type: application/sdp"):
                                    outputarray[11] = " SDP";
                                    break;
                                case string s when (SDPIP = SDPIPRgx.Match(s)) != Match.Empty:
                                    outputarray[13] = SDPIP.ToString();
                                    break;
                                case string s when mAudioRgx.IsMatch(s):
                                    outputarray[14] = portRgx.Match(s).ToString().Trim();
                                    outputarray[15] = codecRgx.Match(s).ToString().Trim();
                                    if (outputarray[15] == "0") { outputarray[15] = "G711u"; }
                                    else if (outputarray[15] == "8") { outputarray[15] = "G711a"; }
                                    else if (outputarray[15] == "9") { outputarray[15] = "G722"; }
                                    else if (outputarray[15] == "18") { outputarray[15] = "G729"; }
                                    else { outputarray[15] = "rtp-payload type:" + outputarray[15]; }
                                    break;
                                case string s when (ua = uaRgx.Match(s)) != Match.Empty:
                                    outputarray[16] = ua.ToString().Trim();
                                    break;
                                case string s when (serv = serverRgx.Match(s)) != Match.Empty:
                                    outputarray[16] = serv.ToString().Trim();
                                    break;
                                case string s when occasRgx.IsMatch(s):
                                    outputarray[16] = "occas";
                                    break;
                            }
                            line = GetNextLine(streamReader);
                            if (line == null) { break; }
                        }

                        // get the index of the end of the msg
                        outputarray[9] = currentLoadProg.ToString();
                        outputarray[10] = "Gray";
                        outputarray[12] = "splunk"; //add file name 
                        if (outputarray[5] == null) { outputarray[5] = "Invalid SIP characters"; }
                        lock (_DataLocker) //messages touched by another thread 
                        {
                            messages.Add(outputarray);
                        }
                    }
                }
                else
                {
                    currentLoadProg++;
                }
            }
            streamReader.Close();
        }

        public void AcSyslogReadData(Stream stream)
        {
            streamData.Clear();
            messages.Clear();
            StreamReader streamReader = new StreamReader(stream);
            currentLoadProg = 0;
            while (!streamReader.EndOfStream)
            {
                string line = GetNextLine(streamReader);
                if (line != null)
                {
                    while (!string.IsNullOrEmpty(line) && acSyslogBeginMsgRgx.IsMatch(line))
                    {

                        String[] outputarray = new String[18];
                        string milliSeconds;
                        string yearStrg;

                        // get the index of the start of the msg
                        outputarray[0] = currentLoadProg.ToString();
                        //outputarray[1] = acBeginMsgRgx.Match(line).Groups["timedate"].ToString();
                        milliSeconds = acSyslogBeginMsgRgx.Match(line).Groups["ms"].ToString();

                        outputarray[3] = acSyslogBeginMsgRgx.Match(line).Groups["SrcIP"].ToString(); //src IP                                                                        
                        outputarray[4] = acSyslogBeginMsgRgx.Match(line).Groups["DstIP"].ToString();
                        outputarray[5] = acSyslogBeginMsgRgx.Match(line).Groups["req"].ToString();
                        line = GetNextLine(streamReader);

                        //check to match these only once. no need match a field if it is already found                
                        Match callid;
                        Match cseq;
                        Match to;
                        Match from; ;
                        Match SDPIP;
                        Match ua;
                        Match serv;
                        Match timeMatch;

                        //untill the begining of the next msg
                        while (!acSyslogBeginMsgRgx.IsMatch(line))
                        { //match line against regexs
                            switch (line)
                            {
                                case string s when (callid = callidRgx.Match(s)) != Match.Empty:
                                    outputarray[6] = callid.Groups[1].ToString();
                                    break;
                                case string s when (cseq = cseqRgx.Match(s)) != Match.Empty:
                                    outputarray[17] = cseq.Groups[2].ToString();
                                    break;
                                case string s when (to = toRgx.Match(s)) != Match.Empty:
                                    outputarray[7] = to.Groups[1].ToString() + to.Groups[3].ToString();
                                    break;
                                case string s when (from = fromRgx.Match(s)) != Match.Empty:
                                    outputarray[8] = from.Groups[1].ToString() + from.Groups[3].ToString();
                                    break;
                                case string s when s.Contains("Content-Type: application/sdp"):
                                    outputarray[11] = " SDP";
                                    break;
                                case string s when (SDPIP = SDPIPRgx.Match(s)) != Match.Empty:
                                    outputarray[13] = SDPIP.ToString();
                                    break;
                                case string s when mAudioRgx.IsMatch(s):
                                    outputarray[14] = portRgx.Match(s).ToString().Trim();
                                    outputarray[15] = codecRgx.Match(s).ToString().Trim();
                                    if (outputarray[15] == "0") { outputarray[15] = "G711u"; }
                                    else if (outputarray[15] == "8") { outputarray[15] = "G711a"; }
                                    else if (outputarray[15] == "9") { outputarray[15] = "G722"; }
                                    else if (outputarray[15] == "18") { outputarray[15] = "G729"; }
                                    else { outputarray[15] = "rtp-payload type:" + outputarray[15]; }
                                    break;
                                case string s when (ua = uaRgx.Match(s)) != Match.Empty:
                                    outputarray[16] = ua.ToString().Trim();
                                    break;
                                case string s when (serv = serverRgx.Match(s)) != Match.Empty:
                                    outputarray[16] = serv.ToString().Trim();
                                    break;
                                case string s when occasRgx.IsMatch(s):
                                    outputarray[16] = "occas";
                                    break;
                                case string s when (timeMatch = acSyslogTimeRgx.Match(s)) != Match.Empty:
                                    if (Int32.Parse(timeMatch.Groups["month"].ToString()) >= DateTime.Now.Month)
                                    {
                                        yearStrg = (DateTime.Now.Year - 1).ToString();
                                    }
                                    else
                                    {
                                        yearStrg = (DateTime.Now.Year).ToString();
                                    }
                                    outputarray[1] = yearStrg + "-" + timeMatch.Groups["month"].ToString() + "-" + timeMatch.Groups["day"].ToString() + "T" + timeMatch.Groups["time"].ToString() + "." + milliSeconds + "-05:00";
                                    outputarray[2] = DateTime.Parse(outputarray[1]).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);
                                    break;
                            }
                            line = GetNextLine(streamReader);
                            if (line == null) { break; }
                        }

                        // get the index of the end of the msg
                        outputarray[9] = currentLoadProg.ToString();
                        outputarray[10] = "Gray";
                        outputarray[12] = "splunk"; //add file name 
                        if (outputarray[5] == null) { outputarray[5] = "Invalid SIP characters"; }
                        lock (_DataLocker) //messages touched by another thread 
                        {
                            messages.Add(outputarray);
                        }
                    }
                }
                else
                {
                    currentLoadProg++;
                }
            }
            streamReader.Close();
        }

        string GetNextLine(StreamReader streamReader)
        {
            string line;
            line = streamReader.ReadLine();
            lock (_DataLocker) streamData.Add(line);  //touched by another threaD
            currentLoadProg++;
            return line;
        }
    }
}
