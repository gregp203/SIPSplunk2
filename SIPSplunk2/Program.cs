using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace SIPSplunk2
{
    static class SIPSplunk2
    {
        static readonly object _LogLocker = new object();
        static StreamWriter logFileSW ;

        [STAThread]
        static void Main()
        {
            
            logFileSW = File.AppendText("log.txt");
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new Form1());
        }

        public static void Log(string logMessage)
        {
            lock (_LogLocker)
            {
                logFileSW.Write("\r\nLog Entry : ");
                logFileSW.WriteLine("{0} {1}", DateTime.Now.ToLongTimeString(),
                    DateTime.Now.ToLongDateString());
                logFileSW.WriteLine("  :");
                logFileSW.WriteLine("  :{0}", logMessage);
                logFileSW.WriteLine("-------------------------------");
            }
        }
    }


}
