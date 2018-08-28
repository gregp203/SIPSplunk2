using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Diagnostics;
using System.Text.RegularExpressions;
using System.Globalization;
using System.Threading;

namespace SIPSplunk2
{
    public partial class Form1 : Form
    {
        SipMessageReader sipMessageReader;
        SplunkSearch splunkSearch;
        CancellationTokenSource cancellationTokenSource;

        public Form1()
        {
            InitializeComponent();
            
        }

        private void Form1_Load(object sender, EventArgs e)
        {

        }

        private async void submitButton_Click(object sender, EventArgs e)
        {
            if (VerifyFields())
            {
                sipMessageReader = new SipMessageReader();
                splunkSearch = new SplunkSearch(
                    serverTextBox.Text,
                    userTextBox.Text,
                    passwordTextBox.Text,
                    indexTextBox.Text,
                    sourceTextBox.Text,
                    earliestTimePicker.Value,
                    latestTimePicker.Value,
                    "tcpdump",
                    sipMessageReader
                    );
                splunkSearch.StatusUpdateHandler += StatusUpdate;
                cancellationTokenSource = new CancellationTokenSource();
                await splunkSearch.SplunkGetCallsAsync(cancellationTokenSource.Token);
                if (splunkSearch.Calls.Count > 0)
                {
                    Form callListForm = new CallListForm(splunkSearch.Calls);
                    callListForm.Show();
                }else
                {
                    statusTextBox.Invoke((MethodInvoker)delegate { statusTextBox.AppendText("no calls found" + Environment.NewLine); });
                }
            }
        }

        void StatusUpdate(Object sender, StatusUpdateEventArgs e)
        {
            statusTextBox.Invoke((MethodInvoker)delegate { statusTextBox.AppendText(e.text+Environment.NewLine); });
        }

        bool VerifyFields()
        {
            bool serverTextBoxGood = false;
            bool indexTextBoxGood = false;
            bool sourceTextBoxGood = false;
            bool userTextBoxGood = false;
            bool passwordTextBoxGood = false;
            bool TimePickerGood = false;
            

            if (!String.IsNullOrEmpty(serverTextBox.Text)) serverTextBoxGood = true;
            else MessageBox.Show("The entry for server is Invalid");
            if (!String.IsNullOrEmpty(indexTextBox.Text)) indexTextBoxGood = true;
            else MessageBox.Show("The entry for index is Invalid");
            if (!String.IsNullOrEmpty(sourceTextBox.Text)) sourceTextBoxGood = true;
            else MessageBox.Show("The entry for source is empty");
            if (!String.IsNullOrEmpty(userTextBox.Text)) userTextBoxGood = true;
            else MessageBox.Show("The user entry is empty");
            if (!String.IsNullOrEmpty(passwordTextBox.Text)) passwordTextBoxGood = true;
            else MessageBox.Show("The password entry is empty");
            if (earliestTimePicker.Value < latestTimePicker.Value) TimePickerGood = true;
            else MessageBox.Show("Earliest must be before latest");
            return serverTextBoxGood &&
                indexTextBoxGood &&
                sourceTextBoxGood &&
                userTextBoxGood &&
                passwordTextBoxGood &&
                TimePickerGood;
        }

        static DateTime RelativeToDateTime(String input)
        {
            DateTime result = DateTime.MinValue;
            if (Regex.IsMatch(input, @"\d{2}\/\d{2}\/\d{4}:\d{2}:\d{2}:\d{2}")) result = DateTime.ParseExact(input, "MM/dd/yyyy:HH:mm:ss", CultureInfo.InvariantCulture);
            //if (!DateTime.TryParse(input,out result)) return result;
            else if (input.Contains("minute") || input.Contains("m"))
                result = DateTime.Now.AddMinutes(-1 * Int32.Parse(Regex.Match(input, @"-(?<minutes>\d+)\s*(m\W|mi.*)").Groups["minutes"].Value));
            else if (input.Contains("hour") || input.Contains("h"))
                result = DateTime.Now.AddHours(-1 * Int32.Parse(Regex.Match(input, @"-(?<hours>\d+)\s*h").Groups["hours"].Value));
            else if (input.Contains("day") || input.Contains("d"))
                result = DateTime.Now.AddDays(-1 * Int32.Parse(Regex.Match(input, @"-(?<days>\d+)\s*d").Groups["days"].Value));
            else if (input.Contains("week") || Regex.IsMatch(input, @"\d\s*w"))
                result = DateTime.Now.AddDays(-1 * 7 * Int32.Parse(Regex.Match(input, @" - (?<weeks>\d+)\s*w").Groups["weeks"].Value));
            else if (input.Contains("month") || input.Contains("M"))
                result = DateTime.Now.AddMonths(-1 * Int32.Parse(Regex.Match(input, @"-(?<months>\d+)\s*(M\W|mo.*)").Groups["months"].Value));
            else if (input.Contains("now"))
                result = DateTime.Now;
            return result;
        }

        private void button2_Click(object sender, EventArgs e)
        {
            if (cancellationTokenSource!=null)cancellationTokenSource.Cancel();
        }
    }       
}           
            
            
            
            
            
