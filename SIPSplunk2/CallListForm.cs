using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace SIPSplunk2
{
    public partial class CallListForm : Form
    {
        List<string[]> calls;
        public CallListForm(List<string[]> callsArg)
        {
            InitializeComponent();
            
            this.listView1.ColumnClick += new System.Windows.Forms.ColumnClickEventHandler(this.listView1_ColumnClick);
            calls = new List<string[]>();
            calls = callsArg.ToList();
            filterAndUpdateList(calls);
            listView1.Items.Add(new ListViewItem(new string[] { "", "2000-01-01T00: 00:00.000-05:00", "FFFFFFFFFFFF", "FFFFFFFFFFFF", "123.123.123.123", "123.123.123.123" }));
        }
        private void listView1_ColumnClick(object sender, System.Windows.Forms.ColumnClickEventArgs e)
        {
            List<string[]> sortedCalls = new List<string[]>();
            switch (e.Column)
            {
                case 0: //checkbox
                    Debug.WriteLine("0");
                    break;
                case 1: //time and date [0]
                    Debug.WriteLine("1");
                    sortedCalls = calls.OrderBy(call => call[0]).ToList();
                    break;
                case 2: //from [3]
                    Debug.WriteLine("2");
                    sortedCalls = calls.OrderBy(call  => call[3]).ToList();
                    break;
                case 3: //to [2]
                    Debug.WriteLine("3");
                    sortedCalls = calls.OrderBy(call => call[2]).ToList();
                    break;
                case 4: //src ip [6]
                    Debug.WriteLine("4");
                    sortedCalls = calls.OrderBy(call => call[6]).ToList();
                    break;
                case 5: // dst ip [7]
                    Debug.WriteLine("5");
                    sortedCalls = calls.OrderBy(call => call[7]).ToList();
                    break;
            }
            listView1.Items.Clear();
            filterAndUpdateList(sortedCalls);
        }

        private void CallListForm_Load(object sender, EventArgs e)
        {
            
        }

        private void filterButton_Click(object sender, EventArgs e)
        {
            listView1.Items.Clear();
            filterAndUpdateList(calls);
        }

        private void listView1_SelectedIndexChanged(object sender, EventArgs e)
        {

        }

        private void filterAndUpdateList (List<string[]> inputCalls)
        {
            listView1.Items.Clear();
            foreach (string[] call in inputCalls)
            {
                if (Regex.IsMatch(String.Join(" ", call), filterTextBox.Text))
                //if (call.Contains<string>(filterTextBox.Text))
                {
                    String[] row = new String[6];
                    row[0] = "";
                    row[1] = call[0];
                    row[2] = call[3];
                    row[3] = call[2];
                    row[4] = call[6];
                    row[5] = call[7];
                    listView1.Items.Add(new ListViewItem(row));
                }
            }
        }


    }
}
