using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace TestController
{
    public class Result
    {
        public DateTime StartTime;
        public DateTime EndTime;
        public IEnumerable<string> Results;
    }

    public class Client
    {
        public string Id;
        public string TestId;
        public string IpAddress;
        public int CurrentCommand;
        public DateTime CurrentCommandStartTime;
        public List<Result> Results;
    }
}
