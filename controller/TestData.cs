using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace TestController
{
    public class Command
    {
        public string Value;
        public string Signature;
    }

    public class RegistrationData
    {
        public string ClientId;
        public string Certificate;
        public Dictionary<string, string> EnvironmentVariables;
    }

    public class TestData
    {
        [JsonRequired]
        public string Id;

        public int CurrentCommand;

        public DateTime CurrentCommandStart;

        public int [] CompletedCommands;

        [JsonRequired]
        public string Certificate;
        
        [JsonRequired]
        public int Minimum;

        [JsonRequired]
        public int Maximum;

        [JsonRequired]
        public List<Command> Commands;

        [JsonIgnore]
        public List<string> RegisteredClients;
    }
}
