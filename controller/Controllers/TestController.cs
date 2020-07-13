using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System.IO;
using Newtonsoft.Json;

namespace TestController.Controllers
{
 
    [ApiController]
    [Route("[controller]")]
    public class TestDataController : ControllerBase
    {
        public static ConcurrentDictionary<string, TestData> Tests = new ConcurrentDictionary<string, TestData>();
        public static ConcurrentDictionary<string, Client> Clients = new ConcurrentDictionary<string, Client>();

        private void WriteError(string error)
        {
            var writer = new StreamWriter(Response.Body);
            Response.StatusCode = 400;
            Response.ContentType = "text/plain";
            writer.Write(error);
            writer.Write("\n");
            writer.Close();
        }

        private void WriteResponse(string contentType, string Body)
        {
            var writer = new StreamWriter(Response.Body);
            Response.ContentType = contentType;
            writer.Write(Body);
            writer.Write("\n");
            writer.Close();
        }

        
        private void WriteJsonResponse<T>(T obj)
        {
            WriteResponse("application/json", JsonConvert.SerializeObject(obj, Formatting.Indented));
        }

        public TestDataController()
        {
        }

        [HttpGet]
        // Get all of the currently running test plans
        public void Get()
        {
            string testId = Request.Query.FirstOrDefault(kvp => kvp.Key.Equals("TestId", StringComparison.OrdinalIgnoreCase)).Value;
            if (!string.IsNullOrEmpty(testId)) 
            {
                WriteJsonResponse(Tests[testId]);
            }
            else 
            {
                WriteJsonResponse(Tests.Values);
            }
        }

        [HttpGet("Clients")]
        // Get all of the clients associated with a test plan
        public void GetClients()
        {
            string id = Request.Query.FirstOrDefault(kvp => kvp.Key.Equals("TestId", StringComparison.OrdinalIgnoreCase)).Value;
            if (string.IsNullOrEmpty(id)) 
            {
                WriteError("Missing TestId");
            }
            else 
            {
                WriteJsonResponse(Clients.Values.Where(c => c.TestId == id));
            }
        }

        [HttpPost("StartTest")]
        // Submit and schedule a test plan
        public async Task StartTest()
        {
            string testId = Request.Query.FirstOrDefault(kvp => kvp.Key.Equals("TestId", StringComparison.OrdinalIgnoreCase)).Value;
            string minimum = Request.Query.FirstOrDefault(kvp => kvp.Key.Equals("Minimum", StringComparison.OrdinalIgnoreCase)).Value;
            string maximum = Request.Query.FirstOrDefault(kvp => kvp.Key.Equals("Maximum", StringComparison.OrdinalIgnoreCase)).Value;
            var reader = new StreamReader(Request.Body);
            var json = await reader.ReadToEndAsync();
            TestData test = JsonConvert.DeserializeObject<TestData>(json);

            if (!string.IsNullOrEmpty(testId)) 
            {
                Console.WriteLine($"Overriding test.Id with {testId}");
                test.Id = testId;
            }
            if (!string.IsNullOrEmpty(minimum)) 
            {
                Console.WriteLine($"Overriding test.Minimum with {minimum}");
                test.Minimum = int.Parse(minimum);
            }
            if (!string.IsNullOrEmpty(maximum)) 
            {
                Console.WriteLine($"Overriding test.Maximum with {maximum}");
                test.Maximum = int.Parse(maximum);
            }
            test.CurrentCommand = 0;
            test.CurrentCommandStart = DateTime.UtcNow;
            test.RegisteredClients = new List<string>();
            test.CompletedCommands = new int[test.Commands.Count];
            

            if (!Tests.TryAdd(test.Id, test))
            {
                WriteError($"Test {test.Id} already exists");
            }
            else {
                WriteResponse("plain/text", $"Starting test {test.Id}");
            }
        }

        [HttpGet("EndTest")]
        // Finish a test plan and collect results
        public void EndTest()
        {
            string id = Request.Query.FirstOrDefault(kvp => kvp.Key.Equals("TestId", StringComparison.OrdinalIgnoreCase)).Value;
            if (!Tests.TryRemove(id, out TestData test)) 
            {
                WriteError($"Test {id} not found exists");
            }
            else {
                WriteJsonResponse(Clients.Values.Where(c => c.TestId == id));
                foreach (string clientId in test.RegisteredClients) 
                {
                    Clients.TryRemove(clientId, out Client client);
                }
            }
        }


        [HttpGet("Register")]
        // Client is ready to run commands.
        // Issue it an ID, associate it with a test and give it the signing cert.
        public void Register()
        {
            
            Client c = new Client()
            {
                Id = Guid.NewGuid().ToString(),
                Results = new List<Result>(),
                CurrentCommand = 0,
                IpAddress = Request.HttpContext.Connection.RemoteIpAddress.MapToIPv4().ToString()
            };

            var test = Tests.FirstOrDefault(kvp =>
            {
                lock (kvp.Value)
                {
                    if (kvp.Value.RegisteredClients.Count >= kvp.Value.Maximum)
                    {
                        return false;
                    }
                    else
                    {
                        kvp.Value.RegisteredClients.Add(c.Id);
                        c.TestId = kvp.Key;
                        return true;
                    }
                }
            });
            if (test.Key != null)
            {
                var registrationData = new RegistrationData() 
                {
                    ClientId = c.Id,
                    Certificate = test.Value.Certificate
                };

                Clients.TryAdd(c.Id, c);

                WriteJsonResponse(registrationData);
            }
            else
            {
                WriteError("No active tests");
            }
            
        }

        [HttpGet("NextCommand")]
        // Give the client the next command to run.
        public void NextCommand()
        {
            string id = Request.Query.FirstOrDefault(kvp => kvp.Key.Equals("id", StringComparison.OrdinalIgnoreCase)).Value;
            if (!Clients.TryGetValue(id, out Client client))
            {
                WriteError("Client not registered");
                return;
            }
            else
            {
                if (!Tests.TryGetValue(client.TestId, out TestData test))
                {
                    WriteError("TestID not registered");
                    return;
                }
                else
                {
                    // Capture the values within the lock, respond to client outside of lock.
                    int testCurrentCommand;
                    Command currentCommand;
                    lock (test)
                    {
                        testCurrentCommand = test.CurrentCommand;
                        currentCommand = client.CurrentCommand < test.Commands.Count ? test.Commands[client.CurrentCommand] : null;
                    }
                    // Client has reached end of test.
                    if (currentCommand == null)
                    {
                        WriteResponse("text/plain", "exit");
                    }
                    // Client is ahead of test, wait
                    else if (client.CurrentCommand > testCurrentCommand)
                    {
                        WriteResponse("text/plain", "wait");
                    } 
                    // Send the current command
                    else
                    {
                        client.CurrentCommandStartTime = DateTime.UtcNow;
                        WriteJsonResponse(currentCommand);
                    }
                }
            }
        }

        [HttpPost("CommandResult")]
        // Client reports result of command.
        public async Task CommandResult()
        {
            string id = Request.Query.FirstOrDefault(kvp => kvp.Key.Equals("id", StringComparison.OrdinalIgnoreCase)).Value;
            var reader = new StreamReader(Request.Body);
            var result = await reader.ReadToEndAsync();
            if (!Clients.TryGetValue(id, out Client client))
            {
                WriteError("Client not registered");
                return;
            }

            if (!Tests.TryGetValue(client.TestId, out TestData test))
            {
                WriteError("TestID not registered");
                return;
            }

            client.Results.Add(new Result() { StartTime = client.CurrentCommandStartTime, EndTime = System.DateTime.UtcNow, Results = result.Split('\n')});

            lock (test) 
            {
                // Increment the count of clients that have completed this command.
                test.CompletedCommands[client.CurrentCommand] ++;
                
                // Advance this client to the next command
                client.CurrentCommand ++;

                // If enough clients have reached this point, advance to the next command
                if (test.CurrentCommand != test.Commands.Count && test.CompletedCommands[test.CurrentCommand] >= test.Minimum)
                {
                    test.CurrentCommandStart = DateTime.UtcNow;
                    test.CurrentCommand++;
                }
            }

        }

    }
}
