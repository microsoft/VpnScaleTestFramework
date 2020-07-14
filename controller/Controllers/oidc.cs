using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;

namespace TestController.Controllers
{
    [Route("[controller]")]
    [ApiController]
    public class OidcController : ControllerBase
    {
        private static string rootKey = RunBinary("generate_root_key", Guid.NewGuid().ToString(), null);

        private static string RunBinary(string fileName, string arguments, string input)
        {
            var process = new Process()
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = fileName,
                    Arguments = arguments,
                    RedirectStandardOutput = true,
                    RedirectStandardInput = input != null ? true : false,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                }
            };
            process.Start();
            if (input != null)
            {
                process.StandardInput.WriteLine(input);
            }
            string result = process.StandardOutput.ReadToEnd();
            process.WaitForExit();
            return result;
        }


        // GET: 
        [HttpGet]
        public IEnumerable<string> Get()
        {
            return new List<string>() { };
        }

        // GET: api/oidc/openid-configuration
        [HttpGet("openid-configuration")]
        public object GetOpenidConfiguration()
        {
            return RunBinary("generate_oidc_config", $"http://{this.HttpContext.Request.Host.Value}/oidc/keys", null);
        }

        // GET: api/oidc/keys
        [HttpGet("keys")]
        public object GetKeys()
        {
            return RunBinary("generate_keys", null, rootKey);
        }

        // GET: api/oidc/token
        [HttpGet("token")]
        public object GetToken()
        {
            string uid = Request.Query.FirstOrDefault(kvp => kvp.Key.Equals("UID", StringComparison.OrdinalIgnoreCase)).Value;
            Guid clientGuid = Guid.NewGuid();
            if (uid != null && !Guid.TryParse(uid, out clientGuid))
            {
                throw new ArgumentException();
            }

            return RunBinary("generate_token", clientGuid.ToString(), rootKey);
        }

        // GET: api/oidc/json-config-file
        [HttpGet("json-config-file")]
        public object GetJsonConfigFile()
        {
            string aud = Request.Query.FirstOrDefault(kvp => kvp.Key.Equals("aud", StringComparison.OrdinalIgnoreCase)).Value.FirstOrDefault() ?? "SomAudience";
            string iss = Request.Query.FirstOrDefault(kvp => kvp.Key.Equals("iss", StringComparison.OrdinalIgnoreCase)).Value.FirstOrDefault() ?? "SomeIssuer";
            return new JsonConfigFile
            {
                openid_configuration_url = $"http://{this.HttpContext.Request.Host.Value}/oidc/openid-configuration",
                user_name_claim = "oid",
                required_claims = new Required_Claims
                {
                    aud = aud,
                    iss = iss
                }
            };
        }
    }
}
