namespace TestController
{
    public class JsonConfigFile
    {
        public string openid_configuration_url { get; set; }
        public string user_name_claim { get; set; }
        public Required_Claims required_claims { get; set; }
    }

    public class Required_Claims
    {
        public string aud { get; set; }
        public string iss { get; set; }
    }
}
