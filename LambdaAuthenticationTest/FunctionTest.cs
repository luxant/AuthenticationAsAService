using Amazon.Lambda.APIGatewayEvents;
using System;
using Xunit;
using System.Collections.Generic;
using Moq;

namespace LambdaAuthenticationTest
{
    public class FunctionTest
    {
        [Fact]
        public void ValidateJsonWebTokenTest()
        {
            var request = new APIGatewayProxyRequest(){
                Headers = new Dictionary<string, string>
                {
                    { "Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJnaXZlbl9uYW1lIjoiQXdzb21lIiwiYmlydGhkYXRlIjoieWVzdGVyZGF5IiwiZXhwIjoxNjMzNDYzMDYxLCJpc3MiOiJNeUlzc3VlciIsImF1ZCI6Ik15SXNzdWVyIn0.zrwTy4jv6blQLFtjpJMoLNUOxlnCEfIpRZG5KimnDjo" }
                    //{ "Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJnaXZlbl9uYW1lIjoiQXdzb21lIiwiYmlydGhkYXRlIjoieWVzdGVyZGF5IiwiZXhwIjoxNjMzNDU1NDA5LCJpc3MiOiJNeUlzc3VlciIsImF1ZCI6Ik15SXNzdWVyIn0.--6M3QuEQJcKjlPbpR0qZb20s7-MonaDm1-t7nik0F0" }
                }
            };


            Environment.SetEnvironmentVariable("jwtIssuer", "MyIssuer");
            Environment.SetEnvironmentVariable("jwtKey", "ThisismySecretKey");

            LambdaAuthentication.Functions.ValidateJsonWebToken(request, context: null);
        }
    }
}
