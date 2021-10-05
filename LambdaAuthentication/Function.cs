using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

using Amazon.Lambda.Core;
using Amazon.Lambda.APIGatewayEvents;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;

// Assembly attribute to enable the Lambda function's JSON input to be converted into a .NET class.
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace LambdaAuthentication
{
    public static class Functions
    {
        public static APIGatewayProxyResponse GenerateJsonWebToken(APIGatewayProxyRequest request, ILambdaContext context)
        {
            var jwtIssuer = Environment.GetEnvironmentVariable("jwtIssuer");
            var jwtKey = Environment.GetEnvironmentVariable("jwtKey");

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: jwtIssuer,
                audience: jwtIssuer,
                new List<Claim>()
                {
                    new Claim(JwtRegisteredClaimNames.GivenName, "Awsome"),
                    new Claim(JwtRegisteredClaimNames.Birthdate, "yesterday"),
                },
                expires: DateTime.Now.AddMinutes(120),
                signingCredentials: credentials);

            var stringBody = System.Text.Json.JsonSerializer.Serialize(new
            {
                Token = new JwtSecurityTokenHandler().WriteToken(token)
            });

            var response = new APIGatewayProxyResponse
            {
                StatusCode = (int)HttpStatusCode.OK,
                Body = stringBody,
                Headers = new Dictionary<string, string> { { "Content-Type", "application/json" } }
            };

            return response;
        }

        public static APIGatewayProxyResponse ValidateJsonWebToken(APIGatewayProxyRequest request, ILambdaContext context)
        {
            var jwtIssuer = Environment.GetEnvironmentVariable("jwtIssuer");
            var jwtKey = Environment.GetEnvironmentVariable("jwtKey");
            
            if (!request.Headers.TryGetValue("Authorization", out var authHeader))
            {
                return new APIGatewayProxyResponse
                {
                    StatusCode = (int)HttpStatusCode.BadRequest,
                };
            }

            var authHeaderParts = authHeader.Split("Bearer ");

            // The Authorization header was not well formed
            if (authHeaderParts.Length != 2)
            {
                return new APIGatewayProxyResponse
                {
                    StatusCode = (int)HttpStatusCode.BadRequest,
                };
            }

            var token = authHeaderParts[1].Trim();

            var validationParameters = new TokenValidationParameters()
            {
                 ValidateIssuer = true,
                 ValidateAudience = true,
                 ValidateIssuerSigningKey = true,
                 ValidateLifetime = true,
                 ValidIssuer = jwtIssuer,
                 ValidAudience = jwtIssuer,
                 IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey))
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            
            try
            {
                tokenHandler.ValidateToken(token, validationParameters, out var securityToken);

                var stringBody = System.Text.Json.JsonSerializer.Serialize(new
                {
                    ValidationResult = securityToken
                });

                var response = new APIGatewayProxyResponse
                {
                    StatusCode = (int)HttpStatusCode.OK,
                    Body = stringBody,
                    Headers = new Dictionary<string, string> { { "Content-Type", "application/json" } }
                };

                return response;
            }
            catch (Exception ex)
            {
                context.Logger.Log(ex.Message);

                return new APIGatewayProxyResponse
                {
                    StatusCode = (int)HttpStatusCode.Unauthorized,
                };
            }
        }
    }
}
