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
using System.Text.Json.Serialization;
using AuthenticationAsAService.Models;
using Amazon.DynamoDBv2;
using Amazon.DynamoDBv2.Model;
using Amazon.DynamoDBv2.DocumentModel;

// Assembly attribute to enable the Lambda function's JSON input to be converted into a .NET class.
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace LambdaAuthentication
{
    public static class Functions
    {
        public static async Task<APIGatewayProxyResponse> Login(APIGatewayProxyRequest request, ILambdaContext context)
        {
            var user = JsonSerializer.Deserialize<UserModel>(request.Body);

            QueryResponse response = await GetUserByName(user.UserName);

            if (response.Count == 0)
            {
                return new APIGatewayProxyResponse {  
                    StatusCode = (int)HttpStatusCode.NotFound,
                    Body = JsonSerializer.Serialize(new
                    {
                        Message = "User was not found"
                    })
                };
            }

            var jwtIssuer = Environment.GetEnvironmentVariable("jwtIssuer");
            var jwtKey = Environment.GetEnvironmentVariable("jwtKey");

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var expireDate = DateTime.Now.AddMinutes(120);

            var token = new JwtSecurityToken(
                issuer: jwtIssuer,
                audience: jwtIssuer,
                new List<Claim>()
                {
                    new Claim(JwtRegisteredClaimNames.GivenName, "Awsome"),
                    new Claim(JwtRegisteredClaimNames.Birthdate, "yesterday"),
                },
                expires: expireDate,
                signingCredentials: credentials);

            return new APIGatewayProxyResponse
            {
                StatusCode = (int)HttpStatusCode.OK,
                Body = JsonSerializer.Serialize(new
                {
                    Token = new JwtSecurityTokenHandler().WriteToken(token),
                    ExpireDate = expireDate
                }),
                Headers = new Dictionary<string, string> {
                    { "Content-Type", "application/json" }
                }
            };
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
                    Body = JsonSerializer.Serialize(new
                    {
                        Message = "Authorzation token not found"
                    }),
                    Headers = new Dictionary<string, string>
                    {
                        { "Content-Type", "application/json" }
                    }
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
                    Headers = new Dictionary<string, string> 
                    { 
                        { "Content-Type", "application/json" }
                    }
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

        public static async Task<APIGatewayProxyResponse> CreateUser(APIGatewayProxyRequest request, ILambdaContext context)
        {
            var user = JsonSerializer.Deserialize<UserModel>(request.Body);

            try
            {
                QueryResponse userQuery = await GetUserByName(user.UserName);

                if (userQuery.Count > 0)
                {
                    return new APIGatewayProxyResponse
                    {
                        StatusCode = (int)HttpStatusCode.InternalServerError,
                        Body = JsonSerializer.Serialize(new
                        {
                            Message = "User already exist"
                        }),
                        Headers = new Dictionary<string, string> {
                            { "Content-Type", "application/json" }
                        }
                    };
                }

                var client = new AmazonDynamoDBClient();

                context.Logger.Log("Creating user");

                var result = await client.PutItemAsync("Users", new Dictionary<string, AttributeValue>
                {
                    { nameof(UserModel.UserName), new AttributeValue { S = user.UserName } },
                    { nameof(UserModel.Age), new AttributeValue { N = user.Age.ToString() } },
                });

                return new APIGatewayProxyResponse
                {
                    StatusCode = (int)HttpStatusCode.OK,
                    Body = JsonSerializer.Serialize(result),
                    Headers = new Dictionary<string, string> {
                        { "Content-Type", "application/json" }
                    }
                };
            }
            catch (Exception ex)
            {
                context.Logger.Log(ex.Message);

                return new APIGatewayProxyResponse
                {
                    StatusCode = (int)HttpStatusCode.InternalServerError,
                };
            }
        }

        private static async Task<QueryResponse> GetUserByName(string username)
        {
            // Query params names
            const string userName = nameof(UserModel.UserName);

            var client = new AmazonDynamoDBClient();

            var query = new QueryRequest
            {
                TableName = "Users",
                KeyConditionExpression = $"{userName} = :{userName}",
                ExpressionAttributeValues = new Dictionary<string, AttributeValue> 
                    {
                        { $":{userName}", new AttributeValue { S = username } }
                    }
            };

            var response = await client.QueryAsync(query);

            return response;
        }
    }
}
