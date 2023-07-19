using JupiterSecurity.Data.Context;
using Microsoft.Extensions.Configuration;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);
builder.Configuration.AddJsonFile("appsettings.json", optional: false, reloadOnChange: true);

builder.Services.AddControllers();
builder.Services.AddAuthentication("default").AddJwtBearer("default",options =>
{
    var secretKey = builder.Configuration.GetValue<string>("SecretKey");
    var secretKeyBytes = Encoding.ASCII.GetBytes(secretKey);
    var key = new SymmetricSecurityKey(secretKeyBytes);
    options.TokenValidationParameters = new TokenValidationParameters
    {
        IssuerSigningKey=key,
        ValidateIssuer = false,
        ValidateAudience = false,
    };
});

builder.Services.AddAuthorization(options => {
    options.AddPolicy("Manager",
    policy => policy.RequireClaim(ClaimTypes.Role, "Manager").RequireClaim("Department", "Management"));

});

builder.Services.AddDbContext<EmployeesContext>(options => options.UseSqlServer(builder.Configuration.GetConnectionString("authEmps")));

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "My API", Version = "v1" });
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "My API V1");
    });
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();