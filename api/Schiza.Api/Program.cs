using Scalar.AspNetCore;

using Schiza.Api.Mocks;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();
builder.Services.AddControllers();
builder.Services.AddMockDetection();
builder.Services.AddCors(b =>
    {
        b.AddDefaultPolicy(p =>
        {
            p.AllowAnyHeader().AllowAnyMethod().WithOrigins("http://localhost:5173");
        });
    });

var app = builder.Build();

app.Services.SeedMockEvents();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference(options => options.WithOperationTitleSource(OperationTitleSource.Path)); // /scalar
}

app.UseHttpsRedirection();
app.UseCors();
app.MapControllers();

await app.RunAsync();
