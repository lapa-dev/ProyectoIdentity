using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using ProyectoIdentity.Datos;
using ProyectoIdentity.Servicios;

var builder = WebApplication.CreateBuilder(args);

//Conexión a sql server
builder.Services.AddDbContext<ApplicationDbContext>(opciones => 
    opciones.UseSqlServer(builder.Configuration.GetConnectionString("ConexionSql"))
);

//Agregar el servicio identity a la palicación
builder.Services.AddIdentity<IdentityUser, IdentityRole>().AddEntityFrameworkStores<ApplicationDbContext>().AddDefaultTokenProviders();

//Url de retorno al acceder
builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = new PathString("/Cuentas/Acceso");
    options.AccessDeniedPath = new PathString("/Cuentas/Denegado");
});

//Configuracion del identity
builder.Services.Configure<IdentityOptions>(options => {
    options.Password.RequiredLength = 5;
    options.Password.RequireLowercase = true;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(1);
    options.Lockout.MaxFailedAccessAttempts = 3;
});

//Autenticación de facebbok
builder.Services.AddAuthentication().AddFacebook(opcions => {
    opcions.AppId = "326988356792292";
    opcions.AppSecret = "f21b18895ee3c8d6f00f7ac7465e2d63";
});

//Autenticación de google
builder.Services.AddAuthentication().AddGoogle(opcions => {
    opcions.ClientId = "151196415320-nn6a84d4p12dt7k49nupisr0n2v6rtct.apps.googleusercontent.com";
    opcions.ClientSecret = "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";
});

//Soporte para autorizaci�n basada en directivas/Policy
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("Administrador", policy => policy.RequireRole("Administrador"));
    options.AddPolicy("Registrado", policy => policy.RequireRole("Registrado"));
    options.AddPolicy("Usuario", policy => policy.RequireRole("Usuario"));
    options.AddPolicy("UsuarioYAdministrador", policy => policy.RequireRole("Administrador").RequireRole("Usuario"));

    //Uso de claims
    options.AddPolicy("AdministradorCrear", policy => policy.RequireRole("Administrador").RequireClaim("Crear", "True"));
    options.AddPolicy("AdministradorEditarBorrar", policy => policy.RequireRole("Administrador").RequireClaim("Editar", "True").RequireClaim("Borrar", "True"));
    options.AddPolicy("AdministradorCrearEditarBorrar", policy => policy.RequireRole("Administrador").RequireClaim("Crear", "True")
    .RequireClaim("Editar", "True").RequireClaim("Borrar", "True"));
});

//IEmailSender
builder.Services.AddTransient<IEmailSender, MailJetEmailSender>();

// Add services to the container.
builder.Services.AddControllersWithViews();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

//Se agrega ka autenticación
app.UseAuthentication();

app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
