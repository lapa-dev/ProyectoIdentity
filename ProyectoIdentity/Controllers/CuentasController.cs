using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using ProyectoIdentity.Models;
using ProyectoIdentity.Utils;
using System.Security.Claims;
using System.Text.Encodings.Web;

namespace ProyectoIdentity.Controllers
{
    [Authorize]
    public class CuentasController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _rolManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IEmailSender _emailSender;
        private readonly UrlEncoder _urlEncoder;

        public CuentasController(UserManager<IdentityUser> userManager, 
                                    SignInManager<IdentityUser> signInManager, 
                                    IEmailSender emailSender, 
                                    UrlEncoder urlEncoder,
                                    RoleManager<IdentityRole> rolManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _emailSender = emailSender;
            _urlEncoder = urlEncoder;
            _rolManager = rolManager;
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Index() => View();

        #region Registro especial solo para los administradores
        [HttpGet]
        public async Task<IActionResult> RegistroAdministrador(string returnurl = null)
        {
            ViewData["ReturnUrl"] = returnurl;
            RegistroViewModel registroVM = new RegistroViewModel()
            {
                ListaRoles = GetRoles()
            };
            return View(registroVM);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RegistroAdministrador(RegistroViewModel rgViewModel, string returnurl = null)
        {
            ViewData["ReturnUrl"] = returnurl;
            returnurl = returnurl ?? Url.Content("~/");

            if (ModelState.IsValid)
            {
                var usuario = new AppUsuario
                {
                    UserName = rgViewModel.Email,
                    Email = rgViewModel.Email,
                    Nombre = rgViewModel.Nombre,
                    Url = rgViewModel.Url,
                    Pais = rgViewModel.Pais,
                    CodigoPais = rgViewModel.CodigoPais,
                    Telefono = rgViewModel.Telefono,
                    Direccion = rgViewModel.Direccion,
                    FechaNacimiento = rgViewModel.FechaNacimiento,
                    PhoneNumber = rgViewModel.Telefono,
                    Ciudad = rgViewModel.Ciudad,
                    Estado = rgViewModel.Estado
                };

                var resultado = await _userManager.CreateAsync(usuario, rgViewModel.Password);

                if (resultado.Succeeded)
                {
                    //Para selección de l rol registro
                    if (!string.IsNullOrEmpty(rgViewModel.RolSeleccionado))
                        await _userManager.AddToRoleAsync(usuario, rgViewModel.RolSeleccionado);

                    //Confirmación de email en el registro
                    var code = await _userManager.GenerateEmailConfirmationTokenAsync(usuario);

                    var urlRetorno = Url.Action("ConfirmarEmail", "Cuentas", new { userId = usuario.Id, code = code }, protocol: HttpContext.Request.Scheme);
                    await _emailSender.SendEmailAsync(usuario.Email, "Confirmar su cuenta - ProyectoIdentity"
                                                                    , $"Por favor confirme su cuenta dando clic aquí: <a href=\"{urlRetorno}\"/>");

                    await _signInManager.SignInAsync(usuario, isPersistent: false);
                    return LocalRedirect(returnurl);
                }

                ValidarErrores(resultado);
            }

            rgViewModel.ListaRoles = GetRoles();

            return View(rgViewModel);
        }

        private List<SelectListItem> GetRoles()
        {
            List<SelectListItem> listaRoles = new List<SelectListItem>();
            listaRoles.Add(new SelectListItem()
            {
                Value = StringHandler.RolRegistrado,
                Text = StringHandler.RolRegistrado
            });

            listaRoles.Add(new SelectListItem()
            {
                Value = StringHandler.RolAdministrador,
                Text = StringHandler.RolAdministrador
            });

            return listaRoles;
        }
        #endregion

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> Registro(string returnurl = null)
        {
            //Para la creación de los roles
            if (!await _rolManager.RoleExistsAsync("Administrador"))
                await _rolManager.CreateAsync(new IdentityRole("Administrador"));

            if (!await _rolManager.RoleExistsAsync("Registrado"))
                await _rolManager.CreateAsync(new IdentityRole("Registrado"));

            ViewData["ReturnUrl"] = returnurl;
            RegistroViewModel registroVM = new RegistroViewModel();
            return View(registroVM);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [AllowAnonymous]
        public async Task<IActionResult> Registro(RegistroViewModel rgViewModel, string returnurl = null)
        {
            ViewData["ReturnUrl"] = returnurl;
            returnurl = returnurl ?? Url.Content("~/");

            if (ModelState.IsValid)
            {
                var usuario = new AppUsuario
                {
                    UserName = rgViewModel.Email,
                    Email = rgViewModel.Email,
                    Nombre = rgViewModel.Nombre,
                    Url = rgViewModel.Url,
                    Pais = rgViewModel.Pais,
                    CodigoPais = rgViewModel.CodigoPais,
                    Telefono = rgViewModel.Telefono,
                    Direccion = rgViewModel.Direccion,
                    FechaNacimiento = rgViewModel.FechaNacimiento,
                    PhoneNumber = rgViewModel.Telefono,
                    Ciudad = rgViewModel.Ciudad,
                    Estado = rgViewModel.Estado
                };

                var resultado = await _userManager.CreateAsync(usuario, rgViewModel.Password);

                if (resultado.Succeeded)
                {
                    //Asignación del usuario que se registra al rol
                    await _userManager.AddToRoleAsync(usuario, StringHandler.RolRegistrado);

                    //Confirmación de email en el registro
                    var code = await _userManager.GenerateEmailConfirmationTokenAsync(usuario);
                    
                    var urlRetorno = Url.Action("ConfirmarEmail", "Cuentas", new { userId = usuario.Id, code = code }, protocol: HttpContext.Request.Scheme);
                    await _emailSender.SendEmailAsync(usuario.Email, "Confirmar su cuenta - ProyectoIdentity"
                                                                    , $"Por favor confirme su cuenta dando clic aquí: <a href=\"{urlRetorno}\"/>");

                    await _signInManager.SignInAsync(usuario, isPersistent: false);
                    return LocalRedirect(returnurl);
                }

                ValidarErrores(resultado);
            }

            return View(rgViewModel);
        }

        [AllowAnonymous]
        private void ValidarErrores(IdentityResult resultado)
        {
            foreach (var error in resultado.Errors)
            {
                ModelState.AddModelError(String.Empty, error.Description);
            }
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Denegado(string returnurl = null)
        {
            ViewData["ReturnUrl"] = returnurl;
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [AllowAnonymous]
        public async Task<IActionResult> Acceso(AccesoViewModel accViewModel, string returnurl = null)
        {
            ViewData["ReturnUrl"] = returnurl;
            returnurl = returnurl ?? Url.Content("~/");

            if (ModelState.IsValid)
            {
                var resultado = await _signInManager.PasswordSignInAsync(accViewModel.Email, accViewModel.Password, accViewModel.RememberMe, lockoutOnFailure: true);

                if (resultado.Succeeded)
                    //return RedirectToAction("Index", "Home");
                    return LocalRedirect(returnurl);

                if (resultado.IsLockedOut)
                    return View("Bloqueado");

                //Para la validación de dos factores
                if (resultado.RequiresTwoFactor)
                    return RedirectToAction(nameof(VerificarCodigoAutenticador), new { returnurl, accViewModel.RememberMe });
                else
                    ModelState.AddModelError(String.Empty, "Acceso inválido");
            }

            return View(accViewModel);
        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> SalirAplicacion()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction(nameof(HomeController.Index), "Home");
        }


        #region Recuperar Contraseña
        [HttpGet]
        [AllowAnonymous]
        public ActionResult OlvidoPassword() => View();

        [HttpPost]
        [ValidateAntiForgeryToken]
        [AllowAnonymous]
        public async Task<IActionResult> OlvidoPassword(OlvidoPasswordViewModel opViewModel)
        {
            if (ModelState.IsValid)
            {
                var usuario = await _userManager.FindByEmailAsync(opViewModel.Email);

                if (usuario == null)
                    return RedirectToAction("ConfirmacionOlvidoPassword");

                var codigo = await _userManager.GeneratePasswordResetTokenAsync(usuario);

                var urlRetorno = Url.Action("ResetPassword", "Cuentas", new { userId = usuario.Id, code = codigo }, protocol: HttpContext.Request.Scheme);

                await _emailSender.SendEmailAsync(opViewModel.Email, "Recuperar Contraseña - ProyectoIdentity", $"Por favor recupere su contraseña dando clic aquí: <a href=\"{urlRetorno}\"/>");

                return RedirectToAction("ConfirmacionOlvidoPassword");
            }

            return View(opViewModel);
        }


        [HttpGet]
        [AllowAnonymous]
        public ActionResult ConfirmacionOlvidoPassword() => View();

        [HttpGet]
        [AllowAnonymous]
        public ActionResult ResetPassword(string code = null) => code == null ? View("Error") : View();

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(RecuperaPasswordViewModel rpdViewModel)
        {
            if (ModelState.IsValid)
            {
                var usuario = await _userManager.FindByEmailAsync(rpdViewModel.Email);

                if (usuario == null)
                    return RedirectToAction("ConfirmacionRecuperaPassword");

                var resultado = await _userManager.ResetPasswordAsync(usuario, rpdViewModel.Code, rpdViewModel.Password);

                if (resultado.Succeeded)
                    return RedirectToAction("ConfirmacionRecuperaPassword");

                ValidarErrores(resultado);
            }

            return View(rpdViewModel);
        }

        [HttpGet]
        [AllowAnonymous]
        public ActionResult ConfirmacionRecuperaPassword() => View();

        [HttpGet]
        [AllowAnonymous]
        public async Task<ActionResult> ConfirmarEmail(string userId, string code)
        {
            if (userId == null || code == null)
                return View("Error");

            var usuario = await _userManager.FindByIdAsync(userId);
            if (usuario == null)
                return View("Error");

            var resultado = await _userManager.ConfirmEmailAsync(usuario, code);

            return View(resultado.Succeeded ? "ConfirmarEmail" : "Error");
        }
        #endregion

        #region Confirmación aplicaiones externas
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> AccesoExterno(string proveedor, string returnurl = null)
        {
            var urlRredireccion = Url.Action("AccesoExternoCallback", "Cuentas", new { ReturnUrl = returnurl });
            var propiedades = _signInManager.ConfigureExternalAuthenticationProperties(proveedor, urlRredireccion);

            return Challenge(propiedades, proveedor);
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> AccesoExternoCallback(string returnurl = null, string error = null)
        {
            returnurl = returnurl ?? Url.Content("~/");
            if (error != null)
            {
                ModelState.AddModelError(string.Empty, $"Error en el acceso externo {error}");
                return View(nameof(Acceso));
            }

            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
                return RedirectToAction(nameof(Acceso));

            //Acceder con el usuario en el proveedor externo
            var resultado = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false);

            if (resultado.Succeeded)
            {
                //actualizar lo token de acceso
                await _signInManager.UpdateExternalAuthenticationTokensAsync(info);
                return LocalRedirect(returnurl);
            }

            //Para la validación de dos factores
            if (resultado.RequiresTwoFactor)
            {
                return RedirectToAction(nameof(VerificarCodigoAutenticador), new { returnurl = returnurl });
            }
            else
            {
                //si el usuario no tiene cuenta pregunta si guiere crear una
                ViewData["ReturnUrl"] = returnurl;
                ViewData["NombreAMostrarProveedor"] = info.ProviderDisplayName;
                var email = info.Principal.FindFirstValue(ClaimTypes.Email);
                var nombre = info.Principal.FindFirstValue(ClaimTypes.Name);

                return View("ConfirmacionAccesoExterno", new ConfirmacionAccesoExternoViewModel { Email = email, Name = nombre });
            }
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ConfirmacionAccesoExterno(ConfirmacionAccesoExternoViewModel caeViewModel, string returnurl = null)
        {
            returnurl = returnurl ?? Url.Content("~/");

            if (ModelState.IsValid)
            {
                var info = await _signInManager.GetExternalLoginInfoAsync();
                if (info == null)
                {
                    return View("Error");
                }

                var usuario = new AppUsuario { UserName = caeViewModel.Email, Email = caeViewModel.Email, Nombre = caeViewModel.Name };
                var resultado = await _userManager.CreateAsync(usuario);

                if (resultado.Succeeded)
                {
                    resultado = await _userManager.AddLoginAsync(usuario, info);

                    if (resultado.Succeeded)
                    {
                        await _signInManager.SignInAsync(usuario, isPersistent: false);
                        await _signInManager.UpdateExternalAuthenticationTokensAsync(info);
                        return LocalRedirect(returnurl);
                    }
                }
                ValidarErrores(resultado);
            }
            ViewData["ReturnUrl"] = returnurl;
            return View(caeViewModel);
        }
        #endregion

        #region Autenticación de dos factores
        [HttpGet]
        public async Task<IActionResult> ActivarAutenticador()
        {
            string formatoUrlAutenticador = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";

            var usuario = await _userManager.GetUserAsync(User);
            await _userManager.ResetAuthenticatorKeyAsync(usuario);
            var token = await _userManager.GetAuthenticatorKeyAsync(usuario);

            //Habilitar codigo QA
            string urlAutheticador = string.Format(formatoUrlAutenticador, _urlEncoder.Encode("ProyectoIdentity"), _urlEncoder.Encode(usuario.Email), token);

            var adfModel = new AutenticacionDosFactoresViewModel() { Token = token, UrlCodigoQR = urlAutheticador };

            return View(adfModel);
        }

        [HttpGet]
        public async Task<IActionResult> EliminarAutenticador()
        {
            var usuario = await _userManager.GetUserAsync(User);
            await _userManager.ResetAuthenticatorKeyAsync(usuario);
            await _userManager.SetTwoFactorEnabledAsync(usuario, false);

            return RedirectToAction(nameof(Index), "Home");
        }

        [HttpPost]
        public async Task<IActionResult> ActivarAutenticador(AutenticacionDosFactoresViewModel adfViewModel)
        {
            if (ModelState.IsValid)
            {
                var usuario = await _userManager.GetUserAsync(User);
                var suceeded = await _userManager.VerifyTwoFactorTokenAsync(usuario, _userManager.Options.Tokens.AuthenticatorTokenProvider, adfViewModel.Code);
                if (suceeded)
                {
                    await _userManager.SetTwoFactorEnabledAsync(usuario, true);
                }
                else
                {
                    ModelState.AddModelError("Error", $"Su autenticación de dos factores no ha sido validada");
                    return View(adfViewModel);
                }
            }
            return RedirectToAction(nameof(ConfirmacionAutenticador));
        }

        [HttpGet]
        public IActionResult ConfirmacionAutenticador() => View();

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> VerificarCodigoAutenticador(bool recordarDatos, string returnurl = null)
        {
            var usuario = await _signInManager.GetTwoFactorAuthenticationUserAsync();

            if (usuario == null)
            {
                return View("Error");
            }

            ViewData["ReturnUrl"] = returnurl;

            return View(new VerificarAutenticadorViewModel { ReturnUrl = returnurl, RecordarDatos = recordarDatos });
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> VerificarCodigoAutenticador(VerificarAutenticadorViewModel vaViewModel)
        {
            vaViewModel.ReturnUrl = vaViewModel.ReturnUrl ?? Url.Content("~/");

            if (!ModelState.IsValid)
                return View(vaViewModel);

            var resultado = await _signInManager.TwoFactorAuthenticatorSignInAsync(vaViewModel.Code, vaViewModel.RecordarDatos, rememberClient: true);
            if (resultado.Succeeded)
                return LocalRedirect(vaViewModel.ReturnUrl);

            if (resultado.IsLockedOut)
                return View("Bloqueado");
            else
            {
                ModelState.AddModelError(String.Empty, "Còdigo Inválido");
                return View(vaViewModel);
            }
        }
        #endregion

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Acceso(string returnurl = null)
        {
            ViewData["ReturnUrl"] = returnurl;
            returnurl = returnurl ?? Url.Content("~/");
            return View();
        }
    }
}
