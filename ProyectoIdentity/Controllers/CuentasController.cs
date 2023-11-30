using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using ProyectoIdentity.Models;

namespace ProyectoIdentity.Controllers
{
    public class CuentasController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IEmailSender _emailSender;

        public CuentasController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, IEmailSender emailSender)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _emailSender = emailSender;
        }

        public IActionResult Index()
        {
            return View();
        }

        [HttpGet]
        public async Task<IActionResult> Registro(string returnurl = null)
        {
            ViewData["ReturnUrl"] = returnurl;
            RegistroViewModel registroVM = new RegistroViewModel();
            return View(registroVM);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
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

        private void ValidarErrores(IdentityResult resultado)
        {
            foreach (var error in resultado.Errors)
            {
                ModelState.AddModelError(String.Empty, error.Description);
            }
        }

        [HttpGet]
        public IActionResult Acceso(string returnurl = null)
        {
            ViewData["ReturnUrl"] = returnurl;
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
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

        [HttpGet]
        public ActionResult OlvidoPassword()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
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
        public ActionResult ConfirmacionOlvidoPassword()
        {
            return View();
        }

        //Recuperar Contraseña
        [HttpGet]
        [AllowAnonymous]
        public ActionResult ResetPassword(string code=null)
        {
            return code == null ? View("Error") : View();
        }

        [HttpPost]
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
        public ActionResult ConfirmacionRecuperaPassword()
        {
            return View();
        }

        [HttpGet]
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
    }
}
