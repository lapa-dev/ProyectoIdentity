using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using ProyectoIdentity.Datos;
using ProyectoIdentity.Models;

namespace ProyectoIdentity.Controllers
{
    [Authorize]
    public class UsuariosController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _rolManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly ApplicationDbContext _context;

        public UsuariosController(UserManager<IdentityUser> userManager,
                                    SignInManager<IdentityUser> signInManager,
                                    RoleManager<IdentityRole> rolManager,
                                    ApplicationDbContext context)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _rolManager = rolManager;
            _context = context;
        }

        public IActionResult Index()
        {
            return View();
        }

        #region Editar Perfil
        [HttpGet]
        public IActionResult EditarPerfil(string id)
        {
            if (string.IsNullOrEmpty(id))
                return NotFound();

            var usuarioDB = _context.AppUsuarios.Find(id);

            if (usuarioDB == null)
                return NotFound();

            return View(usuarioDB);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EditarPerfil(AppUsuario appUsuario)
        {
            if (ModelState.IsValid)
            {
                var usuario = await _context.AppUsuarios.FindAsync(appUsuario.Id);
                usuario.Nombre = appUsuario.Nombre;
                usuario.Url = appUsuario.Url;
                usuario.CodigoPais = appUsuario.CodigoPais;
                usuario.Telefono = appUsuario.Telefono;
                usuario.Ciudad = appUsuario.Ciudad;
                usuario.Pais = appUsuario.Pais;
                usuario.Direccion = appUsuario.Direccion;
                usuario.FechaNacimiento = appUsuario.FechaNacimiento;

                await _userManager.UpdateAsync(usuario);

                return RedirectToAction(nameof(Index), "Home");
            }

            return View(appUsuario);
        }
        #endregion

        #region Cambiar Contraseña
        [HttpGet]
        public IActionResult CambiarPassword()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> CambiarPassword(CambiarPasswordViewModel cpViewModel, string email)
        {
            if (ModelState.IsValid)
            {
                var usuario = await _userManager.FindByEmailAsync(email);
                if (usuario== null)
                    return RedirectToAction("Error");

                var token = await _userManager.GeneratePasswordResetTokenAsync(usuario);

                var resultado = await _userManager.ResetPasswordAsync(usuario, token, cpViewModel.Password);

                if (resultado.Succeeded)
                    return RedirectToAction("ConfirmacionCambioPassword");
                else
                    return View(cpViewModel);
            }

            return View(cpViewModel);
        }

        [HttpGet]
        public IActionResult ConfirmacionCambioPassword()
        {
            return View();
        }
        #endregion
    }
}
