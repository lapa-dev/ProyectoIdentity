using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace ProyectoIdentity.Controllers
{
    public class AutorizacionController : Controller
    {
        //Acceso libre/publico para el usuario
        [AllowAnonymous]
        public IActionResult AccesoPublico()
        {
            return View();
        }


        //Solo debe estar autenticado
        [Authorize]
        public IActionResult AccesoAutenticado()
        {
            return View();
        }

        //Acceso autenticado y que pertenezca al rol "USUARIO"
        //[Authorize(Roles = "Usuario")]
        [Authorize(Policy = "Usuario")]
        public IActionResult AccesoUsuario()
        {
            return View();
        }

        //Acceso autenticado y que pertenezca al rol "REGISTRADO"
        //[Authorize(Roles = "Registrado")]
        [Authorize(Policy = "Registrado")]
        public IActionResult AccesoRegistrado()
        {
            return View();
        }

        //Acceso autenticado y que pertenezca al rol "ADMINISTRADOR"
        //Opción 1 con roles
        //[Authorize(Roles = "Administrador")]
        //Opción 2 Policy o directivas
        [Authorize(Policy = "Administrador")]
        public IActionResult AccesoAdministrador()
        {
            return View();
        }

        //Acceso autenticado y que pertenezca al rol "USUARIO" Ó "ADMINISTRADOR
        [Authorize(Roles = "Usuario, Administrador")]
        public IActionResult AccesoUsuarioAdministrador()
        {
            return View();
        }

        //Acceso autenticado y que pertenezca al rol "USUARIO" Y "ADMINISTRADOR
        [Authorize(Policy = "UsuarioYAdministrador")]
        public IActionResult AccesoUsuarioYAdministrador()
        {
            return View();
        }

        //Acceso autenticado, rol administrador y permiso crear
        [Authorize(Policy = "AdministradorCrear")]
        public IActionResult AccesoAdministradorPermisoCrear()
        {
            return View();
        }

        //Acceso autenticado, rol administrador y permiso editar y borrar
        [Authorize(Policy = "AdministradorEditarBorrar")]
        public IActionResult AccesoAdministradorPermisoEditarBorrar()
        {
            return View();
        }

        //Acceso para usuario administrador que tenga los tres permisos: crear, editar y borrar
        [Authorize(Policy = "AdministradorCrearEditarBorrar")]
        public IActionResult AccesoAdministradorPermisoCrearEditarBorrar()
        {
            return View();
        }

    }
}
