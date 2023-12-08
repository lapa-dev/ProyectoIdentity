using System.ComponentModel.DataAnnotations;

namespace ProyectoIdentity.Models
{
    public class AutenticacionDosFactoresViewModel
    {
        //Para el acceso (login)
        [Required]
        [Display(Name="Código de autenticador")]
        public string Code { get; set; }

        //Para el registro
        public string Token { get; set; }

        //Para código QR
        public string UrlCodigoQR { get; set; }
    }
}
