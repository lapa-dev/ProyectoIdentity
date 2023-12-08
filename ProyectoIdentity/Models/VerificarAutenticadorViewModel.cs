﻿using System.ComponentModel.DataAnnotations;

namespace ProyectoIdentity.Models
{
    public class VerificarAutenticadorViewModel
    {
        [Required]
        [Display(Name = "Código de autenticador")]
        public string Code { get; set; }

        public string ReturnUrl { get; set; }

        [Display(Name = "¿Recordar datos?")]
        public bool RecordarDatos { get; set; }
    }
}
