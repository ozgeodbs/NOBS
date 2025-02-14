using System.ComponentModel.DataAnnotations;

namespace NOBS.Models
{
    public class UserModel
    {
        public int Id { get; set; }

        [Required]
        [Display(Name = "Phone Number")]
        public string PhoneNumber { get; set; }

        [Required]
        [EmailAddress]
        [Display(Name = "E-Mail")]
        public string Email { get; set; }

        [Required]
        public bool IsAgreed { get; set; }

        public bool IsMarketingAgreed { get; set; }

        [Required]
        public string HashedPassword { get; set; } // Şifrelenmiş Parola

        public string RefreshToken { get; set; } // Yeni eklendi
        public DateTime RefreshTokenExpiryTime { get; set; } // Yeni eklendi
    }
}
