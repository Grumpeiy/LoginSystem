using System.ComponentModel.DataAnnotations;

public class LoginViewModel
{
    [Required]
    [EmailAddress]
    public string email { get; set; }

    [Required]
    [DataType(DataType.Password)]
    public string password { get; set; }
}
