package br.com.cotiinformatica.dtos;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class CriarUsuarioRequestDto {

	@Size(min = 8, max = 100, message = "Informe o nome com 8 a 100 caracteres.")
	@NotBlank(message = "O preenchimento do nome é obrigatório.")
	private String nome;

	@Email(message = "Informe um endereço de email válido.")
	@NotBlank(message = "O preenchimento do email é obrigatório.")
	private String email;

	@Pattern(regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$", 
			message = "Informe a senha com letras maiúsculas, minúsculas, números, símbolos e de 8 a 20 caracteres.")
	@NotBlank(message = "O preenchimento da senha é obrigatório.")
	private String senha;
}
