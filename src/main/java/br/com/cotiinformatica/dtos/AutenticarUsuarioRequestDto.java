package br.com.cotiinformatica.dtos;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class AutenticarUsuarioRequestDto {

	@Email(message = "Informe um endereço de email válido.")
	@NotBlank(message = "O preenchimento do email é obrigatório.")
	private String email;

	@Size(min = 8, max = 20, message = "Informe a senha com 8 a 20 caracteres.")
	@NotBlank(message = "O preenchimento da senha é obrigatório.")
	private String senha;

}