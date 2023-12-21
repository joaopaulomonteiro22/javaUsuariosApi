package br.com.cotiinformatica.dtos;

import java.util.Date;
import java.util.UUID;

import lombok.Data;

@Data
public class AutenticarUsuarioResponseDto {

	private UUID idUsuario;
	private String nome;
	private String email;
	private Date dataHoraAcesso;
	private String token;
	private Date dataHoraExpiracao;
}
