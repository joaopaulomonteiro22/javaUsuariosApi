package br.com.cotiinformatica.controllers;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


import br.com.cotiinformatica.dtos.AutenticarUsuarioRequestDto;
import br.com.cotiinformatica.dtos.AutenticarUsuarioResponseDto;
import br.com.cotiinformatica.dtos.CriarUsuarioRequestDto;
import br.com.cotiinformatica.dtos.CriarUsuarioResponseDto;
import br.com.cotiinformatica.services.UsuarioService;
import jakarta.validation.Valid;


@RestController
@RequestMapping("/api/usuarios")
public class UsuariosController {


	@Autowired //autoinicialização
	UsuarioService usuarioService;
	
	/*
	 * ENDPOINT: POST /api/usuarios/criar
	 */
	@PostMapping("criar")
	public CriarUsuarioResponseDto criar(@RequestBody @Valid CriarUsuarioRequestDto request) {
		return usuarioService.criarUsuario(request);
	}


	/*
	 * ENDPOINT: POST /api/usuarios/autenticar
	 */
	@PostMapping("autenticar")
	public AutenticarUsuarioResponseDto autenticar(@RequestBody @Valid AutenticarUsuarioRequestDto request) {
		return usuarioService.autenticarUsuario(request);
	}
}


