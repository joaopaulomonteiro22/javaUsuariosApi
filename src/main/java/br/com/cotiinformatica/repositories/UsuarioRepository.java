package br.com.cotiinformatica.repositories;

import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import br.com.cotiinformatica.entities.Usuario;

public interface UsuarioRepository extends JpaRepository<Usuario, UUID> {

	/*
	 * Consulta em linguagem JPQL para buscar 1 usuário através do email
	 */
	@Query("select u from Usuario u where u.email = :param1")
	Usuario find(@Param("param1") String email);
	
	/*
	 * Consulta em linguagem JPQL para buscar 1 usuário através do email e da senha
	 */
	@Query("select u from Usuario u where u.email = :param1 and u.senha = :param2")
	Usuario find(@Param("param1") String email, @Param("param2") String senha);
}
