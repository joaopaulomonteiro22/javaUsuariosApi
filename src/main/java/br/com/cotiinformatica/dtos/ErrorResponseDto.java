package br.com.cotiinformatica.dtos;

import java.util.List;

import org.springframework.http.HttpStatus;

import lombok.Data;

@Data
public class ErrorResponseDto {

	/*
	 * Código do erro que será
	 * retornado pela API
	 */
	private HttpStatus status;
	
	/*
	 * Lista contendo as mensagens
	 * de erro retornadas pela API
	 */
	private List<String> errors;
}
