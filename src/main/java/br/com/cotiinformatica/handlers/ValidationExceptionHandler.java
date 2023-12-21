package br.com.cotiinformatica.handlers;

import java.util.ArrayList;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import br.com.cotiinformatica.dtos.ErrorResponseDto;

/*
 * Classe para tratamento e retorno dos erros de validação da API
 * gerados pela biblioteca do BeanValidation (jakarta.validation)
 */
@ControllerAdvice
public class ValidationExceptionHandler extends ResponseEntityExceptionHandler {

	@Override
	protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex,
			HttpHeaders headers, HttpStatusCode status, WebRequest request) {

		// Criando o dto que irá retornar a resposta de erros
		ErrorResponseDto dto = new ErrorResponseDto();
		dto.setStatus(HttpStatus.BAD_REQUEST);
		dto.setErrors(new ArrayList<String>());

		// pegando os erros gerados pelo BeanValidation
		// e armazena-los no objeto da classe DTO
		for (FieldError error : ex.getBindingResult().getFieldErrors()) {
			dto.getErrors().add(error.getField() + ": " + error.getDefaultMessage());
		}

		for (ObjectError error : ex.getBindingResult().getGlobalErrors()) {
			dto.getErrors().add(error.getObjectName() + ": " + error.getDefaultMessage());
		}

		// retornando o conteudo dos erros
		return handleExceptionInternal(ex, dto, headers, dto.getStatus(), request);
	}
}
