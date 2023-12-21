package br.com.cotiinformatica;
import static org.assertj.core.api.Assertions.fail;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.javafaker.Faker;
import br.com.cotiinformatica.dtos.AutenticarUsuarioRequestDto;
import br.com.cotiinformatica.dtos.CriarUsuarioRequestDto;
@SpringBootTest
@AutoConfigureMockMvc //executar os testes na API
@TestMethodOrder(MethodOrderer.OrderAnnotation.class) //ordem dos testes
class JavaUsuariosApiApplicationTests {
	
	@Autowired
	MockMvc mockMvc; //realizar as chamadas para a API
	@Autowired
	ObjectMapper objectMapper; //envio dos dados para a API
	
	//atributos
	private static String email;
	private static String senha;
	
	@Test
	@Order(1)
	public void criarUsuarioTest() throws Exception {
		
		Faker faker = new Faker();
		
		CriarUsuarioRequestDto dto = new CriarUsuarioRequestDto();
		dto.setNome(faker.name().fullName());
		dto.setEmail(faker.internet().emailAddress());
		dto.setSenha("@Teste123");
		
		//executando a chamada para a API
		mockMvc.perform(post("/api/usuarios/criar")
				.contentType("application/json")
				.content(objectMapper.writeValueAsString(dto)))
				.andExpect(status().isOk());
		
		email = dto.getEmail();
		senha = dto.getSenha();
	}
	@Test
	@Order(2)
	public void autenticarUsuarioTest() throws Exception{
		
		AutenticarUsuarioRequestDto dto = new AutenticarUsuarioRequestDto();
		dto.setEmail(email);
		dto.setSenha(senha);
		
		mockMvc.perform(post("/api/usuarios/autenticar")
				.contentType("application/json")
				.content(objectMapper.writeValueAsString(dto)))
				.andExpect(status().isOk());
	}
}



