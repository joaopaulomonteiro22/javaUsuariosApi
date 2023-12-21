package br.com.cotiinformatica.components;
import java.util.Calendar;
import java.util.Date;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import br.com.cotiinformatica.entities.Usuario;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
@Component
public class JwtTokenComponent {
	/*
	 * Carregando o valor da configuração mapeada
	 * no arquivo /application.properties
	 */
	@Value("${jwt.secret}")
	String jwtSecret;
	
	/*
	 * Carregando o valor da configuração mapeada
	 * no arquivo /application.properties
	 */
	@Value("${jwt.expirationInMinutes}")
	String jwtExpirationInMinutes;
	
	/*
	 * Método para gerar o token JWT
	 */
	public String generateToken(Usuario usuario) {
		return Jwts.builder()
               .setSubject(usuario.getEmail()) // identificação do usuário
               .setIssuedAt(new Date()) // data de geração
               .setExpiration(getExpirationDate()) // data de expiração
               .signWith(SignatureAlgorithm.HS256, jwtSecret) // chave secreta
               .compact();
	}
	
	/*
	 * Método para gerar a data de expiração do token
	 */
	public Date getExpirationDate() {
       Integer minutos = Integer.parseInt(jwtExpirationInMinutes);
       // Obtenha a data atual
       Calendar calendar = Calendar.getInstance();
       // Adicione os minutos à data atual
       calendar.add(Calendar.MINUTE, minutos);
       Date expirationDate = calendar.getTime();
       return expirationDate;
   }
}




