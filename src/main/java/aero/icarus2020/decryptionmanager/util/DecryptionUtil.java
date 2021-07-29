package aero.icarus2020.decryptionmanager.util;

import aero.icarus2020.decryptionmanager.controller.dto.ObjectDto;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
@Log4j2
public class DecryptionUtil {

  @Value("${icarus.keypair.url}")
  private String keypairUrl;

  @Value("${icarus.keypair.username}")
  private String keypairUsername;

  @Value("${icarus.keypair.password}")
  private String keypairPassword;

  public ResponseEntity<String> login() {
    ResponseEntity<String> response = null;

    try {
      ObjectDto objectDto = new ObjectDto(this.keypairUsername, this.keypairPassword);
      HttpEntity requestEntity = new HttpEntity(objectDto, null);
      RestTemplate restTemplate = new RestTemplate();
      response = restTemplate.exchange(keypairUrl + "/api/v1/login", HttpMethod.POST, requestEntity, String.class);
    } catch (Exception e) {
      log.error(e);
    }

    return response;
  }

  public ResponseEntity<String> getKey(Long did, Long uid, ResponseEntity responseEntity) {
    ResponseEntity<String> response = null;

    try {
      RestTemplate restTemplate = new RestTemplate();
      HttpHeaders headers = new HttpHeaders();
      headers.add(HttpHeaders.AUTHORIZATION, String.valueOf(responseEntity.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0)));
      HttpEntity<String> entity = new HttpEntity<>(null, headers);
      response = restTemplate.exchange(keypairUrl + "/api/v1/get-key/dataasset/" + did + "/user/" + uid,
          HttpMethod.GET, entity, String.class);
    } catch (Exception e) {
      log.error(e);
    }

    return response;
  }

  public ResponseEntity<String> getKeyForSecureSpace(Long mid, ResponseEntity responseEntity) {
    ResponseEntity<String> response = null;

    try {
      RestTemplate restTemplate = new RestTemplate();
      HttpHeaders headers = new HttpHeaders();
      headers.add(HttpHeaders.AUTHORIZATION, String.valueOf(responseEntity.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0)));
      HttpEntity<String> entity = new HttpEntity<>(null, headers);
      response = restTemplate.exchange(keypairUrl + "/api/v1/get-key/secure-space/" + mid, HttpMethod.GET, entity, String.class);
    } catch (Exception e) {
      log.error(e);
    }
    return response;
  }
}
