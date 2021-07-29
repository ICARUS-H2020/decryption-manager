package aero.icarus2020.decryptionmanager.controller;

import aero.icarus2020.decryptionmanager.service.DecryptionService;
import com.google.gson.JsonObject;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

@RestController
@RequestMapping("/api/v1/decryption")
@RequiredArgsConstructor
@Log4j2
public class DecryptionController {

  private final DecryptionService decryptionService;

  @GetMapping(value = "/mongo-id/{mid}", produces = MediaType.APPLICATION_JSON_VALUE)
  public ResponseEntity<String> getKey(@PathVariable("mid") Long mid, HttpServletRequest request) {
    log.info("Received request to decrypt dataset {}.", mid);
    return ResponseEntity.status(HttpStatus.OK).body(getResponse(decryptionService.decryptData(mid, request)));
  }

  @GetMapping(value = "/mongo-id/{mid}/cols", produces = MediaType.APPLICATION_JSON_VALUE)
  public ResponseEntity<String> getKey(@PathVariable("mid") Long mid, @RequestParam("columns") List<String> columns, HttpServletRequest request) {
    log.info("Received request to decrypt contract dataset {}.", mid);
    return ResponseEntity.status(HttpStatus.OK).body(getResponse(decryptionService.decryptContractData(mid, columns, request)));
  }

  @GetMapping(value = "/mongo-id/open/{mid}", produces = MediaType.APPLICATION_JSON_VALUE)
  public ResponseEntity<String> getKeyOpen(@PathVariable("mid") Long mid, HttpServletRequest request) {
    log.info("Received request to decrypt open dataset {}.", mid);
    return ResponseEntity.status(HttpStatus.OK).body(getResponse(decryptionService.decryptOpenData(mid, request,null)));
  }

  private String getResponse(String filePath) {
    JsonObject jsonObject = new JsonObject();
    jsonObject.addProperty("decryptedFilePath", filePath);

    return jsonObject.toString();
  }
}
