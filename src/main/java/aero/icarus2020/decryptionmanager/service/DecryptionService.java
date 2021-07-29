package aero.icarus2020.decryptionmanager.service;

import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

@Service
public interface DecryptionService {

  String decryptData(Long mid, HttpServletRequest httpServletRequest);

  String decryptContractData(Long mid, List<String> columns, HttpServletRequest httpServletRequest);

  String decryptOpenData(Long mid, HttpServletRequest httpServletRequest,List<String> columns);
}
