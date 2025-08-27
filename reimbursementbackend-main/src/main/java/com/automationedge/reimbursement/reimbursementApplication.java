package com.automationedge.reimbursement;

import com.automationedge.clients.ae.AutomationEdgeClient;
import com.automationedge.platform.web.builder.WebApplicationBuilder;
import com.ulisesbocchio.jasyptspringboot.annotation.EnableEncryptableProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.openfeign.EnableFeignClients;

@EnableEncryptableProperties
@EnableFeignClients(clients = {AutomationEdgeClient.class})
@SpringBootApplication
@Slf4j
public class reimbursementApplication {

  public static void main(String[] args) {
    new WebApplicationBuilder(reimbursementApplication.class).run(args);
  }
}
