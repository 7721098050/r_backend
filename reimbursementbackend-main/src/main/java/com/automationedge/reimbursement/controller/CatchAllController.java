package com.automationedge.reimbursement.controller;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@Slf4j
public class CatchAllController {

  @RequestMapping(value = "/{name:^(?!index.html).+}")
  public String catchAllRoutes(HttpServletRequest inRequest) {
    return "forward:/index.html";
  }


}
