package com.automationedge.reimbursement.controller;

import com.automationedge.reimbursement.dto.ExecuteWorkflowRequestBody;
import com.automationedge.clients.ae.AutomationEdgeClient;
import com.automationedge.clients.ae.dto.ExecuteWorkflowRequest;
import com.automationedge.clients.ae.dto.ExecuteWorkflowResponse;
import com.automationedge.clients.ae.dto.Workflow.Parameter;
import java.util.ArrayList;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.util.CollectionUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@Controller
@EnableConfigurationProperties(WorkflowConfigurationProperties.class)
@Slf4j
public class WorkflowController {

    @Value("${ae.orgCode}")
    private String orgCode;

    private final WorkflowConfigurationProperties workflowConfigurationProperties;
    @Autowired
    private AutomationEdgeClient aeClient;

    @Autowired
    public WorkflowController(WorkflowConfigurationProperties workflowConfigurationProperties, AutomationEdgeClient aeClient) {
        this.workflowConfigurationProperties = workflowConfigurationProperties;
        this.aeClient = aeClient;
    }

    @PostMapping(value = "/v1/workflow/execute", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ExecuteWorkflowResponse> executeWorkflow(@RequestBody ExecuteWorkflowRequestBody request) {
        String mappedWorkflowName = getMappedWorkflowName(request.getWorkflowName());
        if (mappedWorkflowName == null) {
            log.error("Workflow name '{}' not found in configuration", request.getWorkflowName());
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(null);
        }
        ExecuteWorkflowRequest executeWorkflowRequest = new ExecuteWorkflowRequest();
        executeWorkflowRequest.setWorkflowName(mappedWorkflowName);

        List<Parameter> params = new ArrayList<>();
        if (!CollectionUtils.isEmpty(request.getParams())) {
            for (ExecuteWorkflowRequestBody.ReportParameter p : request.getParams()) {
                Parameter wp = new Parameter();
                wp.setName(p.getName());
                wp.setValue(p.getValue().toString());
                params.add(wp);
            }
        }
        executeWorkflowRequest.setParams(params);
        executeWorkflowRequest.setOrgCode(orgCode);
        try {
            ExecuteWorkflowResponse executeWorkflowResponse = aeClient.executeWorkflow(executeWorkflowRequest);
            return ResponseEntity.ok(executeWorkflowResponse);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
    private String getMappedWorkflowName(String workflowName) {
        WorkflowConfigurationProperties.WorkflowConfiguration config = workflowConfigurationProperties.getConfig().get(workflowName);
        return (config != null) ? config.getWorkflowName() : null;
    }

}
