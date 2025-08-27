package com.automationedge.reimbursement.controller;

import java.util.Map;
import lombok.Data;
import lombok.Getter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Data
@ConfigurationProperties(prefix = "rpa.workflows")
public class WorkflowConfigurationProperties {

    private Map<String, WorkflowConfiguration> config;

    public void setConfig(Map<String, WorkflowConfiguration> config) {
        this.config = config;
    }

    @Getter
    public static class WorkflowConfiguration {
        private String workflowName;
        //Workflow name configuration for UI Actions
        public void setWorkflowName(String workflowName) {
            this.workflowName = workflowName;
        }
    }
}
