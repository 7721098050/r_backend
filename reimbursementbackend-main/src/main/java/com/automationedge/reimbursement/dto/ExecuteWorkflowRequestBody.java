package com.automationedge.reimbursement.dto;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

@Data
public class ExecuteWorkflowRequestBody {
    private String workflowName;
    private List<ReportParameter> params;

    @Data
    @JsonIgnoreProperties(ignoreUnknown = true)
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class ReportParameter {

        private String name;
        private Object value;
    }

}