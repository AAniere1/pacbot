package com.tmobile.cloud.azurerules.vm;


import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.tmobile.cloud.awsrules.utils.PacmanUtils;
import com.tmobile.cloud.azurerules.dto.NicPublicData;
import com.tmobile.cloud.azurerules.utils.CommonUtils;
import com.tmobile.cloud.azurerules.utils.VirtualMachineUtil;
import com.tmobile.cloud.constants.PacmanRuleConstants;
import com.tmobile.pacman.commons.PacmanSdkConstants;
import com.tmobile.pacman.commons.exception.InvalidInputException;
import com.tmobile.pacman.commons.exception.RuleExecutionFailedExeption;
import com.tmobile.pacman.commons.rule.Annotation;
import com.tmobile.pacman.commons.rule.BaseRule;
import com.tmobile.pacman.commons.rule.PacmanRule;
import com.tmobile.pacman.commons.rule.RuleResult;



/**
 * Azure rule for checking if a virtual machine is open to internet
 */

@PacmanRule(key = "check-for-virtualmachine-public-access", desc = "This is azure rule for checking if the virtual machine is open to internet or not", severity = PacmanSdkConstants.SEV_HIGH, category = PacmanSdkConstants.SECURITY)
public class VirtualMachineWithPublicAccess extends BaseRule {
	
	private static final Logger logger = LoggerFactory.getLogger(VirtualMachineWithPublicAccess.class);
	private static final String VIOLATION_REASON = "VirtualMachine with public accessible ports found";
	private static final String DB_KEY_PUBLIC_PORT = "publicPort";
	private static final String DB_KEY_PUBLICIP = "publicIP";
	private static final String ISSUE_DETAILS_KEY_PUBLIC_PORT = "Public Port- %s";
	private static final String ISSUE_DETAILS_KEY_PUBLIC_IP = "VM Public IP";
	private static final String DB_KEY_NIC = "publicNic";
	private static final String ISSUE_DETAILS_KEY_NIC = "Public Nic";
	
	/**
	 * The method will get triggered from Rule Engine with following parameters
	 * 
	 * @param ruleParam **********Following are the Rule Parameters********* <br><br>
	 * 
	 * ruleKey : check-for-virtualmachine-public-access <br><br>
	 * 
	 * esNsgRule : Enter the VM with NSG URL <br><br>
	 * 
	 * esVirtualMachineRule : Enter the VM ES URL <br><br>
	 * 
	 * publicSourcePortRanges : Enter the value as * <br><br>
	 * 
	 * @param resourceAttributes this is a resource in context which needs to be scanned thisis provided by execution engine
	 *
	 */
	@SuppressWarnings("unchecked")
	@Override
	public RuleResult execute(Map<String, String> ruleParam, Map<String, String> resourceAttributes) {
		logger.debug("========VirtualMachineWithPublicAccess started=========");

		LinkedHashMap<String, Object> issue = new LinkedHashMap<>();

		MDC.put("executionId", ruleParam.get("executionId"));
		MDC.put("ruleId", ruleParam.get(PacmanSdkConstants.RULE_ID));

		String status = resourceAttributes.get(PacmanRuleConstants.STATUS);
		String resourceId = resourceAttributes.get(PacmanRuleConstants.RESOURCE_ID);
		String pacmanHost = PacmanUtils.getPacmanHost(PacmanRuleConstants.ES_URI);
		String esNsgRuleUrl = ruleParam.get(PacmanRuleConstants.ES_NSG_URL);
		String esVirtualMachineRuleURl = ruleParam.get(PacmanRuleConstants.ES_VIRTUALMACHINE_URL);
		String region = resourceAttributes.get(PacmanRuleConstants.REGION);
		String subscription = resourceAttributes.get(PacmanRuleConstants.AZURE_SUBSCRIPTION);
		
		Set<String> publicAccess  = new HashSet<>();

		if (!PacmanUtils.doesAllHaveValue(esNsgRuleUrl, esVirtualMachineRuleURl)) {
			logger.info(PacmanRuleConstants.MISSING_CONFIGURATION);
			throw new InvalidInputException(PacmanRuleConstants.MISSING_CONFIGURATION);
		}
		try {
			if (status.equals(PacmanRuleConstants.RUNNING_STATE)) {
				Map<String, Object> violationReasonMap = new HashMap<>();
						
				Map<String, Object> nsgData = VirtualMachineUtil.getVMResourceNSGList(pacmanHost + esVirtualMachineRuleURl, resourceId, region,subscription);
				JsonArray vmNSGArray = (JsonArray) nsgData.getOrDefault(PacmanRuleConstants.VM_NSG_LIST, new JsonArray());
				JsonArray vmNicArray = (JsonArray) nsgData.getOrDefault(PacmanRuleConstants.VM_NIC_LIST, new JsonArray());
				
				Map<String, Object> nsgPublicDetail = VirtualMachineUtil.getVMPublicPorts(ruleParam,region, subscription, vmNSGArray,vmNicArray, false);
				List<NicPublicData> nicPublicData = (List<NicPublicData>) nsgPublicDetail.get(PacmanRuleConstants.PUBLIC_NIC);
				boolean isPublic = (boolean) nsgPublicDetail.get(PacmanRuleConstants.IS_PUBLIC);
				List<String> vmPublicIPs= (List<String>) nsgPublicDetail.get(PacmanRuleConstants.PUBLICIP);
				if (isPublic) {
					violationReasonMap.putAll(getViolationMap());
					List<String> nicList = new ArrayList<>();
					for(NicPublicData publicNic: nicPublicData) {
						nicList.add(publicNic.getNicId());
						Map<String, Set<String>> portIPMap = publicNic.getPublicPorts();
						portIPMap.forEach((port, ipList) -> {
							String nonPermittedIPs = ipList.stream().map(publicIP -> publicIP.replace(PacmanSdkConstants.ASTERISK, PacmanRuleConstants.IP_ALL)).collect(Collectors.joining(PacmanSdkConstants.DEFAULT_SEPARATOR));
							String portKey = String.format(violationReasonMap
									.getOrDefault(DB_KEY_PUBLIC_PORT, ISSUE_DETAILS_KEY_PUBLIC_PORT).toString(), port);
							issue.put(portKey, nonPermittedIPs);
						});
					}
					publicAccess.add("Yes");
					String ipKey = violationReasonMap
							.getOrDefault(DB_KEY_PUBLICIP, ISSUE_DETAILS_KEY_PUBLIC_IP).toString();
					issue.put(ipKey, String.join(PacmanSdkConstants.SEMICOLON, vmPublicIPs));
					String nicKey = violationReasonMap
							.getOrDefault(DB_KEY_NIC, ISSUE_DETAILS_KEY_NIC).toString();
					issue.put(nicKey, String.join(PacmanSdkConstants.SEMICOLON, nicList));
					logger.trace("========VMPublicAccess found open ports through NSG=========");
				}
				
				if (!publicAccess.isEmpty()) {
					logger.trace("========VMPublicAccess ended with an annotation=========");
					
					String description = violationReasonMap.getOrDefault(PacmanRuleConstants.VIOLATION_REASON, VIOLATION_REASON).toString();
					issue.put(PacmanRuleConstants.VIOLATION_REASON, description);
					Map<String, String> additionalParams=  new HashMap<>();
					additionalParams.put("VirtualMachinePublicIP", String.join(PacmanSdkConstants.SEMICOLON, vmPublicIPs));
					Annotation annotation = CommonUtils.buildAnnotationForAzure(ruleParam, resourceAttributes,
							description, issue, additionalParams);
					return new RuleResult(PacmanSdkConstants.STATUS_FAILURE, PacmanRuleConstants.FAILURE_MESSAGE, annotation);
				}
			}
		} catch (Exception exception) {
			exception.printStackTrace();
			logger.error("error while executig VirtualMachineWithPublicAccess rule ", exception);
			throw new RuleExecutionFailedExeption(exception.getMessage());
		}
		logger.debug("========VirtualMachineWithPublicAccess ended=========");
		return new RuleResult(PacmanSdkConstants.STATUS_SUCCESS, PacmanRuleConstants.SUCCESS_MESSAGE);
	}
    private Map<String,Object> getViolationMap()
    {
    	String violationReason="{\"violationReason\":\"Virtual Machine with public access found!!\",\"publicIP\":\"VM Public IP\", \"publicPort\":\"Port- %s Non Permissible IP Ranges\"}";
    	Gson gson = new Gson();
    	Map<String,Object> violationMap = gson.fromJson(violationReason, Map.class);
    	return violationMap;
    }
	@Override
	public String getHelpText() {
		return "Checks if the virtual machine is exposed to internet by comparing the virtual machine attributes with fact provided by rule params ";
	}
	
}
